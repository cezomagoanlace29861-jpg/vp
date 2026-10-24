// Albatross is a free VPN client that gathers public servers from hundreds
// of sources, keeps testing them, and connects to the fastest one in the
// country the user picks.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/engine"
	"github.com/cezomagoanlace29861-jpg/vp/internal/platform"
	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
	"github.com/cezomagoanlace29861-jpg/vp/internal/ui"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const windowTitle = "Albatross VPN"

func main() {
	headless := flag.Bool("headless", false, "serve the UI without opening a window")
	uiPort := flag.Int("ui-port", 0, "local port for the UI (0 = random)")
	dataDir := flag.String("data", "", "data directory")
	elevated := flag.Bool("elevated", false, "relaunched with administrator rights")
	flag.Bool("autostart", false, "started at login")
	flag.Parse()

	wait := time.Duration(0)
	if *elevated {
		wait = 15 * time.Second
	}
	if !platform.SingleInstance(windowTitle, wait) {
		return
	}
	dir := *dataDir
	if dir == "" {
		dir = platform.DataDir()
	}
	os.MkdirAll(dir, 0o755)
	// Lines go through engine.Redact, and the file is removed when the app
	// quits normally: it is only kept to explain a crash.
	logPath := filepath.Join(dir, "app.log")
	logFile, _ := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if logFile != nil {
		log.SetOutput(engine.RedactWriter(logFile))
	}

	sysProxy := &platform.SystemProxy{}
	var only []sources.Source
	// ALBATROSS_SOURCES replaces the built-in sources (comma separated), for
	// testing against a private list.
	for _, s := range strings.Split(os.Getenv("ALBATROSS_SOURCES"), ",") {
		if src, ok := sources.User(s); ok {
			src.Builtin = true
			only = append(only, src)
		}
	}
	quit := func() {}
	eng, err := engine.New(engine.Options{
		// The installer replaces this copy; it closes the app itself, but
		// quitting first lets the system proxy be put back cleanly.
		InstallUpdate: func(path string) error {
			if err := exec.Command(path).Start(); err != nil {
				return err
			}
			go quit()
			return nil
		},
		Sources:   only,
		DataDir:   dir,
		AppDirs:   []string{platform.ExeDir()},
		ExeName:   platform.ExeName(),
		IsAdmin:   platform.IsAdmin,
		SysProxy:  sysProxy,
		Version:   version,
		Autostart: platform.SetAutostart,
	})
	if err != nil {
		platform.Alert(windowTitle, "The app could not start:\n"+err.Error())
		os.Exit(1)
	}
	eng.Start()

	var once sync.Once
	done := make(chan struct{})
	quit = func() { once.Do(func() { close(done) }) }

	srv, url, err := ui.Start(eng, ui.Hooks{
		Quit: quit,
		RelaunchAdmin: func() error {
			eng.Close()
			platform.ReleaseInstance()
			if err := platform.RelaunchAsAdmin(); err != nil {
				return err
			}
			go func() {
				time.Sleep(300 * time.Millisecond)
				os.Exit(0)
			}()
			return nil
		},
		OpenURL: platform.OpenURL,
	}, *uiPort)
	if err != nil {
		platform.Alert(windowTitle, "The window could not open:\n"+err.Error())
		eng.Close()
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		quit()
	}()

	if *headless {
		fmt.Println(url)
		<-done
	} else {
		// Blocks until the window closes. Falls back to the browser when the
		// WebView2 runtime is missing.
		if !openWindow(windowTitle, url, dir, done) {
			platform.OpenURL(url)
			<-done
		}
	}
	srv.Close()
	eng.Close()
	if logFile != nil {
		log.SetOutput(io.Discard)
		logFile.Close()
		os.Remove(logPath)
	}
}
