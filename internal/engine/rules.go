package engine

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
)

// Rule sets shipped with the app so routing works offline from the first
// run. They are refreshed from upstream once a day when reachable.
//
//go:embed rules/*.srs
var bundledRules embed.FS

var ruleSets = map[string]string{
	"geoip-cn.srs":   "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
	"geosite-cn.srs": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
	"geoip-ir.srs":   "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
	"geosite-ir.srs": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
	// Built every day from the big free lists (.github/workflows/adblock.yml);
	// the copy shipped with the app is the smaller Chocolate4U list.
	"geosite-ads.srs": "https://raw.githubusercontent.com/cezomagoanlace29861-jpg/Albatross/rules/geosite-ads.srs",
}

// installRules writes the bundled rule sets unless a newer copy exists.
func installRules(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name := range ruleSets {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		b, err := bundledRules.ReadFile("rules/" + name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return err
		}
	}
	// The core refuses to start without the learned list, even empty.
	for _, r := range regions {
		if path := r.learnedFile(dir); !fileExists(path) {
			if err := writeLearned(path, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// rulesMu keeps two updates from writing the same file.
var rulesMu sync.Mutex

// updateRules downloads fresh rule sets if the local ones are a day old,
// those want says yes to. private is for the Worker (sources.IsWorker).
func updateRules(ctx context.Context, dir string, client, private func() *http.Client, want func(name string) bool) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	for name, url := range ruleSets {
		path := filepath.Join(dir, name)
		if st, err := os.Stat(path); !want(name) || err == nil && time.Since(st.ModTime()) < 24*time.Hour {
			continue
		}
		for _, u := range append([]string{url}, sources.Mirrors(url)...) {
			c := client()
			if sources.IsWorker(u) {
				c = private()
			}
			b, err := download(ctx, c, u, 8<<20)
			if errors.Is(err, errSlow) {
				// Another copy would come down no faster; try again
				// next time rather than spend the data now.
				break
			}
			if err != nil || len(b) < 64 || !bytes.HasPrefix(b, []byte("SRS")) {
				continue
			}
			tmp := path + ".tmp"
			if os.WriteFile(tmp, b, 0o644) == nil {
				os.Rename(tmp, path)
			}
			break
		}
	}
}

// refreshRules updates the rule sets in the background. The ad list, a few
// megabytes, only while ads are blocked.
func (e *Engine) refreshRules() {
	e.mu.Lock()
	ads := e.settings.BlockAds
	e.mu.Unlock()
	want := func(name string) bool { return ads || name != "geosite-ads.srs" }
	go updateRules(e.ctx, filepath.Join(e.dir, "rules"), e.anyClient, e.accountHTTP, want)
}

// A download may take as long as it keeps moving (the ad list needs
// minutes on a slow line), but not downloadIdle without a byte, which is
// how a blocked address behaves, nor more than downloadMax in all.
var downloadIdle, downloadMax = 30 * time.Second, 10 * time.Minute

// errSlow means a download was still moving when downloadMax ran out.
var errSlow = errors.New("download too slow")

func download(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadMax)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(url, "https://api.github.com/") {
		// The contents API sends the file itself only when asked to.
		req.Header.Set("Accept", "application/vnd.github.raw")
	}
	idle := time.AfterFunc(downloadIdle, cancel)
	defer idle.Stop()
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, io.ErrUnexpectedEOF
	}
	m := &moving{r: resp.Body, idle: idle}
	b, err := io.ReadAll(io.LimitReader(m, limit))
	if err != nil && m.n > 0 && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, errSlow
	}
	return b, err
}

// moving puts the idle timer back each time bytes arrive.
type moving struct {
	r    io.Reader
	idle *time.Timer
	n    int64
}

func (m *moving) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	if n > 0 {
		m.n += int64(n)
		m.idle.Reset(downloadIdle)
	}
	return n, err
}
