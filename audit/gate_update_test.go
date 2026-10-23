package engine

// Release gate tests (checker only), copied into internal/engine by gate.yml.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
)

func TestGateRequire(t *testing.T) {
	v := func(s string) [3]int {
		p, ok := parseVersion(s)
		if !ok {
			t.Fatalf("parse %s", s)
		}
		return p
	}
	cases := []struct {
		cur, min, req string
		want          bool
	}{
		{"0.3.0", "0.3.0", "", false}, {"0.3.1", "0.3.0", "", false}, {"0.2.9", "0.3.0", "", true},
		{"0.3.2", "0.3.0", "0.3.3", true}, {"0.3.3", "0.3.0", "0.3.3", false}, {"0.3.10", "0.3.0", "0.3.9", false},
		{"1.0.0", "0.3.0", "0.3.3", false},
	}
	for _, c := range cases {
		if got := requiredFrom(v(c.cur), c.min, c.req); got != c.want {
			t.Errorf("cur %s min %s require %s: required=%v, want %v", c.cur, c.min, c.req, got, c.want)
		}
	}
}

// A mirror that ignores Range must not corrupt the file after a cut.
func TestGateResumeWithoutRangeSupport(t *testing.T) {
	body := bytes.Repeat([]byte("gate-0123456789"), 40000)
	sum := sha256.Sum256(body)
	n := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if n == 1 {
			w.Write(body[:len(body)/3])
			panic(http.ErrAbortHandler)
		}
		w.Write(body) // 200 with the whole file, Range ignored
	}))
	defer srv.Close()
	old := directUpdateClient
	directUpdateClient = srv.Client
	defer func() { directUpdateClient = old }()
	installed := ""
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}, Version: "0.3.2",
		InstallUpdate: func(p string) error { installed = p; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.pool.Close()
	e.applyUpdate(UpdateManifest{LatestVersion: "0.3.3", Files: map[string]UpdateFile{
		updateKey(false): {URLs: []string{srv.URL + "/a", srv.URL + "/b"}, SHA256: hex.EncodeToString(sum[:])}}})
	for i := 0; i < 3 && installed == ""; i++ {
		e.GetUpdate()
	}
	if b, _ := os.ReadFile(installed); !bytes.Equal(b, body) {
		t.Fatalf("installed %d of %d bytes after %d requests", len(b), len(body), n)
	}
}

// A forced update whose download fails must not leave the user unable to
// connect: from then on the download can only go direct, and in Iran the
// download site is often filtered.
func TestGateForcedUpdateNeverStrands(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "cut", http.StatusBadGateway)
	}))
	defer srv.Close()
	old := directUpdateClient
	directUpdateClient = srv.Client
	defer func() { directUpdateClient = old }()
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}, Version: "0.3.3",
		InstallUpdate: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.pool.Close()
	e.applyUpdate(UpdateManifest{MinVersion: "0.3.0", LatestVersion: "0.3.4", Require: "0.3.4", Files: map[string]UpdateFile{
		updateKey(false): {URLs: []string{srv.URL + "/x"}, SHA256: strings.Repeat("a", 64)}}})
	for i := 0; i < 100; i++ {
		if u := e.Snapshot().Update; u != nil && u.Error != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if e.updateRequired() {
		t.Fatal("the forced download failed and the user is now blocked from connecting, so the retry can only go direct")
	}
}
