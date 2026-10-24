package engine

import (
	"bytes"
	"context"
	"embed"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

// updateRules downloads fresh rule sets if the local ones are a day old.
// private is for the Worker (sources.IsWorker).
func updateRules(ctx context.Context, dir string, client, private func() *http.Client) {
	for name, url := range ruleSets {
		path := filepath.Join(dir, name)
		if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < 24*time.Hour {
			continue
		}
		for _, u := range append([]string{url}, sources.Mirrors(url)...) {
			c := client()
			if sources.IsWorker(u) {
				c = private()
			}
			b, err := download(ctx, c, u, 8<<20)
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

func download(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, io.ErrUnexpectedEOF
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
