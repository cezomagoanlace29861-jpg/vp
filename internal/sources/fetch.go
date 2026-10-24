package sources

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	vpnGateURL  = "https://www.vpngate.net/api/iphone/"
	maxBodySize = 48 << 20
	userAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
)

// Fetcher downloads sources, trying the local proxy (when connected), a
// direct connection and public CDN mirrors of GitHub in turn.
type Fetcher struct {
	Direct *http.Client
	Proxy  func() *http.Client // returns nil while disconnected
	// Private reaches the Worker while disconnected without showing its
	// name (see IsWorker); nil leaves the Worker out then.
	Private  *http.Client
	CacheDir string

	bytes atomic.Int64
}

// Result is the outcome of fetching one source.
type Result struct {
	Source    Source
	Text      string
	FromCache bool // served from disk because nothing changed or all paths failed
	Via       string
	Err       error
}

// BytesDownloaded is the total network traffic used by the fetcher.
func (f *Fetcher) BytesDownloaded() int64 { return f.bytes.Load() }

type cacheMeta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
}

type attempt struct {
	via    string
	url    string
	client *http.Client
}

// Fetch downloads one source. When every path fails it falls back to the
// last copy on disk and reports the error alongside it.
func (f *Fetcher) Fetch(ctx context.Context, s Source) Result {
	res := Result{Source: s}
	var attempts []attempt
	proxy := (*http.Client)(nil)
	if f.Proxy != nil {
		proxy = f.Proxy()
	}
	switch s.Kind {
	case KindTelegram:
		u := "https://t.me/s/" + s.URL
		if proxy != nil {
			attempts = append(attempts, attempt{"proxy", u, proxy})
		}
		attempts = append(attempts, attempt{"direct", u, f.Direct})
		text, via, err := f.fetchTelegram(ctx, attempts)
		if err == nil {
			res.Text, res.Via = text, via
			f.store(s, cacheMeta{URL: u, FetchedAt: time.Now()}, text)
			return res
		}
		return f.fallback(res, err)
	default:
		if proxy != nil {
			attempts = append(attempts, attempt{"proxy", s.URL, proxy})
		}
		attempts = append(attempts, attempt{"direct", s.URL, f.Direct})
		for i, m := range Mirrors(s.URL) {
			c := f.Direct
			if IsWorker(m) {
				if c = proxy; c == nil {
					c = f.Private
				}
				if c == nil {
					continue
				}
			}
			attempts = append(attempts, attempt{"mirror" + strconv.Itoa(i+1), m, c})
		}
	}
	meta, _ := f.loadMeta(s)
	var lastErr error
	for _, a := range attempts {
		if ctx.Err() != nil {
			return f.fallback(res, ctx.Err())
		}
		etag, lm := "", ""
		if meta != nil && meta.URL == a.url {
			etag, lm = meta.ETag, meta.LastModified
		}
		body, newMeta, notModified, err := f.get(ctx, a, etag, lm)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", a.via, err)
			continue
		}
		res.Via = a.via
		if notModified {
			if text, ok := f.loadBody(s); ok {
				res.Text, res.FromCache = text, true
				meta.FetchedAt = time.Now()
				f.saveMeta(s, *meta)
				return res
			}
			// Cache vanished; fetch again without validators.
			body, newMeta, _, err = f.get(ctx, a, "", "")
			if err != nil {
				lastErr = err
				continue
			}
		}
		res.Text = body
		f.store(s, newMeta, body)
		return res
	}
	if lastErr == nil {
		lastErr = errors.New("no way to reach source")
	}
	return f.fallback(res, lastErr)
}

func (f *Fetcher) fallback(res Result, err error) Result {
	if text, ok := f.loadBody(res.Source); ok {
		res.Text, res.FromCache = text, true
	}
	res.Err = err
	return res
}

func (f *Fetcher) get(ctx context.Context, a attempt, etag, lastMod string) (string, cacheMeta, bool, error) {
	timeout := 45 * time.Second
	if a.via != "proxy" && a.via != "direct" {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return "", cacheMeta{}, false, err
	}
	req.Header.Set("User-Agent", userAgent)
	if strings.HasPrefix(a.url, githubAPI) {
		req.Header.Set("Accept", "application/vnd.github.raw")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", cacheMeta{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return "", cacheMeta{}, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", cacheMeta{}, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	f.bytes.Add(int64(len(b)))
	if err != nil {
		return "", cacheMeta{}, false, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return "", cacheMeta{}, false, errors.New("empty body")
	}
	return string(b), cacheMeta{
		URL:          a.url,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		FetchedAt:    time.Now(),
	}, false, nil
}

var tgPostRe = regexp.MustCompile(`data-post="[^"/]+/(\d+)"`)

// fetchTelegram reads the two newest pages of a channel's web preview.
func (f *Fetcher) fetchTelegram(ctx context.Context, attempts []attempt) (string, string, error) {
	var lastErr error
	for _, a := range attempts {
		page, err := f.getPage(ctx, a.client, a.url)
		if err != nil {
			lastErr = err
			continue
		}
		text := page
		if ids := tgPostRe.FindAllStringSubmatch(page, -1); len(ids) > 0 {
			oldest := ids[0][1]
			if older, err := f.getPage(ctx, a.client, a.url+"?before="+oldest); err == nil {
				text += "\n" + older
			}
		}
		return text, a.via, nil
	}
	return "", "", lastErr
}

func (f *Fetcher) getPage(ctx context.Context, c *http.Client, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	f.bytes.Add(int64(len(b)))
	if err != nil {
		return "", err
	}
	if !strings.Contains(string(b), "tgme_widget_message") {
		return "", errors.New("not a channel preview")
	}
	return string(b), nil
}

var rawGitHubRe = regexp.MustCompile(`^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$`)

// WorkerMirror is the project's Cloudflare Worker, which serves the app's
// own lists (backend/src/index.js): its addresses, comma separated, or empty
// while it has none.
var WorkerMirror = ""

// Mirrors returns CDN copies of a raw GitHub URL, which often stay
// reachable when raw.githubusercontent.com is filtered.
func Mirrors(u string) []string {
	m := rawGitHubRe.FindStringSubmatch(u)
	if m == nil {
		return nil
	}
	owner, repo, branch, path := m[1], m[2], m[3], m[4]
	out := []string{
		fmt.Sprintf("https://cdn.jsdelivr.net/gh/%s/%s@%s/%s", owner, repo, branch, path),
		fmt.Sprintf("https://fastly.jsdelivr.net/gh/%s/%s@%s/%s", owner, repo, branch, path),
		fmt.Sprintf("https://raw.githack.com/%s/%s/%s/%s", owner, repo, branch, path),
		fmt.Sprintf("https://gcore.jsdelivr.net/gh/%s/%s@%s/%s", owner, repo, branch, path),
	}
	// api.github.com stayed open through Iran's allowlist periods while
	// github.com and raw were closed. Anonymous use allows 60 requests an
	// hour per address, so only the app's own files go this way.
	if strings.EqualFold(owner+"/"+repo, ownRepo) {
		out = append(out, fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", owner, repo, path, branch))
		for _, w := range strings.Split(WorkerMirror, ",") {
			if w = strings.TrimRight(strings.TrimSpace(w), "/"); w != "" {
				out = append(out, w+"/list/"+branch+"/"+path)
			}
		}
	}
	return out
}

// IsWorker says whether u is on the Worker, whose name is also the account
// service's: a plain direct call to it shows the network who uses the app.
func IsWorker(u string) bool {
	for _, w := range strings.Split(WorkerMirror, ",") {
		if w = strings.TrimRight(strings.TrimSpace(w), "/"); w != "" && strings.HasPrefix(u, w+"/") {
			return true
		}
	}
	return false
}

// ownRepo is the app's own repository, where the collector publishes.
const ownRepo = "cezomagoanlace29861-jpg/Albatross"

// githubAPI is the prefix of api.github.com contents URLs, which return
// the raw file when asked for it.
const githubAPI = "https://api.github.com/repos/"

func (f *Fetcher) paths(s Source) (body, meta string) {
	base := filepath.Join(f.CacheDir, string(s.Kind)+"-"+s.ID)
	return base + ".gz", base + ".json"
}

func (f *Fetcher) store(s Source, meta cacheMeta, text string) {
	if f.CacheDir == "" {
		return
	}
	bodyPath, _ := f.paths(s)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	zw.Write([]byte(text))
	zw.Close()
	if writeAtomic(bodyPath, buf.Bytes()) == nil {
		f.saveMeta(s, meta)
	}
}

func (f *Fetcher) saveMeta(s Source, meta cacheMeta) {
	if f.CacheDir == "" {
		return
	}
	_, metaPath := f.paths(s)
	b, _ := json.Marshal(meta)
	writeAtomic(metaPath, b)
}

func (f *Fetcher) loadMeta(s Source) (*cacheMeta, error) {
	if f.CacheDir == "" {
		return nil, os.ErrNotExist
	}
	_, metaPath := f.paths(s)
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var m cacheMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (f *Fetcher) loadBody(s Source) (string, bool) {
	if f.CacheDir == "" {
		return "", false
	}
	bodyPath, _ := f.paths(s)
	fh, err := os.Open(bodyPath)
	if err != nil {
		return "", false
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(zr, maxBodySize))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// Cached returns the last downloaded body of a source, if any.
func (f *Fetcher) Cached(s Source) (string, bool) { return f.loadBody(s) }

// CachedAt reports when a source was last fetched successfully.
func (f *Fetcher) CachedAt(s Source) time.Time {
	m, err := f.loadMeta(s)
	if err != nil {
		return time.Time{}
	}
	return m.FetchedAt
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
