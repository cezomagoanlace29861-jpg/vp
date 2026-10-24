package sources

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The own-servers list opens only with the key it was sealed with, and is
// offered only when the app was built with one.
func TestSealedOwnList(t *testing.T) {
	defer func(k string) { OwnKey = k }(OwnKey)
	OwnKey = ""
	for _, s := range Central(7) {
		if s.Sealed {
			t.Fatal("own list offered without a key")
		}
	}
	OwnKey = strings.Repeat("ab", 32)
	if c := Central(7); !c[0].Sealed || !c[1].Sealed || c[0].URL == c[1].URL || !strings.Contains(c[0].URL, "/own-") {
		t.Fatalf("own lists missing: %+v", c[:2])
	}
	// Every install reads two different parts, and every part is read.
	seen := map[string]bool{}
	for i := range uint32(64) {
		c := Central(i)
		if c[0].URL == c[1].URL {
			t.Fatalf("install %d reads one part twice", i)
		}
		seen[c[0].URL], seen[c[1].URL] = true, true
	}
	if len(seen) != OwnBuckets {
		t.Fatalf("%d parts read, want %d", len(seen), OwnBuckets)
	}
	sealed, err := Seal(ownKey(), "vless://a\ntrojan://b\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := Open(string(sealed)); got != "vless://a\ntrojan://b\n" {
		t.Fatalf("opened %q", got)
	}
	OwnKey = strings.Repeat("cd", 32)
	if Open(string(sealed)) != "" {
		t.Fatal("opened with the wrong key")
	}
	if strings.Contains(string(sealed), "vless") {
		t.Fatal("sealed list readable")
	}
}

func TestMirrorsUseGitHubAPIOnlyForOwnRepo(t *testing.T) {
	defer func(old string) { WorkerMirror = old }(WorkerMirror)
	WorkerMirror = "https://accounts.example.org/, https://lists.example.workers.dev"
	own := Mirrors(CentralBase + "fresh.txt")
	if !slices.Contains(own, "https://api.github.com/repos/cezomagoanlace29861-jpg/Albatross/contents/fresh.txt?ref=servers") ||
		!slices.Contains(own, "https://accounts.example.org/list/servers/fresh.txt") ||
		!slices.Contains(own, "https://lists.example.workers.dev/list/servers/fresh.txt") {
		t.Fatalf("own repo: %v", own)
	}
	for _, m := range Mirrors("https://raw.githubusercontent.com/someone/lists/main/sub.txt") {
		if strings.Contains(m, "api.github.com") || strings.Contains(m, "example") {
			t.Fatalf("other repo uses the API: %s", m)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The Worker shares the account service's name, so it is reached only
// through the VPN or the private client, never by a plain direct call.
func TestWorkerNotDirect(t *testing.T) {
	defer func(old string) { WorkerMirror = old }(WorkerMirror)
	WorkerMirror = "https://accounts.example.org"
	var mu sync.Mutex
	var direct, private []string
	record := func(to *[]string) *http.Client {
		return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			*to = append(*to, r.URL.String())
			mu.Unlock()
			return nil, errors.New("offline")
		})}
	}
	f := &Fetcher{Direct: record(&direct), CacheDir: t.TempDir()}
	src := Source{ID: "fresh", URL: CentralBase + "fresh.txt"}
	f.Fetch(context.Background(), src)
	f.Private = record(&private)
	f.Fetch(context.Background(), src)
	if len(direct) == 0 || slices.ContainsFunc(direct, IsWorker) {
		t.Fatalf("direct calls: %v", direct)
	}
	if len(private) != 1 || !IsWorker(private[0]) {
		t.Fatalf("private calls: %v", private)
	}
}
