package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The contents API sends the file only when asked for it raw, a stalled
// download gives way to the next address, and one that keeps moving is
// given its time but not the next address's.
func TestDownload(t *testing.T) {
	defer func(i, m time.Duration) { downloadIdle, downloadMax = i, m }(downloadIdle, downloadMax)
	downloadIdle, downloadMax = 150*time.Millisecond, 600*time.Millisecond
	ctx := context.Background()

	var accept string
	api := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		accept = r.Header.Get("Accept")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("SRS")), Request: r}, nil
	})}
	if b, err := download(ctx, api, "https://api.github.com/repos/o/r/contents/a.srs?ref=rules", 1<<20); err != nil || string(b) != "SRS" || accept != "application/vnd.github.raw" {
		t.Fatalf("api: %q %v, Accept %q", b, err, accept)
	}

	trickle := func(every time.Duration, stallAfter int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for i := 0; ; i++ {
				if i == stallAfter {
					<-r.Context().Done()
					return
				}
				if _, err := w.Write(bytes.Repeat([]byte("x"), 100)); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-time.After(every):
				case <-r.Context().Done():
					return
				}
			}
		}))
	}
	stalled := trickle(10*time.Millisecond, 3)
	defer stalled.Close()
	start := time.Now()
	if _, err := download(ctx, http.DefaultClient, stalled.URL, 1<<20); err == nil || errors.Is(err, errSlow) {
		t.Fatalf("stalled: %v", err)
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Fatalf("a stalled download took %v", d)
	}
	slow := trickle(50*time.Millisecond, -1)
	defer slow.Close()
	if _, err := download(ctx, http.DefaultClient, slow.URL, 1<<20); !errors.Is(err, errSlow) {
		t.Fatalf("slow: %v", err)
	}
}

// The ad list is left alone while ads are not blocked.
func TestUpdateRulesSkips(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	c := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		asked = append(asked, r.URL.String())
		mu.Unlock()
		return nil, errors.New("offline")
	})}
	client := func() *http.Client { return c }
	updateRules(context.Background(), t.TempDir(), client, client, func(name string) bool { return name != "geosite-ads.srs" })
	if len(asked) == 0 {
		t.Fatal("nothing was asked for")
	}
	for _, u := range asked {
		if strings.Contains(u, "geosite-ads") {
			t.Fatalf("asked for %s", u)
		}
	}
}
