package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
)

func TestCrowdLearning(t *testing.T) {
	var mu sync.Mutex
	var reports []map[string]json.RawMessage
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/stats" && r.URL.Query().Get("asn") == "self":
			w.Write([]byte(`{"asn":58224,"asns":{"58224":{"proto":[[3,900,1000],[1,10,1000]],"port":[[1,50,100],[99,1,1]]}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/stats":
			var b map[string]json.RawMessage
			json.NewDecoder(r.Body).Decode(&b)
			mu.Lock()
			reports = append(reports, b)
			mu.Unlock()
			w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}, AccountURLs: []string{ts.URL}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.pool.Close()

	// Off by default: nothing is asked or sent.
	e.crowdLookup(context.Background())
	e.net.record(3, 1+1<<5, true)
	e.crowdReport(context.Background())
	if len(reports) != 0 || e.net.table().ASN != 0 {
		t.Fatal("crowd stats were used without permission")
	}
	if !e.Snapshot().CrowdAvailable {
		t.Fatal("the toggle should show in a build with a service")
	}

	e.mu.Lock()
	e.settings.ShareStats = true
	e.mu.Unlock()
	e.crowdLookup(context.Background())
	tb := e.net.table()
	if tb.ASN != 58224 || !tb.Seeded {
		t.Fatalf("lookup: asn %d seeded %v", tb.ASN, tb.Seeded)
	}
	v := e.net.snapshot()
	if v.proto[3] <= v.proto[1] {
		t.Fatalf("the crowd's good protocol should rank first: %v vs %v", v.proto[3], v.proto[1])
	}
	// Seeding is scaled down so the device's own tests soon decide.
	if tb.Proto[3].N > crowdSeedWeight+1 {
		t.Fatalf("seed too heavy: %+v", tb.Proto[3])
	}

	// Reports only go through the VPN.
	e.crowdReport(context.Background())
	if len(reports) != 0 {
		t.Fatal("reported while not connected")
	}
	e.mu.Lock()
	e.conn = &connection{proxyAddr: strings.TrimPrefix(ts.URL, "http://"), healthy: true}
	e.mu.Unlock()
	e.crowdReport(context.Background())
	if len(reports) != 1 {
		t.Fatalf("%d reports", len(reports))
	}
	got := reports[0]
	if string(got["asn"]) != "58224" || string(got["proto"]) != "[[3,1,1]]" || string(got["port"]) != "[[1,1,1]]" {
		t.Fatalf("report: %s", mustJSON(got))
	}
	for k := range got {
		switch k {
		case "asn", "proto", "style", "hello", "port":
		default:
			t.Fatalf("report carries %q", k)
		}
	}
	// What was sent is not sent again.
	e.crowdReport(context.Background())
	if len(reports) != 1 {
		t.Fatal("the same tests were reported twice")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
