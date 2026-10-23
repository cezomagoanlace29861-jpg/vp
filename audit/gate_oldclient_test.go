package engine

// Release gate test (checker only), copied into a checkout of an OLD
// release: that release's own code reads the new update.json.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
)

func TestGateOldClient(t *testing.T) {
	b, err := os.ReadFile(os.Getenv("MANIFEST"))
	if err != nil {
		t.Fatal(err)
	}
	var m UpdateManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("this version cannot parse update.json: %v", err)
	}
	ver := os.Getenv("VER")
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}, Version: ver})
	if err != nil {
		t.Fatal(err)
	}
	e.applyUpdate(m)
	u := e.Snapshot().Update
	if u != nil && u.Required {
		t.Fatalf("%s is blocked from connecting by this update.json", ver)
	}
	if m.LatestVersion != ver && (u == nil || u.Latest != m.LatestVersion) {
		t.Fatalf("%s is not offered %s: %+v", ver, m.LatestVersion, u)
	}
	t.Logf("%s: offered %+v", ver, u)
}
