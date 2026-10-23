package engine

// Release gate test (checker only), copied into a v0.3.2 checkout: 0.3.2's
// own code must offer the next version as an in-app update on Windows.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
)

func TestGateInApp032(t *testing.T) {
	b, _ := os.ReadFile(os.Getenv("MANIFEST"))
	var m UpdateManifest
	json.Unmarshal(b, &m)
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}, Version: "0.3.2",
		InstallUpdate: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	e.applyUpdate(m)
	if u := e.Snapshot().Update; u == nil || !u.InApp || u.Required {
		t.Fatalf("0.3.2 on Windows gets %+v", u)
	}
}
