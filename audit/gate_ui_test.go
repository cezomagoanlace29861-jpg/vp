package ui

// Release gate test (checker only), copied into internal/ui by gate.yml.
// Every state key and setting the page reads must be in what the server sends.

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/cezomagoanlace29861-jpg/vp/internal/engine"
)

func TestGateUIContract(t *testing.T) {
	js, err := os.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile("web/index.html")
	snap := engine.Snapshot{Update: &engine.UpdateInfo{}, Notice: "n", Share: []string{"a"}, SharePAC: []string{"p"}, HelpAvailable: true, Helping: true, CrowdAvailable: true}
	b, _ := json.Marshal(publicState(snap))
	var got map[string]json.RawMessage
	json.Unmarshal(b, &got)
	var set map[string]any
	json.Unmarshal(got["settings"], &set)

	// Keys of the engine snapshot, so JS helpers like s.map are ignored.
	sb, _ := json.Marshal(engine.Snapshot{Notice: "n", Share: []string{"a"}, SharePAC: []string{"p"}, Update: &engine.UpdateInfo{}})
	var eng map[string]any
	json.Unmarshal(sb, &eng)
	for _, m := range regexp.MustCompile(`\bs\.([a-z_]+)`).FindAllStringSubmatch(string(js), -1) {
		if _, isEng := eng[m[1]]; isEng {
			if _, ok := got[m[1]]; !ok {
				t.Errorf("app.js reads s.%s but /api/state never sends it", m[1])
			}
		}
	}
	for _, m := range regexp.MustCompile(`id="set-([a-z_]+)"`).FindAllStringSubmatch(string(html), -1) {
		if _, ok := set[m[1]]; !ok && m[1] != "tun" { // set-tun drives settings.mode
			t.Errorf("index.html has a set-%s control but settings never carry %s", m[1], m[1])
		}
	}
	for _, k := range []string{"notice", "help_available", "helping", "crowd_available"} {
		if _, ok := got[k]; !ok {
			t.Errorf("/api/state lacks %s", k)
		}
	}
}
