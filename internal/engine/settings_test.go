package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/core"
	"github.com/cezomagoanlace29861-jpg/vp/internal/node"
	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
)

func TestSettingsNormalize(t *testing.T) {
	s := DefaultSettings()
	if s.Bypass != "IR" || s.Protocol != "" || s.AllowPlain {
		t.Fatalf("defaults: %+v", s)
	}
	s.Bypass, s.Protocol = "FR", "gopher"
	s.normalize()
	if s.Bypass != "" || s.Protocol != "" {
		t.Fatalf("unknown choices kept: %+v", s)
	}
	s.Bypass, s.Protocol = "CN", "wireguard"
	s.normalize()
	if s.Bypass != "CN" || s.Protocol != "wireguard" {
		t.Fatalf("valid choices dropped: %+v", s)
	}
}

func TestProtocolFilter(t *testing.T) {
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.pool.Close()
	now := time.Now()
	add := func(name, link, country string, delay int) {
		n, err := node.ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		e.good[node.Key64(n.Key())] = &Server{Key: n.Key(), Link: link, Name: name, Proto: n.Proto, Country: country, Delay: delay, LastOK: now, TestedAt: now}
	}
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	for i := 0; i < 3; i++ {
		add(fmt.Sprintf("vl%d", i), fmt.Sprintf("vless://%s@vl%d.example:443?security=tls&type=tcp#x", uuid, i), "DE", 100+i)
		add(fmt.Sprintf("tr%d", i), fmt.Sprintf("trojan://pw@tr%d.example:443?security=tls&type=tcp#x", i), "NL", 90+i)
	}
	count := func() map[string]int {
		e.countriesAt = time.Time{}
		m := map[string]int{}
		for _, c := range e.Countries() {
			m[c.Code] = c.Servers
		}
		return m
	}
	if m := count(); m["DE"] != 3 || m["NL"] != 3 {
		t.Fatalf("automatic: %v", m)
	}
	s := e.Settings()
	s.Protocol = "vless"
	e.UpdateSettings(s)
	if m := count(); m["DE"] != 3 || m["NL"] != 0 {
		t.Fatalf("vless only: %v", m)
	}
	for _, sv := range e.bestServers("", 10, nil) {
		if sv.Proto != "vless" {
			t.Fatalf("connected group holds a %s server", sv.Proto)
		}
	}
	if g := e.pickGroup("", "", nil, groupSize); len(g) != 3 || g[0].Country != "DE" {
		t.Fatalf("group for vless: %d servers", len(g))
	}
	s.Protocol = "trojan"
	e.UpdateSettings(s)
	if m := count(); m["NL"] != 3 || m["DE"] != 0 {
		t.Fatalf("trojan only: %v", m)
	}
}

// TestConnectConfigRegions has the real core load the configuration written
// for each bypass choice, with the rule sets the app ships.
//
//	SING_BOX=/path/sing-box go test -run ConnectConfigRegions ./internal/engine
func TestConnectConfigRegions(t *testing.T) {
	sb := os.Getenv("SING_BOX")
	if sb == "" {
		t.Skip("SING_BOX must be set")
	}
	n, err := node.ParseLink("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=tcp#x")
	if err != nil {
		t.Fatal(err)
	}
	set, err := core.BuildSet([]*node.Node{n}, core.BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bypass := range []string{"", "CN", "IR"} {
		dir := t.TempDir()
		if err := installRules(dir); err != nil {
			t.Fatal(err)
		}
		cfg := connectConfig(set, connOptions{
			listen: "127.0.0.1", port: 10808, user: "u", pass: "p", bypass: bypass, blockAds: true, secureOnly: true, rulesDir: dir,
			clashAddr: "127.0.0.1:9090", clashSecret: "s", probeAddr: "127.0.0.1:9091",
		})
		b, _ := json.Marshal(cfg)
		path := filepath.Join(dir, "config.json")
		os.WriteFile(path, b, 0o600)
		if out, err := exec.Command(sb, "check", "-c", path).CombinedOutput(); err != nil {
			t.Fatalf("bypass %q: %v\n%s", bypass, err, out)
		}
	}
}

// Refusing unencrypted traffic must come after the region bypass (a direct
// site is not carried by a server) and before the final proxy route.
func TestSecureOnlyRules(t *testing.T) {
	n, err := node.ParseLink("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=tcp#x")
	if err != nil {
		t.Fatal(err)
	}
	set, err := core.BuildSet([]*node.Node{n}, core.BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rules := func(secure bool) []map[string]any {
		cfg := connectConfig(set, connOptions{listen: "127.0.0.1", port: 10808, bypass: "CN", secureOnly: secure, rulesDir: t.TempDir(), clashAddr: "127.0.0.1:9090"})
		var out []map[string]any
		route, _ := cfg["route"].(map[string]any)
		b, _ := json.Marshal(route["rules"])
		json.Unmarshal(b, &out)
		return out
	}
	isPlain := func(r map[string]any) bool {
		if r["action"] != "reject" {
			return false
		}
		_, port := r["port"]
		p, _ := r["protocol"].([]any)
		return port || (len(p) == 1 && p[0] == "http")
	}
	if on := rules(true); true {
		plain, bypass := -1, -1
		for i, r := range on {
			if isPlain(r) && plain < 0 {
				plain = i
			}
			if r["outbound"] == "direct" && r["rule_set"] != nil {
				bypass = i
			}
		}
		if plain < 0 || bypass < 0 || plain < bypass {
			t.Fatalf("plain-text rejects at %d, region bypass at %d; want the bypass first\n%v", plain, bypass, on)
		}
	}
	for _, r := range rules(false) {
		if isPlain(r) {
			t.Fatalf("secure mode off still rejects plain traffic: %v", r)
		}
	}
}

// With nothing confirmed lately, last week's servers are offered instead
// of waiting for a scan; fresh ones always win.
func TestRecentServersWhenNothingFresh(t *testing.T) {
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.pool.Close()
	add := func(host string, ok time.Time, fails int) {
		link := fmt.Sprintf("trojan://pw@%s:443?security=tls&type=tcp#x", host)
		n, err := node.ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		e.good[node.Key64(n.Key())] = &Server{Key: n.Key(), Link: link, Proto: n.Proto, Country: "DE", Delay: 100, LastOK: ok, TestedAt: ok, Fails: fails}
	}
	now := time.Now()
	add("yesterday.example", now.Add(-24*time.Hour), 0)
	add("broken.example", now.Add(-24*time.Hour), 7)
	if got := e.bestServers("DE", groupSize, nil); len(got) != 0 {
		t.Fatalf("old servers counted fresh: %d", len(got))
	}
	got := e.recentServers("DE", groupSize, nil)
	if len(got) != 1 || got[0].Node().Server != "yesterday.example" {
		t.Fatalf("recent servers %v, want only yesterday's working one", got)
	}
	add("fresh.example", now, 0)
	if got := e.recentServers("DE", groupSize, nil); len(got) != 1 {
		t.Fatal("a fresh server was offered as a recent one")
	}
}

// The ad blocker is on for new users and was turned on once for those who
// had the old default (off); turning it off afterwards sticks.
func TestBlockAdsDefault(t *testing.T) {
	for file, want := range map[string]bool{
		"":                                   true,
		`{"block_ads": false}`:               true,
		`{"block_ads": false, "version": 1}`: false,
		`{"block_ads": true, "version": 1}`:  true,
	} {
		dir := t.TempDir()
		if file != "" {
			os.WriteFile(filepath.Join(dir, "settings.json"), []byte(file), 0o600)
		}
		if s := loadSettings(dir, false); s.BlockAds != want || s.Version != settingsVersion {
			t.Errorf("%q: block_ads %v version %d", file, s.BlockAds, s.Version)
		}
	}
}
