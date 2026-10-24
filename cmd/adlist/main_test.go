package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEntry(t *testing.T) {
	for line, want := range map[string]string{
		"ads.example.com":                     "ads.example.com",
		"  *.Tracker.Example.COM.  # comment": "tracker.example.com",
		"0.0.0.0 ads.example.com":             "ads.example.com",
		"127.0.0.1\tads.example.com":          "ads.example.com",
		"||ads.example.com^":                  "ads.example.com",
		"||ads.example.com^$important":        "ads.example.com",
		"@@||cdn.example.com^":                "@@cdn.example.com",
		"@@||app.adjust.com^|":                "@@app.adjust.com",
		"@@|statcounter.com^|":                "@@statcounter.com",
		"||clarity.ms^|":                      "clarity.ms",
		"||bitpin.ir^$image,from=par30dl.net": "",
		"||cdn.example.com:8080^":             "",
		"||ads.example.com^$third-party":      "",
		"||example.com/ads/*":                 "",
		"/banner[0-9]+/":                      "",
		"! comment":                           "",
		"[Adblock Plus 2.0]":                  "",
		"0.0.0.0 0.0.0.0":                     "0.0.0.0",
		"example.com/path":                    "",
		"a b c":                               "",
	} {
		if got := entry(line); got != want {
			t.Errorf("entry(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestBuild(t *testing.T) {
	var l lists
	l.read(strings.NewReader(`
||ads.example.com^
||sub.ads.example.com^
||doubleclick.net^
0.0.0.0 localhost
0.0.0.0 0.0.0.0
@@||ok.doubleclick.net^|
ads.digikala.com
yektanet.com
pixel.bank.ir
mihanblog.com
`), true)
	if l.block["localhost"] || l.block["0.0.0.0"] {
		t.Fatal("kept a name that is not a domain")
	}
	keep := names{"yektanet.com": true, "tapsell.ir": true}
	// An allowed parent does not unblock what the lists name under it; a
	// kept name stays blocked even when allowed.
	allow := names{"login.example.com": true, "bank.ir": true, "mihanblog.com": true, "yektanet.com": true}
	for n := range l.allow {
		allow[n] = true
	}
	src, st := build(l.block, keep, allow)
	b, _ := json.Marshal(src)
	got := string(b)
	want := `{"rules":[{"mode":"and","rules":[{"domain_suffix":["ads.digikala.com","ads.example.com","doubleclick.net","pixel.bank.ir","tapsell.ir","yektanet.com"]},{"domain":["ok.doubleclick.net"],"invert":true}],"type":"logical"}],"version":2}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if st.blocked != 6 || st.covered != 1 || st.allowed != 1 || st.exceptions != 1 {
		t.Fatalf("stats %+v", st)
	}
}
