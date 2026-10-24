package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Crowd learning, with the user's permission (Settings.ShareStats): what
// passes on a network is much the same for everyone on its operator, so
// installs share how their tests went, counted per kind of server, under
// the operator's number (ASN). A phone new to an operator then starts from
// what others there learned instead of from nothing.
//
// A report holds counts only: no addresses of servers or of the device, no
// install number. The service keeps two weeks and publishes an operator
// only after several reports.

// crowdEvery is how often tests are reported.
const crowdEvery = 8 * time.Hour

// A table with fewer tests than this is seeded from the crowd.
const crowdSeedBelow = 50

// crowdSeedWeight is how many tests of a kind the crowd's numbers count as
// at most when seeding, so the device's own tests soon outweigh them.
const crowdSeedWeight = 200

type crowdCounts struct {
	Proto [16]crowdRate `json:"proto"`
	Style [32]crowdRate `json:"style"`
	Hello [16]crowdRate `json:"hello"`
	Port  [8]crowdRate  `json:"port"`
}

// crowdRate is a plain count of passes and tests.
type crowdRate [2]uint32

func (r *crowdRate) add(ok bool) {
	if ok {
		r[0]++
	}
	r[1]++
}

// report is the service's report body, nil when nothing was tested.
func (c *crowdCounts) report(asn uint32) map[string]any {
	out := map[string]any{"asn": asn}
	has := false
	put := func(kind string, rs []crowdRate) {
		var list [][3]uint32
		for i, r := range rs {
			if r[1] > 0 {
				list = append(list, [3]uint32{uint32(i), r[0], r[1]})
			}
		}
		if len(list) > 0 {
			out[kind] = list
			has = true
		}
	}
	put("proto", c.Proto[:])
	put("style", c.Style[:])
	put("hello", c.Hello[:])
	put("port", c.Port[:])
	if !has {
		return nil
	}
	return out
}

// crowdSummary is one operator's numbers from the service: per kind, a list
// of [code, passed, tested].
type crowdSummary map[string][][3]float64

// seed adds the crowd's numbers to t, scaled down to crowdSeedWeight tests
// per kind.
func (t *netTable) seed(c crowdSummary) {
	apply := func(rs []passRate, list [][3]float64, all bool) {
		total := 0.0
		for _, r := range list {
			total += r[2]
		}
		if total == 0 {
			return
		}
		f := min(1, crowdSeedWeight/total)
		for _, r := range list {
			code, ok, n := int(r[0]), r[1], r[2]
			if code < 0 || code >= len(rs) || n <= 0 || ok < 0 || ok > n {
				continue
			}
			rs[code].OK += ok * f
			rs[code].N += n * f
			if all {
				t.All.OK += ok * f
				t.All.N += n * f
			}
		}
	}
	apply(t.Proto[:], c["proto"], true)
	apply(t.Style[:], c["style"], false)
	apply(t.Hello[:], c["hello"], false)
	apply(t.Port[:], c["port"], false)
	t.Seeded = true
}

func (e *Engine) shareStats() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settings.ShareStats && len(e.crowdURLs) > 0
}

// crowdLookup asks the service, directly (privateDirect) and not through the VPN, which
// operator this network is (the service sees it from where the request
// comes from) and what passes there, and seeds a new network's table.
func (e *Engine) crowdLookup(ctx context.Context) {
	if !e.shareStats() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var got struct {
		ASN  uint32                  `json:"asn"`
		ASNs map[string]crowdSummary `json:"asns"`
	}
	if !e.crowdCall(ctx, e.privateDirect, http.MethodGet, "stats?asn=self", nil, &got) || got.ASN == 0 {
		return
	}
	e.net.mu.Lock()
	t := e.net.table()
	t.ASN = got.ASN
	seeded := false
	if c, ok := got.ASNs[strconv.FormatUint(uint64(got.ASN), 10)]; ok && !t.Seeded && t.All.N < crowdSeedBelow {
		t.seed(c)
		seeded = true
	}
	e.net.mu.Unlock()
	if seeded {
		e.logf("info", "Started from what other users on this network found works.")
	}
}

// crowdReport sends each network's tests since its last report. It only
// goes through the VPN, so the report does not show the service where it
// comes from, and the network does not see the device talk to the service.
func (e *Engine) crowdReport(ctx context.Context) {
	hc := e.proxyClient()
	if !e.shareStats() || hc == nil {
		return
	}
	type pending struct {
		key  string
		body map[string]any
	}
	var todo []pending
	e.net.mu.Lock()
	for k, t := range e.net.Nets {
		if t.ASN == 0 {
			continue
		}
		if b := t.Pend.report(t.ASN); b != nil {
			todo = append(todo, pending{k, b})
		}
	}
	e.net.mu.Unlock()
	for _, p := range todo {
		if ctx.Err() != nil {
			return
		}
		if !e.crowdCall(ctx, hc, http.MethodPost, "stats", p.body, nil) {
			continue
		}
		e.net.mu.Lock()
		if t := e.net.Nets[p.key]; t != nil {
			// Tests made while the report was on its way stay for the next.
			t.Pend.minus(p.body)
		}
		e.net.mu.Unlock()
	}
}

// minus takes a sent report off the pending counts.
func (c *crowdCounts) minus(body map[string]any) {
	sub := func(rs []crowdRate, v any) {
		list, _ := v.([][3]uint32)
		for _, r := range list {
			if int(r[0]) < len(rs) {
				x := &rs[r[0]]
				x[0] -= min(x[0], r[1])
				x[1] -= min(x[1], r[2])
			}
		}
	}
	sub(c.Proto[:], body["proto"])
	sub(c.Style[:], body["style"])
	sub(c.Hello[:], body["hello"])
	sub(c.Port[:], body["port"])
}

// crowdCall tries the service's addresses in turn.
func (e *Engine) crowdCall(ctx context.Context, hc *http.Client, method, path string, body, out any) bool {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	for _, base := range e.crowdURLs {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+"/api/v1/"+path, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			// The service answered; another address would say the same.
			return false
		}
		return out == nil || json.Unmarshal(b, out) == nil
	}
	return false
}
