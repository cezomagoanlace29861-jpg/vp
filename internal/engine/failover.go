package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/tester"
)

// How a live connection is watched. The server in use is checked often,
// and at once when the core reports failed connections or traffic stalls;
// the whole group is checked less often so backups are known to work before
// they are needed. Both slow down while nothing is being sent.
const (
	checkBusy = 10 * time.Second
	checkIdle = 15 * time.Second
	sweepBusy = 90 * time.Second
	sweepIdle = 5 * time.Minute
	// idleAfter is how long without traffic counts as idle.
	idleAfter = 30 * time.Second
	// refreshAfter is the youngest a group can be refreshed at.
	refreshAfter = 5 * time.Minute
	// quietFor is how long without traffic a group must be before it is
	// refreshed, which restarts the core.
	quietFor = 3 * time.Minute
	// stayAtLeast is how long a member stays in use before it is swapped
	// for a better one; a member that stops answering is left at once.
	// Each swap changes the exit address, which can sign users out, and
	// delays of seconds on filtered networks are noisy enough to make two
	// servers look faster in turn.
	stayAtLeast = 20 * time.Minute
)

// Speed tests: real downloads through one member, made only while traffic
// flows and only when the member in use is not already fast.
// speedURL serves the number of bytes asked for; tests point it elsewhere.
var speedURL = "https://speed.cloudflare.com/__down?bytes="

const (
	// fastEnough is the speed (bytes/s) at which nothing is compared.
	fastEnough = 1 << 20
	// usable is the lowest speed a backup is preferred at before untested ones.
	usable = 150 << 10
	// speedFresh is how long a speed result is trusted.
	speedFresh = 15 * time.Minute
)

// speedPlan is how often and how much to test; phones test less and smaller.
func speedPlan(mobile bool) (every time.Duration, size int) {
	if mobile {
		return 5 * time.Minute, 512 << 10
	}
	return 3 * time.Minute, 2 << 20
}

// healthURL is what the core fetches through a member to check it.
const healthURL = "https://www.gstatic.com/generate_204"

// clashClient talks to the cores' local Clash API. It never uses a proxy.
var clashClient = &http.Client{Transport: &http.Transport{
	Proxy:               nil,
	MaxIdleConnsPerHost: 8,
	IdleConnTimeout:     30 * time.Second,
}}

// api calls the core's Clash API. reached is false when the core itself did
// not answer (it is starting, stopping or gone), so a failure says nothing
// about the servers.
func (c *connection) api(ctx context.Context, method, path string, body, out any, timeout time.Duration) (status int, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+c.clashAddr+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.clashSecret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := clashClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, fmt.Errorf("clash api %s: HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

func delayQuery(timeout time.Duration) string {
	return url.Values{"url": {healthURL}, "timeout": {strconv.Itoa(int(timeout / time.Millisecond))}}.Encode()
}

// test fetches healthURL through one member. reached is false when the
// core could not be asked, in which case ok means nothing.
func (c *connection) test(ctx context.Context, m *member, timeout time.Duration) (delay int, ok, reached bool) {
	var r struct {
		Delay int `json:"delay"`
	}
	status, err := c.api(ctx, http.MethodGet, "/proxies/"+url.PathEscape(m.tag)+"/delay?"+delayQuery(timeout), nil, &r, timeout+2*time.Second)
	if status == 0 {
		return 0, false, false
	}
	return r.Delay, err == nil && r.Delay > 0, true
}

// testTag is test for any outbound or endpoint by tag.
func (c *connection) testTag(ctx context.Context, tag string, timeout time.Duration) (delay int, ok bool) {
	var r struct {
		Delay int `json:"delay"`
	}
	_, err := c.api(ctx, http.MethodGet, "/proxies/"+url.PathEscape(tag)+"/delay?"+delayQuery(timeout), nil, &r, timeout+2*time.Second)
	return r.Delay, err == nil && r.Delay > 0
}

// use makes m the member all new connections go through.
func (c *connection) use(ctx context.Context, m *member) error {
	if _, err := c.api(ctx, http.MethodPut, "/proxies/proxy", map[string]string{"name": m.tag}, nil, 3*time.Second); err != nil {
		return err
	}
	c.mu.Lock()
	if c.active != m {
		c.switched = time.Now()
	}
	c.active = m
	if m.delay > 0 {
		c.delay = m.delay
	}
	c.mu.Unlock()
	return nil
}

// keep makes m the member stickyDomains go through.
func (c *connection) keep(ctx context.Context, m *member) {
	if _, err := c.api(ctx, http.MethodPut, "/proxies/sticky", map[string]string{"name": m.tag}, nil, 3*time.Second); err != nil {
		return
	}
	c.mu.Lock()
	c.sticky = m
	c.mu.Unlock()
}

// closeOn closes the connections still going through tag, so apps waiting
// on a dead server reconnect through the new one right away instead of
// timing out.
func (c *connection) closeOn(ctx context.Context, tag string) {
	var list struct {
		Connections []struct {
			ID     string   `json:"id"`
			Chains []string `json:"chains"`
		} `json:"connections"`
	}
	if _, err := c.api(ctx, http.MethodGet, "/connections", nil, &list, 3*time.Second); err != nil {
		return
	}
	for _, conn := range list.Connections {
		for _, t := range conn.Chains {
			if t == tag {
				c.api(ctx, http.MethodDelete, "/connections/"+url.PathEscape(conn.ID), nil, nil, 2*time.Second)
				break
			}
		}
	}
}

// poke asks the monitor to check the active server now.
func (c *connection) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

type logErr struct {
	at   time.Time
	host string
}

// watchLog reacts to the core reporting failed connections: the server in
// use is checked right away instead of at the next tick. Failing to reach
// the server itself ("dial tcp <server>") is checked at once. A failure
// further on says nothing about the server when only one site has it (the
// site may be down or refuse the visitor), so that takes failures to
// several sites within a few seconds.
func (c *connection) watchLog(core, line string) {
	if core != "sing-box" || !strings.HasPrefix(line, "ERROR") || !strings.Contains(line, "connection") ||
		strings.Contains(line, "outbound/direct") {
		return
	}
	host := line
	if _, rest, ok := strings.Cut(line, "connection to "); ok {
		host, _, _ = strings.Cut(rest, " ")
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if strings.Contains(line, ": dial tcp ") || strings.Contains(line, ": dial udp ") {
		c.poke()
		return
	}
	now := time.Now()
	c.mu.Lock()
	keep := c.errs[:0]
	hosts := map[string]bool{host: true}
	for _, e := range c.errs {
		if now.Sub(e.at) < 10*time.Second {
			keep = append(keep, e)
			hosts[e.host] = true
		}
	}
	c.errs = append(keep, logErr{now, host})
	trouble := len(hosts) >= 3
	if trouble {
		c.errs = nil
	}
	c.mu.Unlock()
	if trouble {
		c.poke()
	}
}

// idle reports whether no traffic has passed for a while.
func (c *connection) idle() bool { return c.idleFor(idleAfter) }

func (c *connection) idleFor(d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.lastBusy) > d
}

func (c *connection) every(busy, quiet time.Duration) time.Duration {
	if c.idle() {
		return quiet
	}
	return busy
}

// backups lists the members known to work, other than skip, best first:
// the group's own country, then those measured fast (fastest first), then
// untested ones (lowest delay first), then those measured slow.
func (c *connection) backups(skip map[*member]bool) []*member {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*member
	for _, m := range c.members {
		if m.alive && !m.forged && !skip[m] {
			out = append(out, m)
		}
	}
	rank := func(m *member) int {
		switch {
		case m.soaked < 0:
			return 3
		case !m.speedKnown():
			return 1
		case m.speed >= usable:
			return 0
		}
		return 2
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ha, hb := a.country == c.home, b.country == c.home; ha != hb {
			return ha
		}
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		if rank(a) != 1 {
			return a.speed > b.speed
		}
		return a.delay < b.delay
	})
	return out
}

// speedKnown reports whether m has a recent speed result. The caller holds
// connection.mu.
func (m *member) speedKnown() bool {
	return !m.speedAt.IsZero() && time.Since(m.speedAt) < speedFresh
}

// noteResult records a check of a member, on the member and on the server
// it runs, so the scanner does not need to test servers in use again.
func (e *Engine) noteResult(c *connection, m *member, delay int, ok bool) {
	now := time.Now()
	c.mu.Lock()
	m.checked = now
	if ok {
		// One sample is noisy; a member's delay is a running average.
		if m.delay > 0 && m.alive {
			delay = (m.delay + delay) / 2
		}
		m.alive, m.delay, m.fails = true, delay, 0
	} else {
		m.alive = false
		m.fails++
	}
	c.mu.Unlock()
	e.mu.Lock()
	s := m.server
	s.TestedAt = now
	if ok {
		s.LastOK, s.Delay, s.Fails = now, delay, 0
	} else {
		s.Fails++
	}
	e.mu.Unlock()
}

// race tests members at once and returns the first to answer, or nil when
// none does within timeout. The others keep being tested in the background
// and their results are recorded too.
func (e *Engine) race(ctx context.Context, c *connection, list []*member, timeout time.Duration) *member {
	c.mu.Lock()
	var trusted []*member
	for _, m := range list {
		if !m.forged {
			trusted = append(trusted, m)
		}
	}
	c.mu.Unlock()
	list = trusted
	if len(list) == 0 {
		return nil
	}
	first := make(chan *member, len(list))
	var wg sync.WaitGroup
	for _, m := range list {
		wg.Add(1)
		go func(m *member) {
			defer wg.Done()
			d, ok, reached := c.test(ctx, m, timeout)
			if !reached {
				return
			}
			e.noteResult(c, m, d, ok)
			if ok {
				first <- m
			}
		}(m)
	}
	go func() {
		wg.Wait()
		close(first)
	}()
	select {
	case m := <-first:
		return m
	case <-ctx.Done():
		return nil
	}
}

// monitor watches a connection: traffic, the health of the server in use
// and of its backups, and whether the group should be refreshed.
func (e *Engine) monitor(ctx context.Context, c *connection) {
	go c.streamTraffic(ctx)
	go e.soakBackups(ctx, c)
	go e.watchWarpExit(ctx, c)
	if e.acct != nil {
		go e.meter(ctx, c)
	}
	if r, ok := findRegion(c.bypass); ok {
		go e.learnLocal(ctx, c, r)
	}
	check := time.NewTimer(checkBusy)
	defer check.Stop()
	// The race at connect time already checked most of the group; look at
	// the whole of it again soon.
	sweep := time.NewTimer(20 * time.Second)
	defer sweep.Stop()
	var last time.Time
	// The server in use is checked for forged certificates a minute in,
	// then every interceptEvery.
	intercept := time.NewTimer(time.Minute)
	defer intercept.Stop()
	// A core that crashes is replaced at once, not at the next check.
	var died <-chan struct{}
	if c.running != nil && c.running.SingBox != nil {
		died = c.running.SingBox.Done()
	}
	for {
		urgent := false
		select {
		case <-ctx.Done():
			return
		case <-died:
			if ctx.Err() != nil {
				return // stopped on purpose
			}
			died = nil
		case <-c.wake:
			if time.Since(last) < 2*time.Second {
				continue
			}
			urgent = true
		case <-check.C:
		case <-sweep.C:
			if !e.sweep(ctx, c) {
				return
			}
			sweep.Reset(c.every(sweepBusy, sweepIdle))
			continue
		case <-intercept.C:
			intercept.Reset(interceptEvery)
			m := c.activeMember()
			if !e.checkIntercept(ctx, c, m) {
				continue
			}
			if !e.failover(ctx, c, m) {
				return
			}
			continue
		}
		last = time.Now()
		if !e.checkActive(ctx, c, urgent) {
			return
		}
		check.Reset(c.every(checkBusy, checkIdle))
	}
}

// checkActive tests the server in use and fails over when it stopped
// answering. urgent means there is already evidence of trouble (failed
// connections, stalled traffic), so one failed check is enough. It reports
// false once the connection has been replaced.
func (e *Engine) checkActive(ctx context.Context, c *connection, urgent bool) bool {
	if !c.running.Alive() {
		e.logf("warn", "The connection core stopped; reconnecting…")
		e.rebuild(c, nil)
		return false
	}
	m := c.activeMember()
	c.mu.Lock()
	usual := time.Duration(m.delay) * time.Millisecond
	c.mu.Unlock()
	// Servers that answer in seconds are common on filtered networks; a
	// fixed limit would call them dead on every check.
	timeout := min(max(4*time.Second, 2*usual+time.Second), 10*time.Second)
	if urgent {
		// A server that usually answers in 300 ms and has not in 1.5 s is
		// not coming back.
		timeout = min(max(3*usual+500*time.Millisecond, 1500*time.Millisecond), max(3*time.Second, 2*usual))
	}
	d, ok, reached := c.test(ctx, m, timeout)
	if reached && !ok && ctx.Err() == nil {
		// A second try rules out one lost request, or a busy server
		// answering a little late.
		d, ok, reached = c.test(ctx, m, min(max(timeout, 3*time.Second, 2*usual+time.Second), 10*time.Second))
	}
	if ctx.Err() != nil {
		return false
	}
	if !reached {
		// The core did not answer its own API; the next tick sees whether
		// it died.
		return true
	}
	e.noteResult(c, m, d, ok)
	if ok {
		c.mu.Lock()
		c.healthy, c.delay = true, d
		c.mu.Unlock()
		return true
	}
	return e.failover(ctx, c, m)
}

// style is the wire style of the member's server.
func (m *member) style() uint8 {
	if n := m.server.Node(); n != nil {
		return n.Style()
	}
	return 0
}

// failover moves traffic off a member that stopped answering: at once to a
// backup known to work, else to whichever member answers first now, and
// only when the whole group is down to a fresh group in the same country.
// It reports false once the connection has been replaced.
func (e *Engine) failover(ctx context.Context, c *connection, dead *member) bool {
	c.mu.Lock()
	inUse := time.Since(c.switched)
	wasActive := c.active == dead
	c.mu.Unlock()
	if wasActive {
		e.net.recordLife(dead.style(), inUse)
	}
	tried := map[*member]bool{dead: true}
	for _, b := range c.backups(tried) {
		tried[b] = true
		if c.use(ctx, b) != nil {
			continue
		}
		c.closeOn(ctx, dead.tag)
		// Switch first, then confirm: the check that found b alive may be
		// a few minutes old.
		d, ok, reached := c.test(ctx, b, 4*time.Second)
		if reached {
			e.noteResult(c, b, d, ok)
		}
		if ok || !reached {
			e.switched(ctx, c, dead, b)
			return true
		}
	}
	if ctx.Err() != nil {
		return false
	}
	var rest []*member
	for _, m := range c.members {
		if !tried[m] {
			rest = append(rest, m)
		}
	}
	if b := e.race(ctx, c, rest, 5*time.Second); b != nil && c.use(ctx, b) == nil {
		c.closeOn(ctx, dead.tag)
		e.switched(ctx, c, dead, b)
		return true
	}
	if e.offline(ctx, c) && ctx.Err() == nil {
		// Every server looks dead when this device has no internet; keep
		// the group and carry on once it is back.
		e.setStatus(StatusReconnecting, "No internet on this device; the connection resumes when it is back.")
		for e.offline(ctx, c) {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(3 * time.Second):
			}
		}
		if ctx.Err() != nil {
			return false
		}
		e.setStatus(StatusConnected, connectedMessage(c))
		c.poke()
		return true
	}
	// Building a new group restarts the core, which drops every open
	// connection and can take long when few servers are known. A burst of
	// loss on a filtered network can make the whole group miss one round,
	// so give all of it one more, slower chance first.
	select {
	case <-ctx.Done():
		return false
	case <-time.After(2 * time.Second):
	}
	if b := e.race(ctx, c, c.members, 8*time.Second); b != nil && c.use(ctx, b) == nil {
		if b != dead {
			c.closeOn(ctx, dead.tag)
		}
		e.switched(ctx, c, dead, b)
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	e.logf("warn", "No ready server answered; preparing a new group in %s…", countryName(c.home))
	e.refreshHotNow()
	e.rebuild(c, c.members)
	return false
}

// switched finishes a failover to b.
func (e *Engine) switched(ctx context.Context, c *connection, from, to *member) {
	c.mu.Lock()
	c.healthy = true
	move := c.sticky == nil || c.sticky == from
	c.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	if move {
		c.keep(ctx, to)
	}
	e.setStatus(StatusConnected, connectedMessage(c))
	if from == to {
		// It missed the checks but answered the race: a pause, not a drop.
		e.logf("info", "A paused server answered again.")
		return
	}
	e.logf("info", "A server dropped; switched at once to a ready server in the same location.")
	go e.refreshExit(ctx, c)
}

// refreshExit learns the new exit address after a switch.
func (e *Engine) refreshExit(ctx context.Context, c *connection) {
	r := tester.Probe(ctx, c.proxyURL(), 10*time.Second)
	if !r.OK {
		return
	}
	c.mu.Lock()
	c.exitIP = r.ExitIP
	if r.Country != "" {
		c.exitCC = r.Country
	}
	c.mu.Unlock()
}

// sweep checks every member at once, so backups are known to work before
// they are needed, moves to a clearly faster member, and refreshes a group
// that is running out of working backups while nobody is using it. It
// reports false once the connection has been replaced.
func (e *Engine) sweep(ctx context.Context, c *connection) bool {
	var live map[string]int
	timeout := 5 * time.Second
	if _, err := c.api(ctx, http.MethodGet, "/group/proxy/delay?"+delayQuery(timeout), nil, &live, timeout+3*time.Second); err != nil {
		return ctx.Err() == nil
	}
	if len(live) == 0 {
		// Nothing answered: more likely this device's network than eight
		// servers at once. A real check of the active one decides.
		c.poke()
		return true
	}
	for _, m := range c.members {
		d, ok := live[m.tag]
		e.noteResult(c, m, d, ok)
	}
	active := c.activeMember()
	if _, ok := live[active.tag]; !ok {
		c.poke()
		return true
	}
	c.mu.Lock()
	sticky := c.sticky
	c.mu.Unlock()
	if _, ok := live[sticky.tagOr(active)]; !ok {
		c.keep(ctx, active)
	}
	e.mu.Lock()
	auto := e.settings.AutoSwitch
	e.mu.Unlock()
	if !auto || c.pinned {
		return true
	}
	if !c.idle() {
		// Speed tests take seconds; health checks must not wait for them.
		go e.speedRound(ctx, c)
	} else if b := c.faster(); b != nil && c.confirmFaster(b) && c.use(ctx, b) == nil {
		c.mu.Lock()
		d := b.delay
		c.mu.Unlock()
		e.logf("info", "A faster server was found in this group (%d ms).", d)
	} else if b == nil {
		c.confirmFaster(nil)
	}
	// A group younger than refreshAfter is left alone, so a country whose
	// servers keep failing does not restart the core over and over. The
	// restart drops connections that apps keep open while quiet (messaging,
	// notifications), so it waits for a longer quiet spell than "idle".
	if c.idleFor(quietFor) && time.Since(c.started) > refreshAfter && e.groupStale(c) {
		e.logf("info", "Refreshing backup servers in %s…", countryName(c.home))
		e.rebuild(c, nil)
		return false
	}
	return true
}

// confirmFaster reports whether b was also the faster member at the last
// sweep: one lucky measurement is not reason enough to change the exit.
func (c *connection) confirmFaster(b *member) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	same := b != nil && c.fasterSeen == b
	c.fasterSeen = b
	if same {
		c.fasterSeen = nil
	}
	return same
}

// faster returns a live member clearly faster than the one in use. It is
// asked only while idle: under the user's traffic the member in use answers
// later than idle backups do, which would make every backup look faster.
func (c *connection) faster() *member {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.active.delay
	if cur <= 0 || time.Since(c.switched) < stayAtLeast {
		return nil
	}
	var best *member
	for _, m := range c.members {
		if m == c.active || !m.alive || m.country != c.active.country {
			continue
		}
		if m.speedKnown() && m.speed < usable {
			continue
		}
		if float64(m.delay) < float64(cur)*0.7 && cur-m.delay > 80 && (best == nil || m.delay < best.delay) {
			best = m
		}
	}
	return best
}

// groupStale reports whether rebuilding the group would help: too few
// members still work and the same country has others to offer. Faster
// servers elsewhere are not reason enough: the restart drops connections,
// and the group already moves to its own fastest member without one.
func (e *Engine) groupStale(c *connection) bool {
	c.mu.Lock()
	live := 0
	inGroup := map[string]bool{}
	for _, m := range c.members {
		inGroup[m.server.Key] = true
		if m.alive {
			live++
		}
	}
	c.mu.Unlock()
	fresh := e.bestServers(c.home, groupSize, inGroup)
	return live < minReady && len(fresh) >= minReady-live
}

// rebuild replaces the connection with a fresh group in the same country,
// avoiding the members that just failed.
func (e *Engine) rebuild(c *connection, failed []*member) {
	e.setStatus(StatusReconnecting, fmt.Sprintf("Preparing fresh servers in %s…", countryName(c.home)))
	var avoid []string
	for _, m := range failed {
		avoid = append(avoid, m.server.Key)
	}
	e.mu.Lock()
	gen := e.connGen
	e.mu.Unlock()
	e.stopConn(c, false)
	go func() {
		// A stale loop gave way to a newer connect, whose VPN must stay up.
		if err := e.connectLoop(gen, c.country, c.home, nil, avoid); err != nil && !errors.Is(err, errStale) {
			e.mu.Lock()
			still := e.conn == nil
			e.mu.Unlock()
			if still {
				e.clearProxy()
			}
		}
	}()
}

// offlineProbes are reachable from almost anywhere, inside Iran and out.
var offlineProbes = []string{"1.1.1.1:443", "8.8.8.8:443", "www.aparat.com:443", "www.digikala.com:443"}

// offline reports whether this device cannot open any TCP connection: not
// to the group's servers and not to well-known sites.
func (e *Engine) offline(ctx context.Context, c *connection) bool {
	addrs := append([]string(nil), offlineProbes...)
	for _, m := range c.members {
		if m.endpoint != "" {
			addrs = append(addrs, m.endpoint)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	up := make(chan struct{}, len(addrs))
	for _, a := range addrs {
		go func(a string) {
			var d net.Dialer
			if conn, err := d.DialContext(ctx, "tcp", a); err == nil {
				conn.Close()
				up <- struct{}{}
			}
		}(a)
	}
	select {
	case <-up:
		return false
	case <-ctx.Done():
		return true
	}
}

// streamTraffic follows the core's per-second traffic counters. One small
// line a second costs far less than polling the connection list.
func (c *connection) streamTraffic(ctx context.Context) {
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.clashAddr+"/traffic", nil)
		req.Header.Set("Authorization", "Bearer "+c.clashSecret)
		if resp, err := clashClient.Do(req); err == nil {
			dec := json.NewDecoder(resp.Body)
			for {
				var t struct {
					Up   int64 `json:"up"`
					Down int64 `json:"down"`
				}
				if dec.Decode(&t) != nil {
					break
				}
				c.addTraffic(t.Up, t.Down)
			}
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// heavyRate is the traffic, in bytes a second, above which background
// tests slow down (scanPace).
const heavyRate = 256 << 10

// heavy reports whether the user is moving a lot of data right now.
func (c *connection) heavy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.upRate+c.dnRate > heavyRate && time.Since(c.lastBusy) < 5*time.Second
}

func (c *connection) addTraffic(up, down int64) {
	c.mu.Lock()
	c.up += up
	c.down += down
	c.upRate, c.dnRate = up, down
	if up+down > 0 {
		c.lastBusy = time.Now()
	}
	// Apps that sent a request and got nothing back for a few seconds
	// usually mean the server in use went silent. An upload (a file, a
	// video call) sends a lot and gets little back; that is not a stall.
	now := time.Now()
	stalled := false
	switch {
	case up >= 64<<10:
		c.waiting = time.Time{}
	case up > 0 && c.waiting.IsZero():
		// Download in the same second may belong to older connections; only
		// a later answer counts.
		c.waiting = now
	case down > 0:
		c.waiting = time.Time{}
	case !c.waiting.IsZero() && now.Sub(c.waiting) >= 2*time.Second:
		c.waiting = time.Time{}
		stalled = true
	}
	c.mu.Unlock()
	if stalled {
		c.poke()
	}
}

// speed downloads through one member and returns its speed in bytes per
// second, timed from the first byte so connection setup is left out.
func (c *connection) speed(ctx context.Context, m *member, size int) (float64, error) {
	proxy := &url.URL{Scheme: "http", User: url.UserPassword(m.tag, c.clashSecret), Host: c.probeAddr}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, speedURL+strconv.Itoa(size), nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("speed test: HTTP %d", resp.StatusCode)
	}
	start := time.Now()
	// A server too slow to finish in time is measured on what arrived.
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(size)))
	took := time.Since(start)
	if n < 64<<10 {
		if ctx.Err() != nil {
			return float64(n) / took.Seconds(), nil
		}
		return 0, fmt.Errorf("speed test: only %d bytes", n)
	}
	return float64(n) / max(took.Seconds(), 0.05), nil
}

// noteLine learns the line speed from a result. Hysteria servers are left
// out: they send at the speed asked for, which comes from this number.
func (e *Engine) noteLine(m *member, bps float64) {
	if p := m.server.Proto; p != "hysteria2" && p != "hysteria" {
		e.net.recordLine(bps)
	}
}

// noteSpeed records a speed result on m.
func (c *connection) noteSpeed(m *member, bps float64) {
	c.mu.Lock()
	m.speed, m.speedAt = bps, time.Now()
	c.mu.Unlock()
}

// speedRound measures the member in use while traffic flows and, when it is
// slow, its best backups; it moves to one that is much faster. A server can
// answer pings quickly and still carry little, so delay alone cannot tell.
// To avoid swapping on one unlucky test, a backup must win twice in a row
// unless it is more than four times as fast.
func (e *Engine) speedRound(ctx context.Context, c *connection) {
	every, size := speedPlan(e.opt.Mobile)
	c.mu.Lock()
	due := time.Since(c.speedAt) >= every && time.Since(c.switched) >= stayAtLeast
	if due {
		c.speedAt = time.Now()
	}
	active := c.active
	c.mu.Unlock()
	if !due {
		return
	}
	cur, err := c.speed(ctx, active, size)
	if err != nil {
		// The health checks decide about a member that does not answer.
		return
	}
	c.noteSpeed(active, cur)
	e.noteLine(active, cur)
	if cur >= fastEnough {
		c.mu.Lock()
		c.slowRuns = 0
		c.mu.Unlock()
		return
	}
	var best *member
	var bestSpeed float64
	tested := 0
	for _, b := range c.backups(map[*member]bool{active: true}) {
		if tested == 2 || ctx.Err() != nil {
			break
		}
		c.mu.Lock()
		same := b.country == active.country
		c.mu.Unlock()
		if !same {
			continue
		}
		tested++
		s, err := c.speed(ctx, b, size)
		if err != nil {
			continue
		}
		c.noteSpeed(b, s)
		e.noteLine(b, s)
		if s > bestSpeed {
			best, bestSpeed = b, s
		}
	}
	c.mu.Lock()
	if tested > 0 && cur < usable && bestSpeed < usable && time.Since(c.slowNet) > time.Hour {
		// Every server is slow, so the network itself is (Iran throttles
		// all encrypted traffic at times). Switching would only drop
		// connections; say so instead.
		c.slowNet = time.Now()
		c.mu.Unlock()
		e.logf("info", "Every server is slow right now (%s at best), so the network itself is slow; staying on the current server.", rate(max(cur, bestSpeed)))
		return
	}
	better := best != nil && bestSpeed >= 2*cur && bestSpeed-cur >= 200<<10
	if better {
		c.slowRuns++
	} else {
		c.slowRuns = 0
	}
	// A failover may have moved traffic meanwhile.
	swap := better && (c.slowRuns >= 2 || bestSpeed >= 4*cur) && c.active == active
	if swap {
		c.slowRuns = 0
	}
	c.mu.Unlock()
	if !swap || c.use(ctx, best) != nil {
		return
	}
	e.logf("info", "A server was slow (%s); switched to one at %s in the same location.", rate(cur), rate(bestSpeed))
}

// rate formats a speed in bytes per second for the log.
func rate(bps float64) string {
	if bps >= 1<<20 {
		return fmt.Sprintf("%.1f MB/s", bps/(1<<20))
	}
	return fmt.Sprintf("%.0f KB/s", bps/(1<<10))
}

// tagOr is m's tag, or other's when m is nil.
func (m *member) tagOr(other *member) string {
	if m == nil {
		return other.tag + "\x00" // never live, so the caller moves it
	}
	return m.tag
}
