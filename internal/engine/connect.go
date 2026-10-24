package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/core"
	"github.com/cezomagoanlace29861-jpg/vp/internal/geo"
	"github.com/cezomagoanlace29861-jpg/vp/internal/node"
	"github.com/cezomagoanlace29861-jpg/vp/internal/tester"
)

// groupSize is how many servers one connection keeps ready: the one in use
// and its backups, all from the same country. They run in one core behind a
// selector, so moving to a backup is a change of selection, not a restart.
const groupSize = 8

// minReady is how many members of a group should be known to work. Below
// that the group is refreshed with new servers from the same country the
// next time the connection is idle.
const minReady = 3

// connectWide is how many candidates a connection attempt looks at. On a
// filtered network most servers that worked an hour ago are gone; a quick
// TCP check of many at once finds the live ones in seconds, where testing
// groups of groupSize one after another took a minute.
const connectWide = 40

type connection struct {
	warp        bool   // the config holds the WARP exit (watchWarpExit)
	country     string // what the user asked for ("" = fastest anywhere)
	home        string // country the group was built in; backups stay here
	pinned      bool   // the user picked this one server
	bypass      string // region whose sites go direct ("" = none)
	mode        string
	proxyAddr   string
	proxyUser   string // with proxyPass, the local proxy's login ("" = none, see privateProxy)
	proxyPass   string
	running     *core.Running
	servers     []*Server
	members     []*member
	clashAddr   string
	clashSecret string
	probeAddr   string // reaches one member by name, for speed tests
	started     time.Time
	sysProxy    bool
	cancel      context.CancelFunc
	wake        chan struct{} // asks the monitor to check the active server now

	mu         sync.Mutex
	active     *member
	sticky     *member // where stickyDomains go; moves only when it fails
	fasterSeen *member // the faster member the last sweep found
	delay      int
	exitIP     string
	exitCC     string
	up         int64
	down       int64
	upRate     int64
	dnRate     int64
	lastBusy   time.Time // last second that carried traffic
	waiting    time.Time // when data went out with nothing back since
	healthy    bool
	switched   time.Time // last time the member in use changed
	speedAt    time.Time // last speed round
	slowRuns   int       // speed rounds in a row that found a much faster backup
	slowNet    time.Time // when the whole network was last found slow
	errs       []logErr  // recent failed connections, for watchLog
}

// member is one server of a live group.
type member struct {
	tag      string // outbound tag in the core
	server   *Server
	country  string // exit country when the group was built
	endpoint string // host:port to dial for an offline check ("" for UDP)

	// Guarded by connection.mu.
	alive   bool
	delay   int
	fails   int // failed checks in a row
	checked time.Time
	speed   float64 // download bytes per second at the last speed test
	speedAt time.Time
	soaked  int8 // endurance check: 1 passed, -1 failed, 0 not run
	// forged: the server showed a forged certificate; it is never used.
	forged bool
}

func (c *connection) ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.healthy
}

func (c *connection) activeMember() *member {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *connection) activeKey() string {
	if m := c.activeMember(); m != nil {
		return m.server.Key
	}
	return ""
}

func (c *connection) uses(key string) bool {
	for _, s := range c.servers {
		if s.Key == key {
			return true
		}
	}
	return false
}

// Connect connects to the fastest servers in country ("" = anywhere). If
// none are known yet it searches until it finds some.
func (e *Engine) Connect(country string) error {
	if e.updateRequired() {
		return ErrUpdateRequired
	}
	if err := e.AllowConnect(); err != nil {
		var limit *LimitError
		if errors.As(err, &limit) {
			e.setStatus(StatusIdle, limit.Message)
		}
		return err
	}
	country = strings.ToUpper(strings.TrimSpace(country))
	e.mu.Lock()
	e.target = country
	e.settings.Country = country
	e.settings.Connected = true
	e.wantConnect = true
	e.connGen++
	e.cancelAttempt()
	gen := e.connGen
	mode := e.settings.Mode
	e.mu.Unlock()
	saveJSON(filepath.Join(e.dir, "settings.json"), e.Settings())
	if mode == "tun" && !e.opt.IsAdmin() {
		e.setStatus(StatusIdle, "")
		return ErrNeedAdmin
	}
	e.poke()
	return e.connectLoop(gen, country, "", nil, nil)
}

// ConnectServer connects to one specific working server.
func (e *Engine) ConnectServer(key string) error {
	if e.updateRequired() {
		return ErrUpdateRequired
	}
	if err := e.AllowConnect(); err != nil {
		return err
	}
	e.mu.Lock()
	var s *Server
	for _, g := range e.good {
		if g.Key == key {
			s = g
		}
	}
	if s == nil {
		e.mu.Unlock()
		return fmt.Errorf("server not found")
	}
	e.target = s.Country
	e.settings.Connected = true
	e.wantConnect = true
	e.connGen++
	e.cancelAttempt()
	gen := e.connGen
	e.mu.Unlock()
	saveJSON(filepath.Join(e.dir, "settings.json"), e.Settings())
	return e.connectLoop(gen, s.Country, "", []*Server{s}, nil)
}

func countryName(code string) string {
	if code == "" {
		return "Fastest location"
	}
	c, _ := geo.Lookup(code)
	return c.EN
}

// connectLoop keeps trying until a group in country is up. home keeps a
// fastest-anywhere connection in the country it was already using; avoid
// lists servers that just failed.
func (e *Engine) connectLoop(gen int, country, home string, pinned []*Server, avoid []string) error {
	name := countryName(country)
	deadline := time.Now().Add(3 * time.Minute)
	exclude := map[string]bool{}
	for _, k := range avoid {
		exclude[k] = true
	}
	triedRecent := false
	for attempt := 0; ; attempt++ {
		e.mu.Lock()
		want := e.wantConnect && e.target == country && e.connGen == gen
		e.mu.Unlock()
		if !want || e.ctx.Err() != nil {
			return errors.New("cancelled")
		}
		picks := pinned
		if picks == nil {
			picks = e.reachable(e.pickGroup(country, home, exclude, connectWide), groupSize, exclude)
		}
		if len(picks) == 0 && pinned == nil && !triedRecent {
			// Nothing fresh: try last week's servers once before waiting on
			// the scan.
			triedRecent = true
			picks = e.reachable(e.recentServers(country, connectWide, exclude), groupSize, exclude)
		}
		if len(picks) == 0 {
			if len(exclude) > 0 {
				// Everything usable has been tried once; try again after the
				// pause. Servers that keep failing drop out on their own.
				exclude = map[string]bool{}
			}
			e.setStatus(StatusSearching, fmt.Sprintf("Looking for a server in %s…", name))
			if time.Now().After(deadline) {
				e.setStatus(StatusSearching, fmt.Sprintf("No server in %s yet. Still looking; you will be connected as soon as one is found.", name))
			}
			select {
			case <-e.ctx.Done():
				return e.ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		e.setStatus(StatusConnecting, fmt.Sprintf("Connecting to %s…", name))
		err := e.start(gen, country, picks, pinned != nil)
		if err == nil {
			return nil
		}
		e.mu.Lock()
		stale := e.connGen != gen
		e.mu.Unlock()
		if stale || errors.Is(err, errStale) {
			return errStale
		}
		e.logf("warn", "Connection attempt failed: %v", err)
		for _, s := range picks {
			exclude[s.Key] = true
		}
		if pinned != nil {
			e.setStatus(StatusIdle, "This server is not available right now.")
			e.mu.Lock()
			e.wantConnect = false
			e.mu.Unlock()
			return err
		}
		if attempt > 6 {
			exclude = map[string]bool{}
		}
	}
}

// pickGroup chooses the servers for a connection: the fastest in country
// with backups from the same country. A fastest-anywhere group forms around
// the best server's country (or home, when it already had one) and reaches
// into other countries only when that country runs short.
func (e *Engine) pickGroup(country, home string, exclude map[string]bool, size int) []*Server {
	if country != "" {
		return e.bestServers(country, size, exclude)
	}
	if home == "" {
		best := e.bestServers("", 1, exclude)
		if len(best) == 0 {
			return nil
		}
		home = best[0].Country
	}
	group := e.bestServers(home, size, exclude)
	if len(group) >= minReady {
		return group
	}
	skip := map[string]bool{}
	for k := range exclude {
		skip[k] = true
	}
	for _, s := range group {
		skip[s.Key] = true
	}
	return append(group, e.bestServers("", size-len(group), skip)...)
}

// maxHandshake is the slowest TCP handshake a server may take to be picked
// while faster ones answer.
const maxHandshake = 1500 * time.Millisecond

// handshakeRTT opens tries TCP connections to addr at once and reports
// whether any succeeded and the median time of those that did.
func handshakeRTT(ctx context.Context, addr string, tries int) (bool, time.Duration) {
	times := make([]time.Duration, tries)
	got := make([]bool, tries)
	var wg sync.WaitGroup
	for k := range tries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			got[k] = tcpAnswers(ctx, addr)
			times[k] = time.Since(start)
		}()
	}
	wg.Wait()
	var ok []time.Duration
	for k := range tries {
		if got[k] {
			ok = append(ok, times[k])
		}
	}
	if len(ok) == 0 {
		return false, 0
	}
	sort.Slice(ok, func(a, b int) bool { return ok[a] < ok[b] })
	return true, ok[len(ok)/2]
}

// tcpAnswers reports whether addr accepts a TCP connection. Tests replace it.
var tcpAnswers = func(ctx context.Context, addr string) bool {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// reachable keeps the first n of list, in order, whose address accepts a
// TCP connection within a few seconds, and adds the rest to exclude.
// Servers on UDP cannot be checked this way and are kept.
func (e *Engine) reachable(list []*Server, n int, exclude map[string]bool) []*Server {
	ok := make([]bool, len(list))
	rtt := make([]time.Duration, len(list))
	ctx, cancel := context.WithTimeout(e.ctx, 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i, s := range list {
		nd := s.Node()
		if nd == nil || nd.UDPBased() {
			ok[i] = nd != nil
			continue
		}
		// The first few get three handshakes at once and the median
		// counts, so one lucky or unlucky packet does not decide.
		tries := 1
		if i < 20 {
			tries = 3
		}
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			ok[i], rtt[i] = handshakeRTT(ctx, addr, tries)
		}(i, nd.Endpoint())
	}
	wg.Wait()
	slow := 0
	for i := range list {
		if ok[i] && rtt[i] > maxHandshake {
			ok[i] = false
			slow++
		}
	}
	// Servers keep their places, but those reached over TCP are reordered
	// among themselves by how fast this network reaches them now.
	var tcp []int
	for i, s := range list {
		if ok[i] && !s.Node().UDPBased() {
			tcp = append(tcp, i)
		}
	}
	byRTT := append([]int(nil), tcp...)
	sort.SliceStable(byRTT, func(a, b int) bool {
		return rtt[byRTT[a]]/(20*time.Millisecond) < rtt[byRTT[b]]/(20*time.Millisecond)
	})
	order := make([]int, len(list))
	for i := range order {
		order[i] = i
	}
	for k, i := range tcp {
		order[i] = byRTT[k]
	}
	var out []*Server
	alive := 0
	for _, i := range order {
		if !ok[i] {
			continue
		}
		alive++
		if len(out) < n {
			out = append(out, list[i])
		}
	}
	if alive == 0 && slow > 0 {
		// Only slow ones answer: a slow server beats none.
		for i, s := range list {
			if rtt[i] > maxHandshake && len(out) < n {
				out = append(out, s)
			}
		}
		return out
	}
	if alive == 0 {
		// Nothing answered: more likely this device's network than every
		// server at once. Leave the list as it was.
		return list[:min(n, len(list))]
	}
	dead := map[string]bool{}
	for i, s := range list {
		if !ok[i] && rtt[i] <= maxHandshake {
			exclude[s.Key] = true
			nd := s.Node()
			dead[nd.Endpoint()] = true
			e.net.recordNet(nd.NetID(), false)
		}
	}
	// Other configs on an address that did not answer will not answer
	// either; skip them instead of finding that out one by one.
	e.mu.Lock()
	for _, s := range e.good {
		if nd := s.Node(); nd != nil && dead[nd.Endpoint()] {
			exclude[s.Key] = true
		}
	}
	e.mu.Unlock()
	return out
}

// bestServers picks the lowest-delay usable servers in a country.
func (e *Engine) bestServers(country string, n int, exclude map[string]bool) []*Server {
	return e.rankedServers(country, n, exclude, (*Server).usable)
}

// recentServers picks servers that worked in the last week but are no
// longer counted usable. When nothing fresh is known (the app was closed
// for a while, or filtering got heavier), trying them at once is much
// faster than waiting for a scan, and most still work.
func (e *Engine) recentServers(country string, n int, exclude map[string]bool) []*Server {
	return e.rankedServers(country, n, exclude, func(s *Server, now time.Time) bool {
		return !s.usable(now) && s.Fails < 6 && now.Sub(s.LastOK) < 7*24*time.Hour
	})
}

func (e *Engine) rankedServers(country string, n int, exclude map[string]bool, ok func(*Server, time.Time) bool) []*Server {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	var list []*Server
	for _, s := range e.good {
		if exclude[s.Key] || !ok(s, now) || s.Country == "IR" || !s.matches(e.settings.Protocol) {
			continue
		}
		if country != "" && s.Country != country {
			continue
		}
		if s.Plain && !e.settings.AllowPlain {
			continue
		}
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].rank(now) < list[j].rank(now) })
	// WireGuard peers sharing a private key fight over one session, and each
	// warp-plus method is a whole process; keep the group light.
	//
	// Backups that share a network, or a protocol, transport and port, tend
	// to be cut together by the same block, so the first pass takes at most
	// two from one network and two of one kind, the second drops the limit
	// on kinds, and the last fills what is left in plain rank order.
	var out []*Server
	taken := map[*Server]bool{}
	keys := map[string]bool{}
	nets := map[uint32]int{}
	kinds := map[string]int{}
	warpPlus := 0
	for pass := 0; pass < 3; pass++ {
		for _, s := range list {
			if len(out) >= n {
				break
			}
			nd := s.Node()
			if nd == nil || taken[s] {
				continue
			}
			kind := nd.Proto + "/" + nd.Transport + "/" + nd.Security + "/" + strconv.Itoa(nd.Port)
			if pass < 2 && nets[nd.NetID()] >= 2 || pass == 0 && kinds[kind] >= 2 {
				continue
			}
			if nd.Proto == "wireguard" {
				if keys[nd.PrivateKey] {
					continue
				}
				keys[nd.PrivateKey] = true
			}
			if nd.Proto == "warpplus" {
				if warpPlus >= 1 {
					continue
				}
				warpPlus++
			}
			taken[s] = true
			nets[nd.NetID()]++
			kinds[kind]++
			out = append(out, s)
		}
	}
	return out
}

var (
	// errStale means the user asked for something else meanwhile.
	errStale = errors.New("superseded")
	// errServers means the servers, not the local setup, failed.
	errServers = errors.New("servers failed")
)

// cancelAttempt stops a connection attempt that a newer connect or a
// disconnect made stale, so its core frees the proxy port at once. Called
// with mu held.
func (e *Engine) cancelAttempt() {
	if e.attempt != nil {
		e.attempt()
		e.attempt = nil
	}
}

// portFree reports whether a local TCP port can be bound.
func portFree(listen string, port int) bool {
	l, err := net.Listen("tcp", net.JoinHostPort(listen, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// start runs the cores for a group of servers and switches over to them.
func (e *Engine) start(gen int, country string, servers []*Server, pinned bool) error {
	e.startMu.Lock()
	defer e.startMu.Unlock()
	e.mu.Lock()
	if e.connGen != gen {
		e.mu.Unlock()
		return errStale
	}
	actx, acancel := context.WithCancel(e.ctx)
	defer acancel()
	e.attempt = acancel
	set := e.settings
	old := e.conn
	e.mu.Unlock()

	var nodes []*node.Node
	fragFor := map[*node.Node]bool{}
	byNode := map[*node.Node]*Server{}
	for _, s := range servers {
		n := s.runNode()
		if n == nil {
			continue
		}
		nodes = append(nodes, n)
		fragFor[n] = s.Fragment
		byNode[n] = s
	}
	if len(nodes) == 0 {
		return errors.New("no valid servers")
	}
	// The old connection must release the proxy port first.
	if old != nil {
		e.stopConn(old, false)
	}
	listen := "127.0.0.1"
	if set.AllowLAN {
		listen = "0.0.0.0"
	}
	proxyPort := set.ProxyPort
	private := privateProxy(e.opt.Mobile, set)
	if private {
		// No one but the app uses the port: a new one each time, so it does
		// not give the app away.
		if p, err := core.FreePorts(1); err == nil {
			proxyPort = p[0]
		}
	} else if !portFree(listen, proxyPort) {
		// Another program (often another VPN client) holds the port.
		if p, err := core.FreePorts(1); err == nil {
			e.logf("warn", "Port %d is used by another program; using port %d instead.", proxyPort, p[0])
			proxyPort = p[0]
		}
	}
	ports, err := core.FreePorts(2)
	if err != nil {
		return err
	}
	home := country
	if home == "" {
		home = servers[0].Country
	}
	c := &connection{
		country:     country,
		home:        home,
		pinned:      pinned,
		bypass:      set.Bypass,
		mode:        set.Mode,
		proxyAddr:   "127.0.0.1:" + strconv.Itoa(proxyPort),
		clashAddr:   "127.0.0.1:" + strconv.Itoa(ports[0]),
		probeAddr:   "127.0.0.1:" + strconv.Itoa(ports[1]),
		clashSecret: randomToken(),
		started:     time.Now(),
		wake:        make(chan struct{}, 1),
	}
	if private {
		c.proxyUser, c.proxyPass = randomToken(), randomToken()
	}
	opts := connOptions{
		listen: listen, port: proxyPort, user: c.proxyUser, pass: c.proxyPass, tun: set.Mode == "tun", bypass: set.Bypass, secureOnly: set.SecureOnly,
		blockAds: set.BlockAds, rulesDir: filepath.Join(e.dir, "rules"), clashAddr: c.clashAddr,
		clashSecret: c.clashSecret, probeAddr: c.probeAddr, exe: e.opt.ExeName, localDNS: e.dns(), mobile: e.opt.Mobile,
	}
	opts.warp = e.warpExit()
	c.warp = opts.warp != nil
	build := core.BuildOptions{
		Fragment:    set.Fragment == "on",
		FragmentFor: func(n *node.Node) bool { return fragFor[n] },
		OnLine:      c.watchLog,
		LineMbps:    e.net.lineMbps(),
	}
	if set.SpoofSNI != "" && e.opt.IsAdmin() {
		build.Spoof = set.SpoofSNI
	}
	ctx, cancel := context.WithTimeout(actx, 30*time.Second)
	defer cancel()
	run, err := e.rt.Run(ctx, "connect", nodes, build, func(s *core.Set) map[string]any {
		return connectConfig(s, opts)
	}, c.proxyAddr)
	if err != nil {
		return err
	}
	for _, n := range run.Rejected {
		if s := byNode[n]; s != nil {
			e.mu.Lock()
			s.Fails = 3
			e.mu.Unlock()
		}
	}
	c.running = run
	// The API that switches servers can come up a moment after the proxy
	// port does.
	if err := run.SingBox.WaitListening(ctx, c.clashAddr, 5*time.Second); err != nil {
		run.Stop()
		return err
	}
	e.mu.Lock()
	for i, n := range run.Set.Nodes {
		if s := byNode[n]; s != nil {
			m := &member{tag: run.Set.Tags[i], server: s, country: s.Country}
			if !n.UDPBased() && n.Proto != "warpplus" {
				m.endpoint = n.Endpoint()
			}
			c.members = append(c.members, m)
			c.servers = append(c.servers, s)
		}
	}
	e.mu.Unlock()
	// Test the whole group at once and start on the first server to answer;
	// the rest keep being tested and become the known-good backups.
	proxy := c.proxyURL()
	var r, bestR tester.Result
	var cur, best *member
	tried := map[*member]bool{}
	// A server that answers slowly is kept only when no other one in the
	// group does better: a first page after many seconds is not a
	// connection anyone can use.
	for try := 0; try < 3 && !(r.OK && r.Delay <= slowPath); try++ {
		var rest []*member
		for _, m := range c.members {
			if !tried[m] {
				rest = append(rest, m)
			}
		}
		m := e.race(actx, c, rest, 8*time.Second)
		if m == nil {
			break
		}
		tried[m] = true
		if err := c.use(actx, m); err != nil {
			run.Stop()
			return err
		}
		c.keep(actx, m)
		cur = m
		// Prove the whole path works before telling anyone it does.
		r = tester.Probe(actx, proxy, 12*time.Second)
		if !r.OK {
			e.noteResult(c, m, 0, false)
		}
		if r.Tampered && e.distrust(m.server.key64, m.server.Name) {
			c.mu.Lock()
			m.forged = true
			c.mu.Unlock()
		}
		if r.OK && (best == nil || r.Delay < bestR.Delay) {
			best, bestR = m, r
		}
	}
	if best != nil && best != cur {
		if err := c.use(actx, best); err == nil {
			c.keep(actx, best)
			r = bestR
		}
	}
	if !r.OK {
		run.Stop()
		if actx.Err() != nil && e.ctx.Err() == nil {
			return errStale // a newer connect or a disconnect took over
		}
		if len(tried) == 0 {
			return fmt.Errorf("%w: no server in the group answered", errServers)
		}
		return fmt.Errorf("%w: test through the new connection failed: %s", errServers, r.Err)
	}
	e.mu.Lock()
	stale := e.connGen != gen
	e.mu.Unlock()
	if stale {
		run.Stop()
		return errStale
	}
	c.exitIP, c.exitCC, c.delay, c.healthy = r.ExitIP, r.Country, int(r.Delay/time.Millisecond), true
	if set.Mode == "proxy" {
		bypass := []string{"localhost", "127.*", "10.*", "172.16.*", "172.17.*", "172.18.*", "172.19.*", "172.2*", "172.30.*", "172.31.*", "192.168.*", "169.254.*", "<local>"}
		if r, ok := findRegion(set.Bypass); ok {
			for _, s := range r.Suffixes {
				bypass = append(bypass, "*"+s)
			}
			for _, d := range r.Extra {
				bypass = append(bypass, d, "*."+d)
			}
		}
		switch err := e.setProxy(gen, c.proxyTarget(), bypass); {
		case errors.Is(err, errStale):
			run.Stop()
			return err
		case err != nil:
			e.logf("warn", "Could not set the system proxy: %v", err)
		default:
			c.sysProxy = true
		}
	} else {
		// Switched to TUN while connected: the system proxy still points at
		// the old connection's port, which is gone. The tunnel carries
		// everything now.
		e.clearProxy()
	}
	mctx, mcancel := context.WithCancel(e.ctx)
	c.cancel = mcancel
	e.mu.Lock()
	if e.connGen != gen {
		// The user disconnected while this connection was being made.
		e.mu.Unlock()
		e.stopConn(c, true)
		return errStale
	}
	e.conn = c
	e.mu.Unlock()
	e.setStatus(StatusConnected, connectedMessage(c))
	e.logf("info", "Connected to %s with %d servers in the group (latency %d ms).", exitName(c), len(c.members), c.delay)
	go e.monitor(mctx, c)
	if set.AllowLAN {
		go servePAC(mctx, c.proxyAddr)
	}
	// Sources blocked on the direct path (Telegram, GitHub) can now be
	// read through the VPN.
	e.triggerRefill()
	return nil
}

// exitName is the country traffic leaves from, as the user sees it.
func exitName(c *connection) string {
	c.mu.Lock()
	cc := c.exitCC
	c.mu.Unlock()
	if cc == "" {
		cc = c.country
	}
	return countryName(cc)
}

func connectedMessage(c *connection) string {
	return fmt.Sprintf("Connected — %s", exitName(c))
}

// Disconnect stops the VPN and restores system settings.
func (e *Engine) Disconnect() {
	e.disconnect(true)
}

// disconnect takes the connection and the VPN down; byUser also records
// that the user wants it off (see Settings.Connected).
func (e *Engine) disconnect(byUser bool) {
	e.mu.Lock()
	e.wantConnect = false
	e.connGen++
	e.cancelAttempt()
	c := e.conn
	wasOn := e.settings.Connected
	if byUser {
		e.settings.Connected = false
	}
	e.mu.Unlock()
	if byUser && wasOn {
		saveJSON(filepath.Join(e.dir, "settings.json"), e.Settings())
	}
	if c != nil {
		e.stopConn(c, true)
	}
	// Between a dropped connection and its replacement there is no
	// connection to stop, but the VPN (the system proxy on Windows) is
	// still up; it must go too.
	e.clearProxy()
	e.setStatus(StatusIdle, "")
}

// Resume connects again when the user left the VPN on, for Android's
// Always-on VPN starting the app by itself (after a restart, say). It
// reports whether a connection is on its way.
func (e *Engine) Resume() bool {
	e.mu.Lock()
	on, busy, target := e.settings.Connected, e.wantConnect, e.target
	e.mu.Unlock()
	if !on {
		return false
	}
	if !busy {
		go e.Connect(target)
	}
	return true
}

// setProxy points the system (on Android, the VPN) at addr unless the user
// disconnected since connection attempt gen began. proxyMu makes the check
// and the change one step, so a disconnect cannot slip in between.
func (e *Engine) setProxy(gen int, addr string, bypass []string) error {
	e.proxyMu.Lock()
	defer e.proxyMu.Unlock()
	e.mu.Lock()
	stale := e.connGen != gen
	e.mu.Unlock()
	if stale {
		return errStale
	}
	if err := e.opt.SysProxy.Set(addr, bypass); err != nil {
		return err
	}
	e.proxyOn = true
	// The login stays out of the file (proxyTarget).
	e.rememberProxySet(addr[strings.LastIndex(addr, "@")+1:])
	return nil
}

// rememberProxySet records the address the system proxy points at ("" when
// cleared), so the next start can undo it after a crash.
func (e *Engine) rememberProxySet(addr string) {
	path := filepath.Join(e.dir, "system-proxy")
	if addr == "" {
		os.Remove(path)
		return
	}
	os.WriteFile(path, []byte(addr), 0o644)
}

func (e *Engine) lastProxySet() string {
	b, _ := os.ReadFile(filepath.Join(e.dir, "system-proxy"))
	return strings.TrimSpace(string(b))
}

// clearProxy undoes setProxy, if it is in effect.
func (e *Engine) clearProxy() {
	e.proxyMu.Lock()
	defer e.proxyMu.Unlock()
	if e.proxyOn {
		e.opt.SysProxy.Clear()
		e.proxyOn = false
		e.rememberProxySet("")
	}
}

func (e *Engine) stopConn(c *connection, clearProxy bool) {
	if c.cancel != nil {
		c.cancel()
	}
	if c.sysProxy && clearProxy {
		e.clearProxy()
	}
	c.running.Stop()
	e.mu.Lock()
	if e.conn == c {
		e.conn = nil
	}
	e.mu.Unlock()
}

// privateProxy reports whether only the app itself uses the local proxy
// port: no system proxy points at it (on a phone the VPN reaches it through
// tun2socks, which can log in; Windows' system proxy cannot) and other
// devices may not use it. Then the port gets a login of its own for each
// connection, so other apps on the device cannot use the VPN through it or
// learn its exit address.
func privateProxy(mobile bool, set Settings) bool {
	return !set.AllowLAN && (mobile || set.Mode == "tun")
}

// proxyURL is the local proxy for the app's own HTTP clients.
func (c *connection) proxyURL() *url.URL {
	u := &url.URL{Scheme: "http", Host: c.proxyAddr}
	if c.proxyUser != "" {
		u.User = url.UserPassword(c.proxyUser, c.proxyPass)
	}
	return u
}

// proxyTarget is what the system proxy is pointed at: the address, with the
// login before it when there is one ("user:pass@host:port", which only the
// phone's tunnel is ever given).
func (c *connection) proxyTarget() string {
	if c.proxyUser == "" {
		return c.proxyAddr
	}
	return c.proxyUser + ":" + c.proxyPass + "@" + c.proxyAddr
}

type connOptions struct {
	listen      string
	port        int
	user, pass  string // the local proxy's login, when it has one
	tun         bool
	bypass      string
	secureOnly  bool
	blockAds    bool
	rulesDir    string
	clashAddr   string
	clashSecret string
	probeAddr   string
	exe         string
	localDNS    string
	mobile      bool
	warp        *warpID // offer WARP through the server in use (watchWarpExit)
}

// slowPath is the first-page delay through a new connection above which the
// next server in the group is tried before settling.
const slowPath = 3 * time.Second

// connectConfig builds the sing-box config for a live connection.
func connectConfig(s *core.Set, o connOptions) map[string]any {
	outbounds := append([]any{}, s.Outbounds...)
	outbounds = append(outbounds,
		// The engine picks the member in use and moves to a backup itself
		// (see failover.go), so a switch takes effect at once.
		map[string]any{
			"type": "selector", "tag": "proxy", "outbounds": s.Tags, "default": s.Tags[0],
			"interrupt_exist_connections": false,
		},
		map[string]any{
			"type": "selector", "tag": "sticky", "outbounds": s.Tags, "default": s.Tags[0],
			"interrupt_exist_connections": false,
		},
		map[string]any{"type": "direct", "tag": "direct"},
	)
	mixed := map[string]any{"type": "mixed", "tag": "mixed-in", "listen": o.listen, "listen_port": o.port}
	if o.user != "" {
		mixed["users"] = []any{map[string]any{"username": o.user, "password": o.pass}}
	}
	inbounds := []any{mixed}
	var rules []any
	if o.probeAddr != "" {
		// The engine measures any member's speed through this inbound by
		// naming it as the user, without moving the user's traffic.
		host, port, _ := net.SplitHostPort(o.probeAddr)
		p, _ := strconv.Atoi(port)
		users := make([]any, 0, len(s.Tags))
		for _, tag := range s.Tags {
			users = append(users, map[string]any{"username": tag, "password": o.clashSecret})
			rules = append(rules, map[string]any{"inbound": []string{"probe-in"}, "auth_user": []string{tag}, "outbound": tag})
		}
		rules = append(rules, map[string]any{"inbound": []string{"probe-in"}, "action": "reject"})
		inbounds = append(inbounds, map[string]any{"type": "mixed", "tag": "probe-in", "listen": host, "listen_port": p, "users": users})
	}
	if o.tun {
		inbounds = append(inbounds, map[string]any{
			"type": "tun", "tag": "tun-in", "interface_name": "Albatross",
			"address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"mtu":     9000, "auto_route": true, "strict_route": true, "stack": "mixed",
			// The local network never enters the tunnel, so casting to a
			// TV and finding printers keep working.
			"route_exclude_address": LANNets,
		})
	}
	var ruleSets []any
	rules = append(rules,
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
		map[string]any{"ip_is_private": true, "outbound": "direct"},
		map[string]any{"ip_cidr": LANNets, "outbound": "direct"},
	)
	if o.tun {
		// Our own app and the cores' test instances must not loop
		// through the tunnel.
		procs := []string{"sing-box.exe", "xray.exe", "warp-plus.exe", "sing-box", "xray"}
		if o.exe != "" {
			procs = append(procs, o.exe)
		}
		rules = append(rules, map[string]any{"process_name": procs, "outbound": "direct"})
	}
	if o.blockAds {
		ruleSets = append(ruleSets, localRuleSet("geosite-ads", o.rulesDir))
		// no_drop: sing-box otherwise drops, silently, after 50 rejects in
		// 30 seconds, which ordinary browsing reaches; then pages hang on
		// ad connections instead of giving up on them at once.
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-ads"}, "action": "reject", "no_drop": true})
	}
	dnsRules := []any{}
	if o.blockAds {
		// Apps learn at once that an ad server does not exist, instead of
		// waiting on a connection that is then refused, and the name is
		// not even looked up.
		dnsRules = append(dnsRules, map[string]any{"rule_set": []string{"geosite-ads"}, "action": "predefined", "rcode": "NXDOMAIN"})
	}
	if r, ok := findRegion(o.bypass); ok {
		// The learned list holds the region's sites the domain list misses
		// (learn.go); the core reloads it whenever the engine adds one.
		ruleSets = append(ruleSets, localRuleSet(r.geoSiteTag(), o.rulesDir), localRuleSet(r.geoIPTag(), o.rulesDir),
			map[string]any{"type": "local", "tag": r.learnedTag(), "format": "source", "path": r.learnedFile(o.rulesDir)})
		rules = append(rules, r.unlessShared(map[string]any{
			"domain_suffix": r.names(),
			"rule_set":      []string{r.geoSiteTag(), r.learnedTag(), r.geoIPTag()},
		}, map[string]any{"outbound": "direct"}))
		dnsRules = append(dnsRules, r.unlessShared(map[string]any{
			"domain_suffix": r.names(), "rule_set": []string{r.geoSiteTag(), r.learnedTag()},
		}, map[string]any{"action": "route", "server": "local"}))
	}
	if o.secureOnly {
		// Last among the rules that send traffic elsewhere, so local sites
		// and the local network (which never reach a server) are untouched.
		// HTTP is recognised by its content on any port, the rest by the
		// ports of plaintext protocols: FTP, telnet, SMTP, HTTP, POP3, IMAP.
		rules = append(rules,
			map[string]any{"protocol": []string{"http"}, "action": "reject"},
			map[string]any{"network": "tcp", "port": []int{21, 23, 25, 80, 110, 143}, "action": "reject"},
		)
	}
	// Sites that sign people out when their address changes keep one exit
	// for the whole connection.
	rules = append(rules, map[string]any{"domain_suffix": stickyDomains, "outbound": "sticky"})
	final := "proxy"
	if o.warp != nil {
		// Traffic starts on the server alone; watchWarpExit moves it onto
		// WARP once WARP answers through the server.
		outbounds = append(outbounds, map[string]any{
			"type": "selector", "tag": "exit", "outbounds": []string{"proxy", "warp-exit"}, "default": "proxy",
			"interrupt_exist_connections": false,
		})
		final = "exit"
	}
	route := map[string]any{
		"rules": rules,
		"final": final,
		// Never on Android: see tester.Tester.Mobile.
		"auto_detect_interface":   !o.mobile,
		"default_domain_resolver": "local",
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	remote := map[string]any{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"}
	dns := map[string]any{
		"servers":  []any{tester.DNSServer(o.localDNS), remote},
		"rules":    dnsRules,
		"final":    "remote",
		"strategy": "ipv4_only",
	}
	if r, ok := findRegion(o.bypass); ok && r.Subnet != "" {
		// Cloudflare's resolver never passes the subnet on; Google's does.
		// The subnet is a public block of the region, not this device's.
		remote["server"] = "8.8.8.8"
		dns["client_subnet"] = r.Subnet
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": false},
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
		"experimental": map[string]any{
			"clash_api": map[string]any{"external_controller": o.clashAddr, "secret": o.clashSecret},
		},
	}
	eps := append([]any{}, s.Endpoints...)
	if o.warp != nil {
		eps = append(eps, o.warp.endpoint())
	}
	if len(eps) > 0 {
		cfg["endpoints"] = eps
	}
	return cfg
}

// unlessShared is the rule doing action for names matching match, except
// names under the region's shared hosting (region.Shared).
func (r region) unlessShared(match, action map[string]any) map[string]any {
	rule := match
	if len(r.Shared) > 0 {
		rule = map[string]any{"type": "logical", "mode": "and", "rules": []any{
			match, map[string]any{"domain_suffix": r.Shared, "invert": true},
		}}
	}
	for k, v := range action {
		rule[k] = v
	}
	return rule
}

func localRuleSet(tag, dir string) map[string]any {
	return map[string]any{"type": "local", "tag": tag, "format": "binary", "path": filepath.Join(dir, tag+".srs")}
}

// ConnInfo describes the live connection for the UI.
type ConnInfo struct {
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	Flag        string `json:"flag"`
	Target      string `json:"target"`
	Server      string `json:"server"`
	Proto       string `json:"proto"`
	ExitIP      string `json:"exit_ip"`
	Delay       int    `json:"delay"`
	Since       int64  `json:"since"`
	Up          int64  `json:"up"`
	Down        int64  `json:"down"`
	UpRate      int64  `json:"up_rate"`
	DownRate    int64  `json:"down_rate"`
	Group       int    `json:"group"`
	Ready       int    `json:"ready"` // backups known to work right now
	Mode        string `json:"mode"`
	ProxyAddr   string `json:"proxy_addr"`
}

func (e *Engine) connInfo() *ConnInfo {
	e.mu.Lock()
	c := e.conn
	e.mu.Unlock()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	info := &ConnInfo{
		Country: c.exitCC, Target: c.country, ExitIP: c.exitIP, Delay: c.delay, Since: c.started.Unix(),
		Up: c.up, Down: c.down, UpRate: c.upRate, DownRate: c.dnRate, Group: len(c.members), Mode: c.mode,
		ProxyAddr: c.proxyAddr,
	}
	active := c.active
	for _, m := range c.members {
		if m.alive && m != active {
			info.Ready++
		}
	}
	c.mu.Unlock()
	if info.Country == "" {
		info.Country = c.country
	}
	info.CountryName = countryName(info.Country)
	info.Flag = geo.Flag(info.Country)
	if active != nil {
		info.Server, info.Proto = active.server.Name, active.server.Proto
	} else if len(c.servers) > 0 {
		info.Server, info.Proto = c.servers[0].Name, c.servers[0].Proto
	}
	return info
}

// LANNets are the local network's addresses, which never go through a
// server: private, link-local, multicast (mDNS, SSDP) and broadcast. The
// tunnel's own addresses stay inside: 172.19.0.0/16 is left out of
// 172.16.0.0/12, and IPv6 unique-local (fc00::/7) holds the tunnel's
// fdfe:dcba:9876::/126, which Android refuses to route around.
var LANNets = []string{
	"10.0.0.0/8", "172.16.0.0/15", "172.18.0.0/16", "172.20.0.0/14", "172.24.0.0/13",
	"192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
	"fe80::/10", "ff00::/8",
}

// stickyDomains are sites that sign people out, or ask them to prove who
// they are, when their address changes: banks, payments, exchanges,
// accounts and AI services.
var stickyDomains = []string{
	"accounts.google.com", "myaccount.google.com", "login.microsoftonline.com", "login.live.com",
	"appleid.apple.com", "icloud.com", "paypal.com", "wise.com", "revolut.com",
	"binance.com", "okx.com", "bybit.com", "kucoin.com", "coinbase.com", "kraken.com",
	"chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "gemini.google.com",
	"instagram.com", "facebook.com", "x.com", "twitter.com", "linkedin.com",
	"github.com", "steampowered.com", "steamcommunity.com", "web.telegram.org",
}
