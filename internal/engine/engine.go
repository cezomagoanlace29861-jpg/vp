// Package engine finds working servers continuously and keeps the user
// connected to the fastest ones in the country they picked.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/account"
	"github.com/cezomagoanlace29861-jpg/vp/internal/antiblock"
	"github.com/cezomagoanlace29861-jpg/vp/internal/core"
	"github.com/cezomagoanlace29861-jpg/vp/internal/geo"
	"github.com/cezomagoanlace29861-jpg/vp/internal/pool"
	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
	"github.com/cezomagoanlace29861-jpg/vp/internal/tester"
)

// Options configure a new engine.
type Options struct {
	DataDir  string // settings, caches and logs
	AppDirs  []string
	ExeName  string // this app's executable name, routed direct in TUN mode
	IsAdmin  func() bool
	SysProxy SystemProxy
	Version  string
	// Autostart turns launching at login on or off.
	Autostart func(enabled bool) error
	// Sources replaces the built-in source list (tests use it).
	Sources []sources.Source
	// LocalDNS is a resolver address the cores use for direct traffic and
	// server names on systems whose resolver they cannot ask themselves
	// (Android). Empty means the system's. SetLocalDNS changes it.
	LocalDNS string
	// AccountURLs replaces the build's account service addresses (tests use
	// it); nil means AccountURL.
	AccountURLs []string
	// Mobile tunes defaults and pacing for phones: lighter scanning, no
	// large lists by default, and "proxy" mode is the device-wide VPN.
	Mobile bool
	// InstallUpdate opens a downloaded installer of a newer version (see
	// GetUpdate); nil means the download page is opened instead.
	InstallUpdate func(path string) error
	// LANAddrs lists this device's addresses on its hotspot and Wi-Fi, for
	// systems where the engine cannot list them itself (Android 11 and
	// later refuse it); nil means the engine asks the system.
	LANAddrs func() []string
}

// SystemProxy sets and clears the OS proxy settings.
type SystemProxy interface {
	Set(addr string, bypass []string) error
	Clear() error
	// Owned reports whether the OS proxy currently points at addr, which
	// means a previous run crashed without cleaning up.
	Owned(addr string) bool
}

// Engine is the app's brain. All exported methods are safe to call from
// any goroutine.
type Engine struct {
	opt  Options
	dir  string
	bin  core.Binaries
	rt   *core.Runtime
	pool *pool.Pool

	acct *account.Client // nil when this build has no accounts
	// crowdURLs are the account service's addresses, which also collect
	// crowd stats (crowd.go); crowdAt is when tests were last reported.
	crowdURLs []string
	crowdAt   time.Time
	// httpsOK is when a server last passed a test with a genuine
	// certificate, which shows this device checks certificates correctly
	// (see distrust).
	httpsOK time.Time
	fetcher *sources.Fetcher
	// privateDirect makes direct calls to the account service (ech.go).
	privateDirect *http.Client
	warmPrivate   func(host string)
	tester        *tester.Tester
	resolver      *antiblock.Resolver
	cf            *antiblock.Scanner

	mu           sync.Mutex
	settings     Settings
	srcs         []sources.Source
	srcStats     []SourceStat
	srcStatsByID map[string]SourceStat
	srcIndex     map[string]int
	good         map[uint64]*Server
	net          netLearn // which kinds of server pass on this network
	conn         *connection
	proxyMu      sync.Mutex // serializes setProxy and clearProxy
	proxyOn      bool       // guarded by proxyMu
	status       string
	message      string
	target       string // country the user wants ("" = fastest anywhere)
	wantConnect  bool   // keep trying to connect until a server is found
	updating     bool   // GetUpdate is downloading
	connGen      int    // bumped by every user connect/disconnect; stale loops exit
	// startMu lets one connection attempt run at a time: two at once each
	// start a core on the proxy port and the second finds it taken.
	startMu     sync.Mutex
	attempt     context.CancelFunc // cancels the attempt in progress; under mu
	poolStats   [4]int             // total, untested, dead, ok; refreshed by statsLoop
	scan        scanState
	logs        []LogLine
	localDNS    string
	reg         regimeState   // the network's filtering regime (regime.go)
	regNet      string        // the network reg was probed on
	notice      string        // a message for the user that outlives status changes
	install     uint32        // this installation's random number (installNumber)
	helper      *core.Process // the "Help others" Snowflake proxy (help.go)
	update      *UpdateInfo   // a newer version, from update.json
	uiSeen      time.Time     // last time the UI asked for a snapshot
	countries   []CountryInfo // cached for countryCache
	countriesAt time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	refill chan struct{}
	wg     sync.WaitGroup
}

// LogLine is one entry of the activity log shown in the UI.
type LogLine struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Text  string    `json:"text"`
}

// Status values.
const (
	StatusIdle         = "idle"
	StatusSearching    = "searching"
	StatusConnecting   = "connecting"
	StatusConnected    = "connected"
	StatusReconnecting = "reconnecting"
)

// New prepares an engine; Start begins work.
func New(opt Options) (*Engine, error) {
	if err := os.MkdirAll(opt.DataDir, 0o755); err != nil {
		return nil, err
	}
	for _, d := range []string{"cache", "run", "rules"} {
		os.MkdirAll(filepath.Join(opt.DataDir, d), 0o755)
	}
	if opt.IsAdmin == nil {
		opt.IsAdmin = func() bool { return false }
	}
	if opt.SysProxy == nil {
		opt.SysProxy = noProxy{}
	}
	e := &Engine{
		opt:          opt,
		dir:          opt.DataDir,
		good:         map[uint64]*Server{},
		srcStatsByID: map[string]SourceStat{},
		status:       StatusIdle,
		wake:         make(chan struct{}, 1),
		refill:       make(chan struct{}, 1),
		localDNS:     opt.LocalDNS,
	}
	e.settings = loadSettings(e.dir, opt.Mobile)
	e.install = installNumber(e.dir)
	e.target = e.settings.Country
	e.bin = core.Locate(append(opt.AppDirs, e.dir)...)
	e.rt = &core.Runtime{Bin: e.bin, Dir: filepath.Join(e.dir, "run"), TorBridges: e.torBridges}
	p, err := pool.Open(filepath.Join(e.dir, "pool.dat"))
	if err != nil {
		return nil, err
	}
	e.pool = p
	direct := &http.Client{Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}}
	e.privateDirect, e.warmPrivate = newPrivateDirect(direct)
	e.fetcher = &sources.Fetcher{Direct: direct, Proxy: e.proxyClient, Private: e.privateDirect, CacheDir: filepath.Join(e.dir, "cache")}
	if urls := accountURLs(opt); len(urls) > 0 {
		e.acct = account.New(urls, account.SessionPath(e.dir), e.accountHTTP)
		e.crowdURLs = urls
	}
	e.tester = &tester.Tester{Runtime: e.rt}
	e.resolver = &antiblock.Resolver{Client: e.anyClient}
	e.cf = &antiblock.Scanner{}
	e.applyIntensity()
	if err := installRules(filepath.Join(e.dir, "rules")); err != nil {
		e.logf("warn", "Could not install the local-site lists: %v", err)
	}
	e.loadServers()
	e.net.load(e.dir)
	e.loadRegime()
	e.net.use(opt.LocalDNS)
	e.loadSourceStats()
	e.buildSources()
	return e, nil
}

// Start begins scanning (and connects if the user asked for that).
func (e *Engine) Start() {
	e.ctx, e.cancel = context.WithCancel(context.Background())
	// A crash left the system pointing at our dead proxy: at today's port,
	// or at the one in use then, which an automatic port change (another
	// program took the port) may have made different.
	for _, addr := range []string{e.proxyAddr(), e.lastProxySet()} {
		if addr != "" && e.opt.SysProxy.Owned(addr) {
			e.opt.SysProxy.Clear()
			break
		}
	}
	e.rememberProxySet("")
	if e.bin.SingBox == "" {
		e.logf("error", "Connection core not found; please reinstall the app.")
	}
	if e.bin.Xray == "" {
		e.logf("warn", "Secondary core not found; some connection types cannot be used.")
	}
	e.logf("info", "%d servers loaded from the last session.", len(e.good))
	e.loadUpdate()
	e.wg.Add(3)
	go e.refreshLoop()
	go e.scanLoop()
	go e.statsLoop()
	e.mu.Lock()
	auto := e.settings.AutoConnect
	e.mu.Unlock()
	if auto {
		go e.Connect(e.target)
	}
}

// Close disconnects, stops all work and saves state.
func (e *Engine) Close() {
	e.disconnect(false)
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	e.rt.StopTor()
	e.stopHelp()
	e.saveServers()
	e.saveSourceStats()
	e.saveStates()
	e.pool.Close()
}

func (e *Engine) logf(level, format string, args ...any) {
	line := LogLine{Time: time.Now(), Level: level, Text: Redact(fmt.Sprintf(format, args...))}
	e.mu.Lock()
	e.logs = append(e.logs, line)
	if len(e.logs) > 400 {
		e.logs = e.logs[len(e.logs)-400:]
	}
	e.mu.Unlock()
}

// Logs returns recent activity.
func (e *Engine) Logs() []LogLine {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]LogLine(nil), e.logs...)
}

func (e *Engine) setStatus(status, message string) {
	e.mu.Lock()
	e.status, e.message = status, message
	e.mu.Unlock()
}

func (e *Engine) poke() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// SetLocalDNS changes the resolver cores started from now on use for
// direct traffic (see Options.LocalDNS).
func (e *Engine) SetLocalDNS(addr string) {
	e.mu.Lock()
	moved := e.localDNS != addr
	e.localDNS = addr
	c := e.conn
	e.mu.Unlock()
	// Another network filters differently.
	e.net.use(addr)
	if moved {
		// Probe the new network's regime (the refresh loop sees it due).
		e.triggerRefill()
	}
	if moved && c != nil {
		// Connections made over the old network are gone; check the
		// server in use now so traffic recovers at once.
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
}

func (e *Engine) dns() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.localDNS
}

func (e *Engine) proxyAddr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return "127.0.0.1:" + strconv.Itoa(e.settings.ProxyPort)
}

// proxyClient returns an HTTP client through our own proxy while
// connected, so blocked sources (Telegram, GitHub) are fetched through it.
func (e *Engine) proxyClient() *http.Client {
	e.mu.Lock()
	c := e.conn
	e.mu.Unlock()
	if c == nil || !c.ready() {
		return nil
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:               http.ProxyURL(c.proxyURL()),
		TLSHandshakeTimeout: 20 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}}
}

// accountHTTP is the account service's client: through the VPN while it
// is up, otherwise direct without showing the service's name where possible.
func (e *Engine) accountHTTP() *http.Client {
	if c := e.proxyClient(); c != nil {
		return c
	}
	return e.privateDirect
}

func (e *Engine) anyClient() *http.Client {
	if c := e.proxyClient(); c != nil {
		return c
	}
	return e.fetcher.Direct
}

func (e *Engine) applyIntensity() {
	switch e.settings.Intensity {
	case "low":
		e.tester.Concurrency, e.tester.TCPConcurrency = 12, 48
	case "max":
		e.tester.Concurrency, e.tester.TCPConcurrency = 64, 256
	default:
		e.tester.Concurrency, e.tester.TCPConcurrency = 32, 128
	}
	e.tester.Timeout = 10 * time.Second
	e.tester.TCPTimeout = 3 * time.Second
}

// newTester returns a copy of the tester for one run, with the current
// intensity and resolver.
func (e *Engine) newTester() tester.Tester {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := *e.tester
	if e.wantConnect && e.conn == nil && e.settings.Intensity == "low" {
		// Finding a server is what the user is waiting for; a phone
		// saves its battery once connected, not before.
		t.Concurrency, t.TCPConcurrency = 32, 128
	}
	t.LocalDNS = e.localDNS
	t.Mobile = e.opt.Mobile
	t.LineMbps = e.net.lineMbps()
	return t
}

// Settings returns the current settings.
func (e *Engine) Settings() Settings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settings
}

// UpdateSettings applies new settings and reconnects when routing changed.
func (e *Engine) UpdateSettings(s Settings) error {
	e.mu.Lock()
	old := e.settings
	if s.ProxyPort <= 0 || s.ProxyPort > 65535 {
		s.ProxyPort = old.ProxyPort
	}
	s.Country = e.target
	s.Connected = old.Connected
	s.normalize()
	if e.opt.Mobile {
		s.Mode = "proxy"
	}
	e.settings = s
	e.countriesAt = time.Time{} // the list depends on the protocol
	e.applyIntensity()
	connected := e.conn != nil
	e.mu.Unlock()
	if s.Mode == "tun" && old.Mode != "tun" && !e.opt.IsAdmin() {
		e.mu.Lock()
		e.settings.Mode = old.Mode
		e.mu.Unlock()
		return ErrNeedAdmin
	}
	saveJSON(filepath.Join(e.dir, "settings.json"), e.Settings())
	if s.ShareStats && !old.ShareStats {
		go e.crowdLookup(e.ctx)
	}
	if old.HelpOthers != s.HelpOthers {
		go e.updateHelp()
	}
	if s.BlockAds && !old.BlockAds {
		// The ad list is only kept fresh while it is used.
		e.refreshRules()
	}
	if old.DeepSources != s.DeepSources || len(old.UserSources) != len(s.UserSources) || len(old.DisabledSources) != len(s.DisabledSources) {
		e.buildSources()
		e.triggerRefill()
	}
	routing := old.Mode != s.Mode || old.Bypass != s.Bypass || old.Protocol != s.Protocol || old.BlockAds != s.BlockAds || old.SecureOnly != s.SecureOnly ||
		old.ProxyPort != s.ProxyPort || old.AllowLAN != s.AllowLAN || old.Fragment != s.Fragment || old.AllowPlain != s.AllowPlain
	if connected && routing {
		go e.Connect(e.target)
	}
	if e.opt.Autostart != nil && old.StartWithSystem != s.StartWithSystem {
		if err := e.opt.Autostart(s.StartWithSystem); err != nil {
			e.logf("warn", "Could not change the start-with-system setting: %v", err)
		}
	}
	return nil
}

// ErrNeedAdmin means TUN mode needs the app to run as administrator.
var ErrNeedAdmin = fmt.Errorf("need administrator")

func (e *Engine) triggerRefill() {
	select {
	case e.refill <- struct{}{}:
	default:
	}
}

// installNumber returns this installation's random number, made once and
// kept in the data folder. It never leaves the device.
func installNumber(dir string) uint32 {
	path := filepath.Join(dir, "install.id")
	if b, err := os.ReadFile(path); err == nil && len(b) == 8 {
		if v, err := strconv.ParseUint(string(b), 16, 32); err == nil {
			return uint32(v)
		}
	}
	var b [4]byte
	rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:])
	os.WriteFile(path, []byte(fmt.Sprintf("%08x", v)), 0o644)
	return v
}

// buildSources rebuilds the source list from built-ins and settings.
func (e *Engine) buildSources() {
	e.mu.Lock()
	defer e.mu.Unlock()
	disabled := map[string]bool{}
	for _, id := range e.settings.DisabledSources {
		disabled[id] = true
	}
	var list []sources.Source
	builtin := e.opt.Sources
	if builtin == nil {
		builtin = append(sources.Central(e.install), sources.Builtin()...)
	}
	for _, s := range builtin {
		if s.Tier == sources.TierDeep && !s.Central && !e.settings.DeepSources {
			s.Enabled = false
		}
		if disabled[s.ID] {
			s.Enabled = false
		}
		list = append(list, s)
	}
	list = append(list, e.settings.UserSources...)
	// Keep indexes stable for sources that already exist: the pool stores
	// source indexes.
	if e.srcIndex == nil {
		e.srcIndex = map[string]int{}
	}
	byID := map[string]sources.Source{}
	for _, s := range list {
		byID[s.ID] = s
	}
	for i := range e.srcs {
		if s, ok := byID[e.srcs[i].ID]; ok {
			e.srcs[i] = s
			delete(byID, s.ID)
		} else {
			e.srcs[i].Enabled = false
		}
	}
	for _, s := range list {
		if _, isNew := byID[s.ID]; !isNew {
			continue
		}
		e.srcIndex[s.ID] = len(e.srcs)
		e.srcs = append(e.srcs, s)
		e.srcStats = append(e.srcStats, e.srcStatsByID[s.ID])
	}
}

// CountryInfo summarizes servers in one country.
type CountryInfo struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Flag      string `json:"flag"`
	Servers   int    `json:"servers"`
	BestDelay int    `json:"best_delay"`
}

// Countries lists the countries that have usable servers for the chosen
// protocol, the best supplied first.
func (e *Engine) Countries() []CountryInfo {
	now := time.Now()
	e.mu.Lock()
	if now.Sub(e.countriesAt) < countryCache {
		out := e.countries
		e.mu.Unlock()
		return out
	}
	m := map[string]*CountryInfo{}
	for _, s := range e.good {
		if s.Country == "" || s.Country == "IR" || !s.usable(now) || !s.matches(e.settings.Protocol) {
			continue
		}
		ci, ok := m[s.Country]
		if !ok {
			c, _ := geo.Lookup(s.Country)
			ci = &CountryInfo{Code: s.Country, Name: c.EN, Flag: geo.Flag(s.Country)}
			m[s.Country] = ci
		}
		ci.Servers++
		if ci.BestDelay == 0 || s.Delay < ci.BestDelay {
			ci.BestDelay = s.Delay
		}
	}
	e.mu.Unlock()
	out := make([]CountryInfo, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Servers != out[j].Servers {
			return out[i].Servers > out[j].Servers
		}
		return out[i].Code < out[j].Code
	})
	e.mu.Lock()
	e.countries, e.countriesAt = out, now
	e.mu.Unlock()
	return out
}

// countryCache is how long the country list is reused. The UI asks every
// second and the list changes slowly.
const countryCache = 3 * time.Second

// ServerInfo is a working server as shown in the UI.
type ServerInfo struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Proto     string `json:"proto"`
	Transport string `json:"transport"`
	Security  string `json:"security"`
	Country   string `json:"country"`
	Delay     int    `json:"delay"`
	AgeSec    int    `json:"age_sec"`
	Fragment  bool   `json:"fragment"`
	Plain     bool   `json:"plain"`
	Active    bool   `json:"active"`
	Link      string `json:"link"`
}

// Servers lists usable servers in a country ("" = all), best first.
func (e *Engine) Servers(country string, limit int) []ServerInfo {
	now := time.Now()
	e.mu.Lock()
	active := map[string]bool{}
	if e.conn != nil {
		active[e.conn.activeKey()] = true
	}
	var list []*Server
	for _, s := range e.good {
		if !s.usable(now) || (country != "" && s.Country != country) {
			continue
		}
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].rank(now) < list[j].rank(now) })
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	out := make([]ServerInfo, 0, len(list))
	for _, s := range list {
		out = append(out, ServerInfo{
			Key: s.Key, Name: s.Name, Proto: s.Proto, Transport: s.Transport, Security: s.Security,
			Country: s.Country, Delay: s.Delay, AgeSec: int(now.Sub(s.LastOK).Seconds()),
			Fragment: s.Fragment, Plain: s.Plain, Active: active[s.Key], Link: s.Link,
		})
	}
	e.mu.Unlock()
	return out
}
