package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/node"
)

// Set is a group of nodes laid out for the cores. Nodes Xray must run are
// served by an Xray sidecar on local SOCKS ports and appear in sing-box as
// plain SOCKS outbounds, so sing-box always fronts every node.
type Set struct {
	Nodes     []*node.Node
	Tags      []string // sing-box tag per node
	Outbounds []any    // sing-box outbounds, node order; configs must keep them first
	Endpoints []any    // sing-box endpoints, node order; configs must keep them first
	outIdx    []int    // node index per entry in Outbounds
	epIdx     []int    // node index per entry in Endpoints
	xrayIdx   []int    // node index per Xray node
	Xray      map[string]any
	XrayProbe string
}

// BuildOptions tune generated outbounds.
type BuildOptions struct {
	// Fragment fragments the TLS ClientHello of every TLS node.
	Fragment bool
	// FragmentFor, when set, picks fragmentation per node instead.
	FragmentFor func(*node.Node) bool
	// Spoof is the allowed SNI for forged ClientHellos ("" = off).
	Spoof string
	// LineMbps is the measured line speed (see node.SingBoxOptions).
	LineMbps int
	// OnLine, when set, receives every line the cores of this run print.
	OnLine func(core, line string)
	// warpPorts maps warp-plus nodes to the SOCKS port their process
	// listens on; nodes without a port are left out.
	warpPorts map[*node.Node]int
}

// BuildSet lays nodes out for sing-box and, when needed, Xray.
func BuildSet(nodes []*node.Node, o BuildOptions) (*Set, error) {
	s := &Set{Nodes: nodes, Tags: make([]string, len(nodes))}
	var xrayNodes, wpNodes []int
	for i, n := range nodes {
		tag := "n" + strconv.Itoa(i)
		s.Tags[i] = tag
		switch n.Engine() {
		case node.EngineXray:
			xrayNodes = append(xrayNodes, i)
			continue
		case node.EngineWarpPlus:
			wpNodes = append(wpNodes, i)
			continue
		}
		frag := o.Fragment
		if o.FragmentFor != nil {
			frag = frag || o.FragmentFor(n)
		}
		obj, ep := n.SingBox(tag, node.SingBoxOptions{Fragment: frag, Spoof: o.Spoof, LineMbps: o.LineMbps})
		if ep {
			s.Endpoints = append(s.Endpoints, obj)
			s.epIdx = append(s.epIdx, i)
		} else {
			if !n.UDPBased() {
				// Mobile networks drop idle TCP connections after a minute or
				// two; keepalives this often keep quiet connections (chats,
				// notifications) open.
				obj["tcp_keep_alive"] = "30s"
				obj["tcp_keep_alive_interval"] = "15s"
			}
			s.Outbounds = append(s.Outbounds, obj)
			s.outIdx = append(s.outIdx, i)
		}
	}
	for _, i := range wpNodes {
		port := o.warpPorts[nodes[i]]
		if port == 0 {
			port = 9 // discard: no process serves this node
		}
		s.Outbounds = append(s.Outbounds, map[string]any{
			"type": "socks", "tag": s.Tags[i], "server": "127.0.0.1", "server_port": port, "version": "5",
		})
		s.outIdx = append(s.outIdx, i)
	}
	if len(xrayNodes) == 0 {
		return s, nil
	}
	ports, err := FreePorts(len(xrayNodes))
	if err != nil {
		return nil, err
	}
	var inbounds, outbounds, rules []any
	// The ports Xray takes traffic on lead straight to the servers, so they
	// need a login like the app's own proxy: any program on the device
	// could otherwise use a server through them and learn its address.
	secret := make([]byte, 16)
	rand.Read(secret)
	pass := hex.EncodeToString(secret)
	for k, i := range xrayNodes {
		n := nodes[i]
		xtag := "x" + strconv.Itoa(i)
		inTag := "in" + strconv.Itoa(i)
		inbounds = append(inbounds, map[string]any{
			"tag": inTag, "listen": "127.0.0.1", "port": ports[k], "protocol": "socks",
			"settings": map[string]any{"udp": true, "auth": "password", "accounts": []any{map[string]any{"user": inTag, "pass": pass}}},
		})
		for _, ob := range n.Xray(xtag) {
			outbounds = append(outbounds, ob)
		}
		rules = append(rules, map[string]any{"inboundTag": []string{inTag}, "outboundTag": xtag})
		s.Outbounds = append(s.Outbounds, map[string]any{
			"type": "socks", "tag": s.Tags[i], "server": "127.0.0.1", "server_port": ports[k], "version": "5",
			"username": inTag, "password": pass,
		})
		s.outIdx = append(s.outIdx, i)
		s.xrayIdx = append(s.xrayIdx, i)
	}
	outbounds = append(outbounds, map[string]any{"tag": "block", "protocol": "blackhole"})
	s.Xray = map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	s.XrayProbe = "127.0.0.1:" + strconv.Itoa(ports[0])
	return s, nil
}

// Running is a started set of cores.
type Running struct {
	Set      *Set
	SingBox  *Process
	Xray     *Process
	WarpPlus []*Process
	Rejected []*node.Node // configs a core refused
	Failed   []*node.Node // warp-plus methods that could not connect
	release  func()       // lets go of the shared tor
}

// Stop stops every core.
func (r *Running) Stop() {
	if r == nil {
		return
	}
	r.SingBox.Stop()
	if r.Xray != nil {
		r.Xray.Stop()
	}
	for _, p := range r.WarpPlus {
		p.Stop()
	}
	if r.release != nil {
		r.release()
		r.release = nil
	}
}

// Alive reports whether every core is still running.
func (r *Running) Alive() bool {
	if r == nil || r.SingBox == nil || r.SingBox.Exited() {
		return false
	}
	return r.Xray == nil || !r.Xray.Exited()
}

// Runtime starts sets on the installed cores.
type Runtime struct {
	Bin    Binaries
	Dir    string // where configs are written
	OnLine func(core, line string)
	// TorBridges, when set, returns extra bridge lines for tor as a JSON
	// map of transport to lines.
	TorBridges func() []byte

	tor torProc
}

var (
	sbIndexRe   = regexp.MustCompile(`(outbounds?|endpoints?)\[(\d+)\]`)
	xrayIndexRe = regexp.MustCompile(`outbound config with tag x(\d+)`)
)

// ConfigFunc builds a full sing-box config around a set. It must keep the
// set's Outbounds and Endpoints at the front of their arrays so startup
// errors can be traced back to nodes.
type ConfigFunc func(s *Set) map[string]any

// Run starts the cores for nodes. Nodes a core rejects are dropped and the
// rest are started again, so one broken server never blocks the others.
func (r *Runtime) Run(ctx context.Context, name string, nodes []*node.Node, o BuildOptions, cfg ConfigFunc, probe string) (*Running, error) {
	var rejected []*node.Node
	nodes = append([]*node.Node(nil), nodes...)
	wp, ports, failed, nodes, release := r.startWarpPlus(ctx, nodes)
	o.warpPorts = ports
	stopWP := func() {
		for _, p := range wp {
			p.Stop()
		}
		if release != nil {
			release()
		}
	}
	for attempt := 0; attempt < 200; attempt++ {
		if len(nodes) == 0 {
			stopWP()
			return &Running{Rejected: rejected, Failed: failed}, fmt.Errorf("no usable servers")
		}
		if err := ctx.Err(); err != nil {
			stopWP()
			return nil, err
		}
		set, err := BuildSet(nodes, o)
		if err != nil {
			stopWP()
			return nil, err
		}
		var xr *Process
		if set.Xray != nil {
			if r.Bin.Xray == "" {
				// Without Xray those nodes cannot run at all.
				nodes, rejected = dropIdx(nodes, set.xrayIdx, rejected)
				continue
			}
			xr, err = r.start(ctx, "xray", name, set.Xray, set.XrayProbe, o.OnLine, func(path string) []string {
				return []string{"run", "-c", path}
			})
			if err != nil {
				if ee, ok := IsExit(err); ok {
					if m := xrayIndexRe.FindStringSubmatch(ee.Output); m != nil {
						i, _ := strconv.Atoi(m[1])
						nodes, rejected = dropIdx(nodes, []int{i}, rejected)
					} else {
						nodes, rejected = dropIdx(nodes, set.xrayIdx, rejected)
					}
					continue
				}
				stopWP()
				return nil, err
			}
		}
		sb, err := r.start(ctx, "sing-box", name, cfg(set), probe, o.OnLine, func(path string) []string {
			return []string{"run", "-c", path, "--disable-color"}
		})
		if err != nil {
			if xr != nil {
				xr.Stop()
			}
			if ee, ok := IsExit(err); ok {
				if m := sbIndexRe.FindStringSubmatch(ee.Output); m != nil {
					k, _ := strconv.Atoi(m[2])
					var idx []int
					if m[1][0] == 'o' {
						idx = set.outIdx
					} else {
						idx = set.epIdx
					}
					if k < len(idx) {
						nodes, rejected = dropIdx(nodes, []int{idx[k]}, rejected)
						continue
					}
				}
			}
			stopWP()
			return nil, err
		}
		return &Running{Set: set, SingBox: sb, Xray: xr, WarpPlus: wp, Rejected: rejected, Failed: failed, release: release}, nil
	}
	stopWP()
	return nil, fmt.Errorf("too many rejected servers")
}

// startWarpPlus launches one warp-plus process per warp-plus node, in
// parallel, and waits for each to open its SOCKS port. warp-plus only
// listens once its tunnel is up, so this also tests the method. Tor nodes
// share one tor process instead; release lets go of it.
func (r *Runtime) startWarpPlus(ctx context.Context, nodes []*node.Node) ([]*Process, map[*node.Node]int, []*node.Node, []*node.Node, func()) {
	var idx []int
	for i, n := range nodes {
		if n.Engine() == node.EngineWarpPlus {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return nil, nil, nil, nodes, nil
	}
	procs := make([]*Process, len(nodes))
	torPorts := make([]int, len(nodes))
	ports, err := FreePorts(len(idx))
	if err == nil {
		var wg sync.WaitGroup
		for k, i := range idx {
			n := nodes[i]
			if n.WPMode == "tor" {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					if port, err := r.acquireTor(ctx); err == nil {
						torPorts[i] = port
					}
				}(i)
				continue
			}
			if r.Bin.WarpPlus == "" {
				continue
			}
			wg.Add(1)
			go func(i, port int) {
				defer wg.Done()
				bind := "127.0.0.1:" + strconv.Itoa(port)
				cache := filepath.Join(r.Dir, "warp-plus", n.WPMode+"-"+strings.ToLower(n.WPCountry))
				os.MkdirAll(cache, 0o755)
				var onLine func(string)
				if r.OnLine != nil {
					onLine = func(l string) { r.OnLine("warp-plus", l) }
				}
				p, err := Start("warp-plus", r.Bin.WarpPlus, n.WarpPlusArgs(bind, cache), nil, onLine)
				if err != nil {
					return
				}
				if err := p.WaitListening(ctx, bind, 75*time.Second); err != nil {
					p.Stop()
					return
				}
				procs[i] = p
			}(i, ports[k])
		}
		wg.Wait()
	}
	bound := map[*node.Node]int{}
	var keep, failed []*node.Node
	var running []*Process
	held := 0
	k := 0
	for i, n := range nodes {
		if n.Engine() != node.EngineWarpPlus {
			keep = append(keep, n)
			continue
		}
		switch {
		case torPorts[i] != 0:
			keep = append(keep, n)
			bound[n] = torPorts[i]
			held++
		case procs[i] != nil:
			keep = append(keep, n)
			running = append(running, procs[i])
			bound[n] = ports[k]
		default:
			failed = append(failed, n)
		}
		k++
	}
	var release func()
	if held > 0 {
		release = func() {
			for range held {
				r.releaseTor()
			}
		}
	}
	return running, bound, failed, keep, release
}

func dropIdx(nodes []*node.Node, idx []int, rejected []*node.Node) ([]*node.Node, []*node.Node) {
	drop := map[int]bool{}
	for _, i := range idx {
		drop[i] = true
	}
	var keep []*node.Node
	for i, n := range nodes {
		if drop[i] {
			rejected = append(rejected, n)
		} else {
			keep = append(keep, n)
		}
	}
	return keep, rejected
}

func (r *Runtime) start(ctx context.Context, coreName, name string, cfg map[string]any, probe string, runLine func(core, line string), args func(string) []string) (*Process, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(r.Dir, name+"-"+coreName+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	bin := r.Bin.SingBox
	if coreName == "xray" {
		bin = r.Bin.Xray
	}
	var onLine func(string)
	if r.OnLine != nil || runLine != nil {
		onLine = func(l string) {
			if r.OnLine != nil {
				r.OnLine(coreName, l)
			}
			if runLine != nil {
				runLine(coreName, l)
			}
		}
	}
	var env []string
	if coreName == "xray" {
		env = []string{"XRAY_LOCATION_ASSET=" + filepath.Dir(bin)}
	}
	p, err := Start(coreName, bin, args(path), env, onLine)
	if err != nil {
		return nil, err
	}
	if err := p.WaitListening(ctx, probe, 15*time.Second); err != nil {
		p.Stop()
		return nil, err
	}
	return p, nil
}
