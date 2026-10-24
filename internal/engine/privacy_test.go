package engine

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/cezomagoanlace29861-jpg/vp/internal/core"
	"github.com/cezomagoanlace29861-jpg/vp/internal/node"
	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
)

// The local proxy gets a login wherever only the app itself uses it, and
// stays open where Windows' system proxy (which cannot log in) or other
// devices use it.
func TestPrivateProxy(t *testing.T) {
	for _, c := range []struct {
		mobile bool
		set    Settings
		want   bool
	}{
		{true, Settings{Mode: "proxy"}, true},
		{true, Settings{Mode: "proxy", AllowLAN: true}, false},
		{false, Settings{Mode: "proxy"}, false},
		{false, Settings{Mode: "tun"}, true},
		{false, Settings{Mode: "tun", AllowLAN: true}, false},
	} {
		if got := privateProxy(c.mobile, c.set); got != c.want {
			t.Errorf("mobile %v, %+v: got %v", c.mobile, c.set, got)
		}
	}
}

func TestProxyLogin(t *testing.T) {
	n, err := node.ParseLink("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=tcp#x")
	if err != nil {
		t.Fatal(err)
	}
	set, err := core.BuildSet([]*node.Node{n}, core.BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mixed := func(o connOptions) map[string]any {
		o.listen, o.port, o.rulesDir, o.clashAddr = "127.0.0.1", 10808, t.TempDir(), "127.0.0.1:9090"
		b, _ := json.Marshal(connectConfig(set, o)["inbounds"])
		var in []map[string]any
		json.Unmarshal(b, &in)
		for _, i := range in {
			if i["tag"] == "mixed-in" {
				return i
			}
		}
		t.Fatal("no mixed-in inbound")
		return nil
	}
	if _, ok := mixed(connOptions{})["users"]; ok {
		t.Fatal("open proxy got a login")
	}
	users, _ := mixed(connOptions{user: "u1", pass: "p1"})["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["username"] != "u1" || users[0].(map[string]any)["password"] != "p1" {
		t.Fatalf("users = %v", users)
	}

	c := &connection{proxyAddr: "127.0.0.1:40123"}
	if c.proxyTarget() != "127.0.0.1:40123" || c.proxyURL().User != nil {
		t.Fatalf("open: %s %s", c.proxyTarget(), c.proxyURL())
	}
	c.proxyUser, c.proxyPass = "u1", "p1"
	if c.proxyTarget() != "u1:p1@127.0.0.1:40123" {
		t.Fatalf("target = %s", c.proxyTarget())
	}
	if u := c.proxyURL(); u.User.Username() != "u1" || u.Host != "127.0.0.1:40123" {
		t.Fatalf("url = %s", u)
	}

	// The login never reaches the file read after a crash.
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}, SysProxy: &fakeProxy{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.setProxy(e.connGen, c.proxyTarget(), nil); err != nil {
		t.Fatal(err)
	}
	if e.lastProxySet() != "127.0.0.1:40123" {
		t.Fatalf("remembered %q", e.lastProxySet())
	}
}

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"Connection attempt failed: dial tcp 203.0.113.7:443: i/o timeout":              "Connection attempt failed: dial tcp [address]: i/o timeout",
		"lookup accounts.albatrossvpn.online: no such host":                             "lookup [host]: no such host",
		"lookup site.xn--mgba3a4f16a: no such host":                                     "lookup [host]: no such host",
		`Get "https://accounts.albatrossvpn.online/api/v1/login": EOF`:                  `Get "[link]": EOF`,
		"vless://b831381d@example.com:443?security=tls#name failed":                     "[link] failed",
		"dial [2001:db8::1]:443 and fe80::1 and digikala.ir:443 and xn--mgba3a4f16a.ir": "dial [address] and [address] and [host] and [host]",
		"sing-box.exe exited; geosite-ir.srs is old; version 0.3.4 at 12:30:45":         "sing-box.exe exited; geosite-ir.srs is old; version 0.3.4 at 12:30:45",
		"Connected to Germany with 3 servers in the group (latency 120 ms).":            "Connected to Germany with 3 servers in the group (latency 120 ms).",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", in, got, want)
		}
	}

	// The engine's log and the app's log file both go through it.
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.pool.Close()
	e.logf("warn", "Connection attempt failed: %v", errors.New("dial tcp 198.51.100.2:8443 via cdn.example.net"))
	if l := e.Logs(); len(l) == 0 || strings.Contains(l[len(l)-1].Text, "198.51") || strings.Contains(l[len(l)-1].Text, "example") {
		t.Fatalf("log kept an address: %v", l)
	}
	var b strings.Builder
	log := RedactWriter(&b)
	if n, err := log.Write([]byte("http: TLS handshake error from 192.0.2.1:5000: EOF\n")); err != nil || n == 0 || strings.Contains(b.String(), "192.0.2.1") {
		t.Fatalf("file got %q", b.String())
	}
}

// An HTTPS record's ECH key and address hints are read, and a key the
// server refuses (or a network that blocks ECH) still ends in a working
// connection, without the system's resolver.
func TestPrivateDirect(t *testing.T) {
	name := dnsmessage.MustNewName("accounts.example.com.")
	rr := &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName(".")}}
	rr.SetParam(dnsmessage.SVCParamIPv4Hint, []byte{127, 0, 0, 1})
	rr.SetParam(dnsmessage.SVCParamECH, []byte{0, 3, 1, 2, 3})
	rr.SetParam(dnsmessage.SVCParamIPv6Hint, netip.MustParseAddr("2001:db8::1").AsSlice())
	m := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: name}},
			{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}, Body: rr},
		},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := parseHTTPS(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.ech, []byte{0, 3, 1, 2, 3}) || len(rec.addrs) != 2 || rec.addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("record = %+v", rec)
	}
	empty := dnsmessage.Message{Header: dnsmessage.Header{Response: true}}
	if _, err := parseHTTPS(must(empty.Pack())); err == nil {
		t.Fatal("an empty answer gave a record")
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	roots := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	// The test certificate is for example.com; the name never resolves, so
	// only the hint reaches the server.
	rec.addrs = rec.addrs[:1]
	c, refused, err := dialPrivate(context.Background(), "tcp", "example.com", port, rec, roots)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !refused {
		t.Fatal("a broken ECH key was not reported")
	}
}

// echKey returns an ECH key for a test server and the list a client uses.
func echKey(t *testing.T) (tls.EncryptedClientHelloKey, []byte) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey().Bytes()
	c := []byte{1}                               // config id
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, 4)
	c = binary.BigEndian.AppendUint16(c, 0x0001) // HKDF-SHA256
	c = binary.BigEndian.AppendUint16(c, 0x0001) // AES-128-GCM
	c = append(c, 0, byte(len("example.com")))
	c = append(c, "example.com"...)
	c = binary.BigEndian.AppendUint16(c, 0) // no extensions
	cfg := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(c)))
	cfg = append(cfg, c...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(cfg)))
	return tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: k.Bytes(), SendAsRetry: true}, append(list, cfg...)
}

// stallListener holds the first stall connections without answering, as a
// network does that drops what it does not like.
type stallListener struct {
	net.Listener
	stall atomic.Int32
	mu    sync.Mutex
	held  []net.Conn
}

func (l *stallListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil || l.stall.Add(-1) < 0 {
			return c, err
		}
		l.mu.Lock()
		l.held = append(l.held, c)
		l.mu.Unlock()
	}
}

func (l *stallListener) Close() error {
	l.mu.Lock()
	for _, c := range l.held {
		c.Close()
	}
	l.mu.Unlock()
	return l.Listener.Close()
}

// echServer serves "ech" to calls that used ECH and "plain" to others.
func echServer(t *testing.T, key tls.EncryptedClientHelloKey) (*httptest.Server, *stallListener) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ECHAccepted {
			io.WriteString(w, "ech")
			return
		}
		io.WriteString(w, "plain")
	}))
	ln := &stallListener{Listener: ts.Listener}
	ts.Listener = ln
	ts.TLS = &tls.Config{EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, ln
}

// A blocked ECH handshake hangs; the call still gets through in time, and
// never outlives its deadline.
func TestPrivateDial(t *testing.T) {
	key, list := echKey(t)
	ts, ln := echServer(t, key)
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	roots := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	rec := httpsRecord{ech: list, addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	defer func(e, p time.Duration) { echWait, plainWait = e, p }(echWait, plainWait)
	echWait, plainWait = 300*time.Millisecond, time.Second

	c, refused, err := dialPrivate(context.Background(), "tcp", "example.com", port, rec, roots)
	if err != nil {
		t.Fatal(err)
	}
	if !c.(*tls.Conn).ConnectionState().ECHAccepted || refused {
		t.Fatal("ECH was not used")
	}
	c.Close()

	ln.stall.Store(1)
	start := time.Now()
	c, refused, err = dialPrivate(context.Background(), "tcp", "example.com", port, rec, roots)
	if err != nil {
		t.Fatal(err)
	}
	if c.(*tls.Conn).ConnectionState().ECHAccepted || !refused {
		t.Fatal("the blocked ECH handshake was not given up")
	}
	c.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("falling back took %v", d)
	}

	ln.stall.Store(100)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start = time.Now()
	if _, _, err := dialPrivate(ctx, "tcp", "example.com", port, rec, roots); err == nil {
		t.Fatal("a dial to a server that never answers worked")
	}
	if d := time.Since(start); d > 700*time.Millisecond {
		t.Fatalf("the dial outlived its deadline by %v", d-400*time.Millisecond)
	}
}

// Names are looked up once however many calls wait for them, and a key the
// network refused is left alone until the name is looked up again.
func TestHTTPSCache(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	rr := &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName(".")}}
	rr.SetParam(dnsmessage.SVCParamECH, []byte{0, 3, 1, 2, 3})
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}, Body: rr},
	}}
	answer := must(m.Pack())
	var asked atomic.Int32
	doh := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		asked.Add(1)
		time.Sleep(50 * time.Millisecond)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(answer)), Request: r}, nil
	})}
	cache := &httpsCache{doh: doh, recs: map[string]httpsRecord{}, busy: map[string]chan struct{}{}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if r := cache.get(context.Background(), "example.com"); r.ech == nil {
				t.Error("no key")
			}
		})
	}
	wg.Wait()
	if n := asked.Load(); n != int32(len(dohWire)) {
		t.Fatalf("%d queries for one name", n)
	}
	cache.forgetECH("example.com")
	if r := cache.get(context.Background(), "example.com"); r.ech != nil || asked.Load() != int32(len(dohWire)) {
		t.Fatal("a refused key was used again")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
