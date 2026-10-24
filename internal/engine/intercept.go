package engine

import (
	"context"
	"net/url"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/pool"
	"github.com/cezomagoanlace29861-jpg/vp/internal/tester"
)

// Servers that read HTTPS. Whoever runs a free server can try to decrypt
// the traffic it carries by showing a certificate of its own instead of the
// site's. Browsers refuse it, but the user may click through a warning, and
// apps that check less carefully may accept it. Every test already checks
// the certificate; a server caught forging one is dropped for good, and the
// server in use and the backups are also checked against well-known sites
// such a server is likely to single out.

// interceptEvery is how often the server in use is checked.
const interceptEvery = 20 * time.Minute

// distrust drops a server that showed a forged certificate: it is never
// tested or used again. It does so only when another server passed a test
// with a genuine certificate within the hour, which shows the forgery is
// the server's and not this device's (a security program that inspects
// HTTPS, or a missing root certificate, would fail every server alike).
// It reports whether the server was dropped.
func (e *Engine) distrust(key uint64, name string) bool {
	e.mu.Lock()
	sure := !e.httpsOK.IsZero() && time.Since(e.httpsOK) < time.Hour
	if sure {
		delete(e.good, key)
	}
	e.mu.Unlock()
	if !sure {
		return false
	}
	e.pool.Update(key, func(p *pool.Entry) { p.State = pool.StateRejected; p.LastTest = pool.Minutes(time.Now()) })
	e.logf("warn", "A server showed a forged certificate, so it tries to read HTTPS traffic. It will not be used again.")
	return true
}

// memberProxy is the proxy address that sends traffic through m alone.
func (c *connection) memberProxy(m *member) *url.URL {
	return &url.URL{Scheme: "http", User: url.UserPassword(m.tag, c.clashSecret), Host: c.probeAddr}
}

// checkIntercept checks m against one well-known site and drops it when it
// forges the certificate. It reports whether m was dropped.
func (e *Engine) checkIntercept(ctx context.Context, c *connection, m *member) bool {
	if !tester.Intercepted(ctx, c.memberProxy(m), 10*time.Second) || ctx.Err() != nil {
		return false
	}
	if !e.distrust(m.server.key64, m.server.Name) {
		return false
	}
	c.mu.Lock()
	m.forged, m.alive = true, false
	c.mu.Unlock()
	return true
}
