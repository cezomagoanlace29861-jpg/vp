package engine

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Endurance checks. Iran's filtering lets a few packets of a flow through
// before it cuts it (six, on Cloudflare addresses whose name is not
// allowed) and kills some tunnels a minute or so in, so a server that
// answers one test request can still die once it is used. Backups hold one
// connection open for a minute and move data over it before a failover
// trusts them.
var (
	soakFor   = 60 * time.Second
	soakEvery = 4 * time.Second
)

const (
	soakChunk = 100 << 10
	soakMin   = 1 << 20
	// soakAfter lets the connection settle before backups are checked.
	soakAfter = 30 * time.Second
)

// soak reports whether one connection through m lasts soakFor while
// carrying at least soakMin bytes.
func (c *connection) soak(ctx context.Context, m *member) bool {
	proxy := c.memberProxy(m)
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 2 * soakFor}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	end := time.Now().Add(soakFor)
	var got int64
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, speedURL+strconv.Itoa(soakChunk), nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		got += n
		if time.Now().After(end) {
			return got >= soakMin
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(soakEvery):
		}
	}
}

// soakBackups checks the group's backups, best first, one at a time. Phones
// check fewer, since each check moves about 1.5 MB.
func (e *Engine) soakBackups(ctx context.Context, c *connection) {
	limit := 6
	if e.opt.Mobile {
		limit = 3
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(soakAfter):
	}
	done := map[*member]bool{}
	for len(done) < limit && ctx.Err() == nil {
		var next *member
		for _, m := range c.backups(map[*member]bool{c.activeMember(): true}) {
			c.mu.Lock()
			fresh := m.soaked == 0
			c.mu.Unlock()
			if fresh && !done[m] {
				next = m
				break
			}
		}
		if next == nil {
			return
		}
		done[next] = true
		if e.checkIntercept(ctx, c, next) {
			continue
		}
		ok := c.soak(ctx, next)
		if ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		if ok {
			next.soaked = 1
		} else {
			next.soaked = -1
		}
		c.mu.Unlock()
		if !ok {
			e.logf("info", "A server answers but did not keep a connection up for a minute; it is used only as a last resort.")
		}
	}
}
