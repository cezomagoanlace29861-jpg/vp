// Package account is the app's side of user accounts: signing in to the
// account service, remembering the session, and reporting how much data and
// time a user has spent so the service can enforce each user's limits.
//
// The service is a Cloudflare Worker (backend/). The app asks it, once a
// minute while connected, whether the user may go on; the answer decides
// whether the connection stays up. Only a username, byte and second counts
// leave the device; never the sites visited.
//
// Limits are enforced by the app (the servers behind it belong to others),
// so they hold for the official app and stop honest overuse; they cannot
// stop someone who rebuilds the client. See the README.
package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Grace is how long an account stays usable when the service cannot be
// reached (it may be blocked where the user is). After that the app asks
// for a connection to the service before it connects again.
const Grace = 72 * time.Hour

// Reasons an account may not connect.
const (
	ReasonDisabled = "disabled"
	ReasonExpired  = "expired"
	ReasonQuota    = "quota"
	ReasonTime     = "time"
)

// Info is what the service says about a user. Zero limits mean unlimited.
type Info struct {
	Username    string `json:"username"`
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason,omitempty"`
	QuotaBytes  int64  `json:"quota_bytes"`
	UsedBytes   int64  `json:"used_bytes"`
	MaxSeconds  int64  `json:"max_seconds"`
	UsedSeconds int64  `json:"used_seconds"`
	ExpiresAt   int64  `json:"expires_at"` // unix seconds
	ResetsAt    int64  `json:"resets_at"`  // unix seconds: when the allowance renews
}

// Why returns the reason this account cannot connect now, or "" if it can.
// It trusts the service's verdict and also applies the counts the app has
// added since, so a limit is noticed between two syncs.
func (i Info) Why(now time.Time) string {
	if !i.Allowed && i.Reason != "" {
		return i.Reason
	}
	switch {
	case i.ExpiresAt > 0 && now.Unix() >= i.ExpiresAt:
		return ReasonExpired
	case i.QuotaBytes > 0 && i.UsedBytes >= i.QuotaBytes:
		return ReasonQuota
	case i.MaxSeconds > 0 && i.UsedSeconds >= i.MaxSeconds:
		return ReasonTime
	case !i.Allowed:
		return ReasonDisabled
	}
	return ""
}

// Error is an answer from the service that refused the request.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Busy says the service turned the call away for coming too often from its
// address, which a public server shares with many other users: another
// way in may still work.
func Busy(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusTooManyRequests
}

var (
	// ErrSignedOut means the service no longer accepts the saved session.
	ErrSignedOut = errors.New("signed out")
	// ErrUnreachable means no address of the service answered.
	ErrUnreachable = errors.New("cannot reach the account service")
)

type stored struct {
	Token    string `json:"token"`
	Info     Info   `json:"info"`
	SyncedAt int64  `json:"synced_at"`
	// Counts not yet confirmed by the service.
	PendingBytes   int64 `json:"pending_bytes"`
	PendingSeconds int64 `json:"pending_seconds"`
	// Base is the address that answered last, tried first after a restart.
	Base string `json:"base,omitempty"`
}

// Client talks to the service and keeps the session on disk.
type Client struct {
	// URLs are the service's addresses, tried in order.
	URLs []string
	// HTTP returns the client to use now (through the VPN when it is up).
	HTTP func() *http.Client
	// Path is where the session is saved.
	Path string
	// Now is the clock (tests replace it).
	Now func() time.Time

	mu sync.Mutex
	st stored
	// last is the index in URLs of the address that answered last, tried
	// first, so an address that is blocked costs its timeout only once. It
	// is saved with the session (stored.Base).
	last atomic.Int32
}

// New returns a client with the session at path loaded.
func New(urls []string, path string, httpClient func() *http.Client) *Client {
	c := &Client{URLs: urls, HTTP: httpClient, Path: path, Now: time.Now}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &c.st)
	}
	for i, u := range urls {
		if u == c.st.Base {
			c.last.Store(int32(i))
		}
	}
	return c
}

// Site is the service's web address, where users sign up and see their
// account.
func (c *Client) Site() string {
	if len(c.URLs) == 0 {
		return ""
	}
	return strings.TrimRight(c.URLs[0], "/") + "/"
}

// View is the account as the app shows it.
type View struct {
	SignedIn bool
	Info     Info
	// Stale means the service has not been reached for longer than Grace.
	Stale bool
	// SyncedAt is when the service last answered.
	SyncedAt time.Time
}

// View returns the signed-in account with unreported use added.
func (c *Client) View() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Token == "" {
		return View{}
	}
	i := c.st.Info
	i.UsedBytes += c.st.PendingBytes
	i.UsedSeconds += c.st.PendingSeconds
	stale := c.Now().Sub(time.Unix(c.st.SyncedAt, 0)) > Grace
	return View{SignedIn: true, Info: i, Stale: stale, SyncedAt: time.Unix(c.st.SyncedAt, 0)}
}

// Login signs in and saves the session.
func (c *Client) Login(ctx context.Context, username, password string) (Info, error) {
	var out struct {
		Token   string `json:"token"`
		Account Info   `json:"account"`
	}
	body := map[string]string{"username": strings.TrimSpace(username), "password": password}
	if err := c.call(ctx, http.MethodPost, "login", "", body, &out); err != nil {
		return Info{}, err
	}
	if out.Token == "" {
		return Info{}, errors.New("unexpected answer from the account service")
	}
	c.mu.Lock()
	c.st = stored{Token: out.Token, Info: out.Account, SyncedAt: c.Now().Unix()}
	err := c.saveLocked()
	c.mu.Unlock()
	return out.Account, err
}

// Logout forgets the session.
func (c *Client) Logout() {
	c.mu.Lock()
	c.st = stored{}
	c.mu.Unlock()
	os.Remove(c.Path)
}

// Add records use that the service has not been told about yet.
func (c *Client) Add(bytes, seconds int64) {
	if bytes <= 0 && seconds <= 0 {
		return
	}
	c.mu.Lock()
	if c.st.Token != "" {
		c.st.PendingBytes += max(bytes, 0)
		c.st.PendingSeconds += max(seconds, 0)
		c.saveLocked()
	}
	c.mu.Unlock()
}

// Sync reports unreported use and takes the service's current answer. When
// the service cannot be reached the use stays pending and the last answer
// stands (until Grace passes).
func (c *Client) Sync(ctx context.Context) (Info, error) {
	c.mu.Lock()
	token, b, s := c.st.Token, c.st.PendingBytes, c.st.PendingSeconds
	c.mu.Unlock()
	if token == "" {
		return Info{}, ErrSignedOut
	}
	var out struct {
		Token   string `json:"token"`
		Account Info   `json:"account"`
	}
	err := c.call(ctx, http.MethodPost, "usage", token, map[string]int64{"bytes": b, "seconds": s}, &out)
	var he *Error
	if errors.As(err, &he) && he.Status == http.StatusUnauthorized {
		c.Logout()
		return Info{}, ErrSignedOut
	}
	if err != nil {
		return Info{}, err
	}
	c.mu.Lock()
	// Use added while the request was in flight stays pending.
	c.st.PendingBytes = max(c.st.PendingBytes-b, 0)
	c.st.PendingSeconds = max(c.st.PendingSeconds-s, 0)
	c.st.Info, c.st.SyncedAt = out.Account, c.Now().Unix()
	if out.Token != "" {
		c.st.Token = out.Token
	}
	err = c.saveLocked()
	c.mu.Unlock()
	return out.Account, err
}

func (c *Client) saveLocked() error {
	if k := int(c.last.Load()); k < len(c.URLs) {
		c.st.Base = c.URLs[k]
	}
	b, err := json.Marshal(c.st)
	if err != nil {
		return err
	}
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}

type clientKey struct{}

// WithClient makes the calls made with ctx go through hc, such as a server
// the app found working while the service cannot be reached directly.
func WithClient(ctx context.Context, hc *http.Client) context.Context {
	return context.WithValue(ctx, clientKey{}, hc)
}

// call sends one request to the first address that answers.
func (c *Client) call(ctx context.Context, method, path, token string, body, out any) error {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	var last error = ErrUnreachable
	first := int(c.last.Load())
	for i := range c.URLs {
		k := (first + i) % len(c.URLs)
		base := c.URLs[k]
		hc := http.DefaultClient
		if h, ok := ctx.Value(clientKey{}).(*http.Client); ok {
			hc = h
		} else if c.HTTP != nil {
			if h := c.HTTP(); h != nil {
				hc = h
			}
		}
		// With a deadline, each address left gets an equal share of what
		// remains, so one that hangs (blocked silently) leaves time for the
		// next.
		wait := 15 * time.Second
		if d, ok := ctx.Deadline(); ok {
			wait = min(wait, time.Until(d)/time.Duration(len(c.URLs)-i))
		}
		rctx, cancel := context.WithTimeout(ctx, wait)
		req, err := http.NewRequestWithContext(rctx, method, strings.TrimRight(base, "/")+"/api/v1/"+path, bytes.NewReader(payload))
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := hc.Do(req)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		cancel()
		// A server error or a page from something in the way (a captive
		// portal, a block page) is not the service's answer: try the next
		// address.
		if resp.StatusCode >= 500 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			last = fmt.Errorf("%w (%s)", ErrUnreachable, resp.Status)
			continue
		}
		if resp.StatusCode >= 300 {
			var e struct {
				Error string `json:"error"`
			}
			json.Unmarshal(data, &e)
			if e.Error == "" {
				e.Error = resp.Status
			}
			c.last.Store(int32(k))
			return &Error{Status: resp.StatusCode, Message: e.Error}
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				last = ErrUnreachable
				continue
			}
		}
		c.last.Store(int32(k))
		return nil
	}
	return last
}

// SessionPath is where an engine keeps the session inside its data dir.
func SessionPath(dir string) string { return filepath.Join(dir, "account.json") }
