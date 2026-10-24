package engine

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/account"
	"github.com/cezomagoanlace29861-jpg/vp/internal/node"
)

// AccountURL is the account service, set at build time with
// -ldflags "-X .../internal/engine.AccountURL=https://a.example,https://b.example".
// Several addresses may be given, comma separated; they are tried in order,
// which helps where one of them is blocked. Empty means no accounts: the app
// connects without signing in (development builds and tests).
var AccountURL = ""

// ErrLoginRequired means the user has to sign in before connecting.
var ErrLoginRequired = errors.New("Sign in to connect.")

// LimitError means the user's account may not connect right now.
type LimitError struct {
	Reason  string
	Message string
}

func (e *LimitError) Error() string { return e.Message }

const (
	// An answer from the service this recent is not asked for again when
	// connecting.
	syncFresh = 2 * time.Minute
	// How often use is added up and how often the service is asked.
	meterEvery = 15 * time.Second
	syncEvery  = time.Minute
	// How long connecting waits for a direct call to the service.
	connectSync = 6 * time.Second
	// How long signing in may take, finding a server to go through included.
	signInWait = 75 * time.Second
	// What signing in keeps for a direct call when no server got through.
	directWait = 20 * time.Second
	// How long connecting tries servers to recheck an account at its limit.
	limitSync = 25 * time.Second
)

// AccountState is the signed-in user's account as the UI shows it.
type AccountState struct {
	Enabled     bool   `json:"enabled"` // this build asks users to sign in
	SignedIn    bool   `json:"signed_in"`
	Username    string `json:"username,omitempty"`
	Message     string `json:"message,omitempty"` // why the account cannot connect, if so
	QuotaBytes  int64  `json:"quota_bytes"`
	UsedBytes   int64  `json:"used_bytes"`
	MaxSeconds  int64  `json:"max_seconds"`
	UsedSeconds int64  `json:"used_seconds"`
	ExpiresAt   int64  `json:"expires_at"`
	ResetsAt    int64  `json:"resets_at"`
	SiteURL     string `json:"site_url,omitempty"`
}

func accountURLs(opt Options) []string {
	list := opt.AccountURLs
	if list == nil {
		list = strings.Split(AccountURL, ",")
	}
	var out []string
	for _, u := range list {
		if u = strings.TrimSpace(u); strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://127.0.0.1") {
			out = append(out, u)
		}
	}
	return out
}

// Account returns the account for the UI.
func (e *Engine) Account() AccountState {
	if e.acct == nil {
		return AccountState{}
	}
	st := AccountState{Enabled: true, SiteURL: e.acct.Site()}
	v := e.acct.View()
	if !v.SignedIn {
		return st
	}
	i := v.Info
	st.SignedIn, st.Username = true, i.Username
	st.QuotaBytes, st.UsedBytes, st.MaxSeconds, st.UsedSeconds = i.QuotaBytes, i.UsedBytes, i.MaxSeconds, i.UsedSeconds
	st.ExpiresAt, st.ResetsAt = i.ExpiresAt, i.ResetsAt
	if why := i.Why(time.Now()); why != "" {
		st.Message = limitMessage(why, i)
	}
	return st
}

// Login signs the user in to the account service.
func (e *Engine) Login(username, password string) error {
	if e.acct == nil {
		return errors.New("Accounts are not used in this build.")
	}
	if strings.TrimSpace(username) == "" || password == "" {
		return errors.New("Enter your username and password.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), signInWait)
	defer cancel()
	login := func(ctx context.Context) error {
		_, err := e.acct.Login(ctx, username, password)
		return err
	}
	err := e.tunnelFirst(ctx, signInWait-directWait, login)
	if err != nil {
		if errors.Is(err, account.ErrUnreachable) || errors.Is(err, context.DeadlineExceeded) {
			return errors.New("Cannot reach the account service. Check your internet connection and try again.")
		}
		return err
	}
	e.logf("info", "Signed in.")
	return nil
}

// tunnelFirst runs call through the VPN, or while it is down through
// working servers for up to wait, and only then directly: a direct call
// shows the network that this device talks to the service (ECH hides the
// name where it works, see ech.go). The service is also filtered in many
// places.
func (e *Engine) tunnelFirst(ctx context.Context, wait time.Duration, call func(context.Context) error) error {
	if e.proxyClient() != nil {
		return call(ctx)
	}
	if e.warmPrivate != nil {
		// Look the names up while the servers are tried.
		for _, u := range e.crowdURLs {
			if p, err := url.Parse(u); err == nil {
				e.warmPrivate(p.Hostname())
			}
		}
	}
	vctx, cancel := context.WithTimeout(ctx, wait)
	err := e.viaServer(vctx, call)
	cancel()
	if !errors.Is(err, account.ErrUnreachable) && !errors.Is(err, context.DeadlineExceeded) && !account.Busy(err) {
		return err
	}
	return call(account.WithClient(ctx, e.privateDirect))
}

// viaServer runs call through working servers, one after another, until
// one of them reaches the account service. On a first start the servers
// are still being found, so it waits for them.
func (e *Engine) viaServer(ctx context.Context, call func(context.Context) error) error {
	err := account.ErrUnreachable
	if e.bin.SingBox == "" {
		// No core to go through a server with.
		return err
	}
	tried := map[string]bool{}
	for ctx.Err() == nil {
		list := e.bestServers("", 6, tried)
		if len(list) == 0 {
			list = e.recentServers("", 6, tried)
		}
		var nodes []*node.Node
		for _, s := range list {
			tried[s.Key] = true
			if n := s.runNode(); n != nil {
				nodes = append(nodes, n)
			}
		}
		if len(nodes) == 0 {
			e.triggerRefill()
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			continue
		}
		e.logf("info", "Signing in through a server.")
		e.tester.Through(ctx, "signin", nodes, func(proxy *url.URL) bool {
			hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSHandshakeTimeout: 15 * time.Second}}
			err = call(account.WithClient(ctx, hc))
			return !errors.Is(err, account.ErrUnreachable) && !account.Busy(err)
		})
		if !errors.Is(err, account.ErrUnreachable) && !account.Busy(err) {
			return err
		}
	}
	return err
}

// Logout disconnects and forgets the session.
func (e *Engine) Logout() {
	if e.acct == nil {
		return
	}
	e.Disconnect()
	e.acct.Logout()
}

// AllowConnect says whether the signed-in user may connect now. The last
// answer from the service decides, and the meter asks the service through
// the VPN as soon as it is up, so connecting makes no direct call. Only an
// account the last answer put at a limit is checked first (its allowance
// may have renewed), through servers before going direct.
func (e *Engine) AllowConnect() error {
	if e.acct == nil {
		return nil
	}
	v := e.acct.View()
	if !v.SignedIn {
		return ErrLoginRequired
	}
	info, now := v.Info, e.acct.Now()
	if info.Why(now) != "" {
		ctx, cancel := context.WithTimeout(context.Background(), limitSync+connectSync)
		err := e.tunnelFirst(ctx, limitSync, func(ctx context.Context) error {
			got, err := e.acct.Sync(ctx)
			if err == nil {
				info = got
			}
			return err
		})
		cancel()
		if errors.Is(err, account.ErrSignedOut) {
			return ErrLoginRequired
		}
	}
	if why := info.Why(now); why != "" {
		return &LimitError{Reason: why, Message: limitMessage(why, info)}
	}
	return nil
}

func limitMessage(reason string, i account.Info) string {
	renew := ""
	if i.ResetsAt > 0 {
		renew = " It renews on " + time.Unix(i.ResetsAt, 0).UTC().Format("2 Jan 2006") + "."
	}
	switch reason {
	case account.ReasonQuota:
		return "Your data allowance is used up." + renew
	case account.ReasonTime:
		return "Your time allowance is used up." + renew
	case account.ReasonExpired:
		return "Your account has expired."
	}
	return "Your account is turned off."
}

// meterState is what meterStep has already counted.
type meterState struct {
	bytes  int64
	at     time.Time // use is counted in whole seconds up to here
	synced time.Time
}

// meter adds up the connection's data and time for the account and asks the
// service whether the user may go on, until the connection ends.
func (e *Engine) meter(ctx context.Context, c *connection) {
	m := &meterState{at: time.Now(), synced: time.Now()}
	if v := e.acct.View(); v.Stale || e.acct.Now().Sub(v.SyncedAt) > syncFresh {
		// Connecting did not ask the service (AllowConnect): ask at the
		// first step, through the VPN.
		m.synced = time.Time{}
	}
	t := time.NewTicker(meterEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			e.meterStep(context.Background(), c, m, false)
			return
		case <-t.C:
			if e.meterStep(ctx, c, m, true) {
				return
			}
		}
	}
}

// meterStep counts use since the last step and, when the account is over a
// limit or the service is due to be asked, checks with the service. It
// disconnects an account that may not go on and reports whether it did.
func (e *Engine) meterStep(ctx context.Context, c *connection, m *meterState, check bool) bool {
	now := time.Now()
	c.mu.Lock()
	total := c.up + c.down
	c.mu.Unlock()
	secs := int64(now.Sub(m.at) / time.Second)
	e.acct.Add(total-m.bytes, secs)
	m.bytes = total
	m.at = m.at.Add(time.Duration(secs) * time.Second)
	if !check {
		return false
	}
	v := e.acct.View()
	why, info := v.Info.Why(now), v.Info
	if v.SignedIn && (why != "" || now.Sub(m.synced) >= syncEvery) {
		// A local count over a limit is confirmed with the service first:
		// the allowance may have renewed.
		got, err := e.acct.Sync(ctx)
		switch {
		case err == nil:
			info, why, m.synced = got, got.Why(now), now
		case errors.Is(err, account.ErrSignedOut):
			e.stopForAccount("Sign in to connect.")
			return true
		case ctx.Err() != nil:
			return false
		case v.Stale:
			e.stopForAccount("Cannot reach the account service. Check your internet connection and try again.")
			return true
		}
	}
	if !v.SignedIn {
		e.stopForAccount("Sign in to connect.")
		return true
	}
	if why != "" {
		e.logf("warn", "Account limit reached (%s).", why)
		e.stopForAccount(limitMessage(why, info))
		return true
	}
	return false
}

// stopForAccount disconnects and tells the user why.
func (e *Engine) stopForAccount(message string) {
	go func() {
		e.Disconnect()
		e.setStatus(StatusIdle, message)
	}()
}
