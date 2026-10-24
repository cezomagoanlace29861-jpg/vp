package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cezomagoanlace29861-jpg/vp/internal/sources"
)

// accountService is a stand-in for the account Worker.
type accountService struct {
	mu    sync.Mutex
	quota int64
	used  int64
	off   bool
	reset int64
}

func (a *accountService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	acct := func() map[string]any {
		m := map[string]any{"username": "ada", "allowed": !a.off && (a.quota == 0 || a.used < a.quota),
			"quota_bytes": a.quota, "used_bytes": a.used, "resets_at": a.reset}
		switch {
		case a.off:
			m["reason"] = "disabled"
		case a.quota > 0 && a.used >= a.quota:
			m["reason"] = "quota"
		}
		return m
	}
	switch r.URL.Path {
	case "/api/v1/login":
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["password"] != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Wrong username or password"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"token": "t", "account": acct()})
	case "/api/v1/usage":
		var in map[string]int64
		json.NewDecoder(r.Body).Decode(&in)
		a.used += in["bytes"]
		json.NewEncoder(w).Encode(map[string]any{"account": acct()})
	}
}

func newAccountEngine(t *testing.T, svc *accountService) *Engine {
	t.Helper()
	ts := httptest.NewServer(svc)
	t.Cleanup(ts.Close)
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}, AccountURLs: []string{ts.URL}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.pool.Close() })
	return e
}

func TestAccountGate(t *testing.T) {
	svc := &accountService{quota: 1000}
	e := newAccountEngine(t, svc)

	if a := e.Snapshot().Account; !a.Enabled || a.SignedIn {
		t.Fatalf("before login: %+v", a)
	}
	if err := e.Connect(""); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("connect without an account: %v", err)
	}
	if err := e.Login("ada", "nope"); err == nil || !strings.Contains(err.Error(), "Wrong username") {
		t.Fatalf("login with a wrong password: %v", err)
	}
	if err := e.Login("ada", "pw"); err != nil {
		t.Fatal(err)
	}
	if a := e.Snapshot().Account; !a.SignedIn || a.Username != "ada" || a.QuotaBytes != 1000 {
		t.Fatalf("after login: %+v", a)
	}
	if err := e.AllowConnect(); err != nil {
		t.Fatalf("an account with data left was refused: %v", err)
	}

	// The last answer stands, even an old one: connecting makes no direct
	// call, and the meter asks through the VPN once it is up.
	clock := time.Now()
	e.acct.Now = func() time.Time { return clock }
	svc.mu.Lock()
	svc.off = true
	svc.mu.Unlock()
	clock = clock.Add(3 * time.Minute)
	if err := e.AllowConnect(); err != nil {
		t.Fatalf("asked the service when the last answer allowed connecting: %v", err)
	}
	svc.mu.Lock()
	svc.off = false
	svc.mu.Unlock()

	// Used up (as counted here): the service is asked, since the allowance
	// may have renewed, and it refuses with a message the user can read,
	// with the renewal date.
	svc.mu.Lock()
	svc.used, svc.reset = 1000, time.Date(2030, 3, 5, 0, 0, 0, 0, time.UTC).Unix()
	svc.mu.Unlock()
	e.acct.Add(1000, 0)
	var limit *LimitError
	if err := e.Connect(""); !errors.As(err, &limit) || limit.Reason != "quota" {
		t.Fatalf("connect over the quota: %v", err)
	}
	if !strings.Contains(limit.Message, "5 Mar 2030") {
		t.Fatalf("message lacks the renewal date: %q", limit.Message)
	}
	if s := e.Snapshot(); s.Status != StatusIdle || s.Message != limit.Message {
		t.Fatalf("status after refusal: %q %q", s.Status, s.Message)
	}

	// Switched off by the administrator.
	svc.mu.Lock()
	svc.used, svc.off = 0, true
	svc.mu.Unlock()
	if err := e.AllowConnect(); !errors.As(err, &limit) || limit.Reason != "disabled" {
		t.Fatalf("disabled account: %v", err)
	}

	e.Logout()
	if err := e.AllowConnect(); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("after sign out: %v", err)
	}
}

func TestNoAccountsInThisBuild(t *testing.T) {
	e, err := New(Options{DataDir: t.TempDir(), Sources: []sources.Source{}, AccountURLs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.pool.Close()
	if e.Snapshot().Account.Enabled {
		t.Fatal("accounts enabled without a service address")
	}
	if err := e.AllowConnect(); err != nil {
		t.Fatal(err)
	}
}

func TestMeterCountsAndStops(t *testing.T) {
	svc := &accountService{quota: 1000}
	e := newAccountEngine(t, svc)
	if err := e.Login("ada", "pw"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &connection{cancel: cancel}
	e.mu.Lock()
	e.conn = c
	e.mu.Unlock()
	e.setStatus(StatusConnected, "")

	m := &meterState{at: time.Now().Add(-3 * time.Second), synced: time.Now()}
	// Under the quota: counted locally, the service is not asked yet.
	c.mu.Lock()
	c.up, c.down = 100, 200
	c.mu.Unlock()
	if e.meterStep(ctx, c, m, true) {
		t.Fatal("stopped an account with data left")
	}
	if a := e.Account(); a.UsedBytes != 300 || a.UsedSeconds < 3 {
		t.Fatalf("counted %d bytes, %d s", a.UsedBytes, a.UsedSeconds)
	}
	// Over the quota: the service confirms, the connection is taken down.
	c.mu.Lock()
	c.down = 5000
	c.mu.Unlock()
	if !e.meterStep(ctx, c, m, true) {
		t.Fatal("did not stop an account over its quota")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := e.Snapshot()
		if s.Status == StatusIdle && strings.Contains(s.Message, "data allowance") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still %q %q after the limit", s.Status, s.Message)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ctx.Err() == nil {
		t.Fatal("the connection was not cancelled")
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.used < 5100 {
		t.Fatalf("service was told about %d bytes, want 5100", svc.used)
	}
}
