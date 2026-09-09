package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// writeConfigFile writes a config to dir/config.json (used to simulate
// configs produced by older versions or edited through the UI).
func writeConfigFile(t *testing.T, dir string, c Config) {
	t.Helper()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---- daily traffic limits ----

// TestDailyBytesDateReset: a counter from a previous day must read as zero
// (limits reset at UTC midnight without a restart), while today's counter
// accumulates normally.
func TestDailyBytesDateReset(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := NewUser("carol", "secret123", "user")
	u.DailyTrafficMB = 1
	if err := store.Update(func(c *Config) error {
		c.Users = append(c.Users, *u)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())

	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	p.dailyMu.Lock()
	p.daily[u.ID] = &dailyTraffic{date: yesterday, bytes: 10 * 1024 * 1024}
	p.dailyMu.Unlock()
	if got := p.dailyBytes(u.ID); got != 0 {
		t.Fatalf("stale (yesterday) counter must read as 0, got %d", got)
	}
	p.addDaily(u.ID, 5*1024*1024)
	if got := p.dailyBytes(u.ID); got != 5*1024*1024 {
		t.Fatalf("today's counter = %d, want 5 MiB", got)
	}
}

// ---- connection caps ----

func TestTryEnterConnPerUserCap(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	cfg := store.Config()
	u, _ := NewUser("alice", "secret123", "user")
	u.MaxConns = 2

	if st, reason := p.tryEnterConn(u, cfg); st != 0 {
		t.Fatalf("first slot: %d (%s)", st, reason)
	}
	if st, reason := p.tryEnterConn(u, cfg); st != 0 {
		t.Fatalf("second slot: %d (%s)", st, reason)
	}
	if got := p.userConnCount(u.ID); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	if st, reason := p.tryEnterConn(u, cfg); st != 429 {
		t.Fatalf("third slot = %d (%s), want 429", st, reason)
	}
	if got := p.userConnCount(u.ID); got != 2 {
		t.Fatalf("rejected attempt must not increment the counter; got %d, want 2", got)
	}
	p.exitConn(u.ID)
	p.exitConn(u.ID)
	if st, reason := p.tryEnterConn(u, cfg); st != 0 {
		t.Fatalf("entry after exit should succeed: %d (%s)", st, reason)
	}
	p.exitConn(u.ID)
}

func TestTryEnterConnGlobalCap(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	cfg := store.Config()
	cfg.Proxy.MaxGlobalConns = 1
	u, _ := NewUser("alice", "secret123", "user")

	if st, reason := p.tryEnterConn(u, cfg); st != 0 {
		t.Fatalf("first slot: %d (%s)", st, reason)
	}
	if st, reason := p.tryEnterConn(u, cfg); st != 503 {
		t.Fatalf("second slot = %d (%s), want 503", st, reason)
	}
	if got := p.userConnCount(u.ID); got != 1 {
		t.Fatalf("global rejection must roll back the per-user counter to the pre-attempt value (1 from the first entry); got %d", got)
	}
	if got := p.globalConns.Load(); got != 1 {
		t.Fatalf("global counter = %d, want 1", got)
	}
	p.exitConn(u.ID)
	if st, reason := p.tryEnterConn(u, cfg); st != 0 {
		t.Fatalf("entry after exit should succeed: %d (%s)", st, reason)
	}
	p.exitConn(u.ID)
}

// ---- forwarding / CONNECT ----

func newProxyOnEphemeral(t *testing.T) (*Proxy, *Store) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	if err := store.Update(func(c *Config) error {
		c.Proxy.RequireAuth = false
		c.Proxy.ListenAddr = "127.0.0.1:0"
		c.Proxy.AdminListenAddr = "127.0.0.1:0"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p.OnConfigChanged(store.Config())
	if err := p.Start(store.Config()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Shutdown)
	return p, store
}

// TestForwardRejectsNonHTTPScheme: absolute-form URLs that are not plain
// HTTP must be rejected with 400 (they used to fall through to a 502
// upstream error).
func TestForwardRejectsNonHTTPScheme(t *testing.T) {
	p, _ := newProxyOnEphemeral(t)
	req := httptest.NewRequest("GET", "https://example.com/secret", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("https absolute-form = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	req2 := httptest.NewRequest("GET", "gopher://example.com/", nil)
	w2 := httptest.NewRecorder()
	p.ServeHTTP(w2, req2)
	if w2.Code != 400 {
		t.Fatalf("gopher absolute-form = %d, want 400", w2.Code)
	}
}

// TestConnectForwardsPipelinedBytes: bytes sent in the same segment as the
// CONNECT request (for TLS: the first bytes of the ClientHello) must reach
// the upstream, not be dropped.
func TestConnectForwardsPipelinedBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	upstreamFirst := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			upstreamFirst <- nil
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		upstreamFirst <- buf[:n]
	}()

	p, _ := newProxyOnEphemeral(t)
	target := ln.Addr().String()

	conn, err := net.Dial("tcp", p.ListenerAddr("proxy"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	// A minimal TLS-looking record pipelined right after the headers.
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'T', 'L', 'S', 0x01, 0x02}
	if _, err := conn.Write(append([]byte(req), hello...)); err != nil {
		t.Fatal(err)
	}

	// Read the 200 response.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	one := make([]byte, 1)
	for !bytes.Contains(got, []byte("\r\n\r\n")) {
		n, err := conn.Read(one)
		if err != nil {
			t.Fatalf("reading CONNECT response: %v", err)
		}
		got = append(got, one[:n]...)
		if len(got) > 4096 {
			t.Fatalf("no end of response in %d bytes", len(got))
		}
	}
	if !strings.Contains(string(got), "200") {
		t.Fatalf("CONNECT response = %q, want 200", got)
	}

	select {
	case first := <-upstreamFirst:
		if first == nil || first[0] != 0x16 {
			t.Fatalf("upstream first bytes = %v, want the pipelined 0x16 hello", first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the pipelined bytes")
	}
}

// ---- rules ----

func TestEvaluateNilUser(t *testing.T) {
	re := NewRulesEngine()
	re.Rebuild(Config{})
	if d := re.Evaluate(nil, "anything.example.com"); !d.Allowed {
		t.Fatalf("nil user, no rules, must not panic/deny: %v", d.Reason)
	}

	// whitelist-only mode must gate even nil users
	re2 := NewRulesEngine()
	re2.Rebuild(Config{GlobalRules: GlobalRules{WhitelistOnly: true}})
	if d := re2.Evaluate(nil, "anything.example.com"); d.Allowed {
		t.Fatal("nil user must be denied in whitelist-only mode")
	}

	// a non-empty global whitelist must gate nil users too (the old code
	// only checked the WhitelistOnly flag for unknown users)
	re3 := NewRulesEngine()
	re3.Rebuild(Config{GlobalRules: GlobalRules{Whitelist: []string{"good.example.com"}}})
	if d := re3.Evaluate(nil, "other.example.com"); d.Allowed {
		t.Fatal("nil user with a non-empty global whitelist must be denied")
	}
	if d := re3.Evaluate(nil, "good.example.com"); !d.Allowed {
		t.Fatalf("nil user should match the global whitelist: %v", d.Reason)
	}

	// global blacklist beats everything, nil user included
	re4 := NewRulesEngine()
	re4.Rebuild(Config{GlobalRules: GlobalRules{
		WhitelistOnly: true,
		Whitelist:     []string{"good.example.com"},
		Blacklist:     []string{"bad.example.com"},
	}})
	if d := re4.Evaluate(nil, "bad.example.com"); d.Allowed {
		t.Fatal("global blacklist must win for a nil user")
	}
}

func TestNormalizeHostColonAndIP(t *testing.T) {
	cases := map[string]string{
		"example.com:":   "example.com", // trailing colon no longer bypasses rules
		"EXAMPLE.com:80": "example.com",
		"2001:DB8::1":    "2001:db8::1", // bare IPv6 canonicalized, not mangled
		"10.0.0.1":       "10.0.0.1",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"example.com":        "example.com:443",
		"example.com:":       "example.com:443",
		"example.com:8443":   "example.com:8443",
		"2001:db8::1":        "[2001:db8::1]:443",
		"[2001:db8::1]":      "[2001:db8::1]:443",
		"[2001:db8::1]:8443": "[2001:db8::1]:8443",
		"[::1]":              "[::1]:443",
		"EXAMPLE.com:443":    "example.com:443",
		"":                   "",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompileBareIPv6(t *testing.T) {
	r, err := compilePattern("2001:DB8::1")
	if err != nil {
		t.Fatalf("compile bare IPv6: %v", err)
	}
	if r.exact != "2001:db8::1" {
		t.Fatalf("canonical form = %q, want 2001:db8::1", r.exact)
	}
	if !r.matches(normalizeHost("2001:db8::1")) {
		t.Error("pattern must match the normalized request host")
	}
	if r.matches(normalizeHost("2001:db8::2")) {
		t.Error("pattern must not match a different address")
	}
}

// ---- config migration ----

func TestMigrateRespectsExplicitLogSettings(t *testing.T) {
	// v1 config with file logging explicitly disabled: must survive a boot.
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.SessionKey = "0123456789abcdef0123456789abcdef"
	cfg.Logs = LogSettings{RingSize: 5000, FileMaxMB: 0, ToFile: false}
	writeConfigFile(t, dir, cfg)
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := st.Config().Logs
	if got.ToFile || got.FileMaxMB != 0 || got.RingSize != 5000 {
		t.Fatalf("explicit log settings were clobbered on boot: %+v", got)
	}
	if st.Config().SessionKey == cfg.SessionKey {
		t.Fatal("session key must still rotate on boot")
	}

	// all-zero logs (pre-UI config): defaults must be applied.
	dir2 := t.TempDir()
	cfg2 := defaultConfig()
	cfg2.Logs = LogSettings{}
	writeConfigFile(t, dir2, cfg2)
	st2, err := NewStore(dir2)
	if err != nil {
		t.Fatal(err)
	}
	g2 := st2.Config().Logs
	if g2.RingSize != 20000 || g2.FileMaxMB != 10 || !g2.ToFile {
		t.Fatalf("all-zero logs should get defaults: %+v", g2)
	}
}

// ---- admin API guards ----

func newAdminTest(t *testing.T) (*httptest.Server, *Store, string) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	srv := httptest.NewServer(p.AdminHandler())
	t.Cleanup(func() {
		srv.Close()
		p.Shutdown()
	})
	tok, err := issueToken(store.Config().SessionKey, "admin", time.Hour, store.FindUserByName("admin").TokenEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return srv, store, tok
}

func adminDo(t *testing.T, srv *httptest.Server, tok, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rbody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rbody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, rbody)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestLastAdminGuard: disabling OR demoting the only enabled admin must
// fail, while two admins may disable/demote one another.
func TestLastAdminGuard(t *testing.T) {
	srv, store, tok := newAdminTest(t)
	adminID := store.FindUserByName("admin").ID

	// Add a second admin.
	st, body := adminDo(t, srv, tok, "POST", "/admin/api/users", map[string]any{
		"username": "bob", "password": "bobpass123", "role": "admin",
	})
	if st != 201 {
		t.Fatalf("create second admin: %d %v", st, body)
	}

	// With two admins, demoting the first is allowed.
	st, body = adminDo(t, srv, tok, "PUT", "/admin/api/users/"+adminID, map[string]any{"role": "user"})
	if st != 200 {
		t.Fatalf("demote with a second admin present: %d %v", st, body)
	}

	// The original token no longer belongs to an admin; log in as bob.
	bobTok := loginToken(t, srv, "bob", "bobpass123")

	// Now bob is the only admin: disabling him must fail...
	bobID := store.FindUserByName("bob").ID
	st, body = adminDo(t, srv, bobTok, "PUT", "/admin/api/users/"+bobID, map[string]any{"enabled": false})
	if st != 400 {
		t.Fatalf("disable last admin: %d %v (want 400)", st, body)
	}
	// ...and demoting him must fail too (the original hole).
	st, body = adminDo(t, srv, bobTok, "PUT", "/admin/api/users/"+bobID, map[string]any{"role": "user"})
	if st != 400 {
		t.Fatalf("demote last admin: %d %v (want 400)", st, body)
	}

	// State must be untouched by the failed updates.
	if u := store.FindUser(bobID); u == nil || u.Role != "admin" || !u.Enabled {
		t.Fatalf("failed update must not mutate state: %+v", u)
	}
	if u := store.FindUser(adminID); u == nil || u.Role != "user" {
		t.Fatalf("earlier demotion should have persisted: %+v", u)
	}

	// Deleting the last admin must also fail.
	st, body = adminDo(t, srv, bobTok, "DELETE", "/admin/api/users/"+bobID, nil)
	if st != 400 {
		t.Fatalf("delete last admin: %d %v (want 400)", st, body)
	}
}

// loginToken logs in through the admin API and returns the session token
// (the API delivers it via the fpx_session cookie).
func loginToken(t *testing.T, srv *httptest.Server, user, pass string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := http.Post(srv.URL+"/admin/api/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login as %s: %d", user, resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "fpx_session" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("login response has no fpx_session cookie")
	return ""
}

// TestDuplicateUsername: creating a user with an already-taken name must
// return 409.
func TestDuplicateUsername(t *testing.T) {
	srv, _, tok := newAdminTest(t)
	st, _ := adminDo(t, srv, tok, "POST", "/admin/api/users", map[string]any{
		"username": "alice", "password": "alicepw123", "role": "user",
	})
	if st != 201 {
		t.Fatalf("create alice: %d", st)
	}
	st, body := adminDo(t, srv, tok, "POST", "/admin/api/users", map[string]any{
		"username": "alice", "password": "otherpw123", "role": "user",
	})
	if st != 409 {
		t.Fatalf("duplicate create: %d %v (want 409)", st, body)
	}
	// Renaming another user onto a taken name must also fail.
	// (create a third user first)
	st, _ = adminDo(t, srv, tok, "POST", "/admin/api/users", map[string]any{
		"username": "carol", "password": "carolpw123", "role": "user",
	})
	if st != 201 {
		t.Fatalf("create carol: %d", st)
	}
	carolID := carolUser(t, srv, tok)
	st, body = adminDo(t, srv, tok, "PUT", "/admin/api/users/"+carolID, map[string]any{"username": "alice"})
	if st != 409 {
		t.Fatalf("rename onto taken name: %d %v (want 409)", st, body)
	}
}

func carolUser(t *testing.T, srv *httptest.Server, tok string) string {
	t.Helper()
	st, body := adminDo(t, srv, tok, "GET", "/admin/api/users", nil)
	if st != 200 {
		t.Fatal(st)
	}
	_ = body
	// users are returned as a JSON array; re-decode properly
	req, _ := http.NewRequest("GET", srv.URL+"/admin/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Username == "carol" {
			return u.ID
		}
	}
	t.Fatal("carol not found")
	return ""
}

// TestLoginLockout: 10 failed logins from one IP lock it out; while locked,
// even correct credentials get 429.
func TestLoginLockout(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	srv := httptest.NewServer(p.AdminHandler())
	defer func() {
		srv.Close()
		p.Shutdown()
	}()

	login := func(user, pass string) int {
		b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
		resp, err := http.Post(srv.URL+"/admin/api/login", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 1; i <= 10; i++ {
		if got := login("admin", "wrong-password"); got != 401 {
			t.Fatalf("failed attempt %d = %d, want 401", i, got)
		}
	}
	if got := login("admin", "admin123"); got != 429 {
		t.Fatalf("11th attempt (correct password) = %d, want 429 while locked out", got)
	}
}

// TestRequireAdminStaleCookie: a stale/invalid session cookie must not
// shadow a valid bearer token (or basic auth) on the same request.
func TestRequireAdminStaleCookie(t *testing.T) {
	srv, store, tok := newAdminTest(t)
	req, err := http.NewRequest("GET", srv.URL+"/admin/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "fpx_session", Value: "bogus.stale-token"})
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("stale cookie shadowed the valid bearer token: %d", resp.StatusCode)
	}
	_ = store
}

// ---- log store ----

func TestCSVQuoting(t *testing.T) {
	l := &LogStore{}
	out := l.CSV([]LogEntry{{
		Time:    "2024-01-01T00:00:00Z",
		User:    `a"b,c`,
		Method:  "GET",
		Host:    "h.example.com",
		Path:    "p\nq",
		Outcome: `DENIED: reason "x"`,
		Status:  403,
		Client:  "1.2.3.4",
	}})
	if !strings.Contains(out, `"a""b,c"`) {
		t.Fatalf("quote/comma field not RFC-4180 quoted:\n%s", out)
	}
	if !strings.Contains(out, "\"p\nq\"") {
		t.Fatalf("newline field not quoted:\n%s", out)
	}
	if !strings.Contains(out, `"DENIED: reason ""x"""`) {
		t.Fatalf("embedded quotes not doubled:\n%s", out)
	}
	// fields without special characters must stay unquoted
	if !strings.Contains(out, "2024-01-01T00:00:00Z,") {
		t.Fatalf("plain field unexpectedly quoted:\n%s", out)
	}
}

// TestLoadFileBounded: a large JSONL file must load only the newest ring
// size lines (bounded memory), newest first in Recent().
func TestLoadFileBounded(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(c *Config) error {
		c.Logs = LogSettings{RingSize: 1000, FileMaxMB: 10, ToFile: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "activity.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	const n = 50000
	for i := 0; i < n; i++ {
		line, _ := json.Marshal(LogEntry{
			Time:    time.Now().UTC().Format(time.RFC3339),
			User:    fmt.Sprintf("u%d", i%7),
			Host:    "h.example.com",
			Path:    fmt.Sprintf("/p%d", i),
			Status:  200,
			Outcome: "ALLOWED",
		})
		if _, err := f.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	l := NewLogStore(store, dir)
	if got := len(l.entries); got != 1000 {
		t.Fatalf("loaded %d entries, want exactly 1000 (ring size)", got)
	}
	wantPath := fmt.Sprintf("/p%d", n-1)
	if got := l.entries[len(l.entries)-1].Path; got != wantPath {
		t.Fatalf("last entry = %q, want %q", got, wantPath)
	}
	rec := l.Recent(1, "", "")
	if len(rec) != 1 || rec[0].Path != wantPath {
		t.Fatalf("Recent(1) = %+v, want newest line first", rec)
	}
}

// ---- sinkhole DNS detection (1.0.5) ----

func TestIsSinkholeAddress(t *testing.T) {
	sink := []string{"0.0.0.0", "::", "0:0:0:0:0:0:0:0"}
	for _, s := range sink {
		if !isSinkholeAddress(net.ParseIP(s)) {
			t.Errorf("%s should be a sinkhole address", s)
		}
	}
	real := []string{"127.0.0.1", "::1", "8.8.8.8", "2001:db8::1", "172.17.0.1"}
	for _, s := range real {
		if isSinkholeAddress(net.ParseIP(s)) {
			t.Errorf("%s must not be treated as a sinkhole (localhost is legitimate)", s)
		}
	}
}

// TestDialSinkholeReason uses IP literals so no network/DNS is needed
// (net.LookupHost short-circuits literals): 0.0.0.0 must be detected,
// real addresses and localhost must not.
func TestDialSinkholeReason(t *testing.T) {
	if got := dialSinkholeReason("0.0.0.0:443"); got == "" || !strings.Contains(got, "blocked") {
		t.Errorf("0.0.0.0:443 should yield a blocked-DNS explanation, got %q", got)
	}
	if got := dialSinkholeReason("0.0.0.0"); got == "" {
		t.Error("bare 0.0.0.0 (no port) should also be detected")
	}
	for _, target := range []string{"127.0.0.1:443", "8.8.8.8:443", "172.17.0.1:80", "[::1]:443", ":443", ""} {
		if got := dialSinkholeReason(target); got != "" {
			t.Errorf("dialSinkholeReason(%q) = %q, want \"\" (not a sinkhole)", target, got)
		}
	}
}

// ---- 1.0.6: auth fast path + throttle ----

// TestVerifyCacheSemantics: the PBKDF2 verification cache must not change
// behavior — correct passwords authenticate, wrong ones don't, and a
// password change takes effect immediately (the stored hash is part of the
// cache key).
func TestVerifyCacheSemantics(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Update(func(c *Config) error {
		c.Users = append(c.Users, *mustUser("alice", "secret123"))
		return nil
	})
	hdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret123"))
	if u := store.checkBasicAuth(hdr); u == nil || u.Username != "alice" {
		t.Fatalf("correct password must authenticate (first call): %+v", u)
	}
	if u := store.checkBasicAuth(hdr); u == nil || u.Username != "alice" {
		t.Fatal("correct password must authenticate (cached call)")
	}
	if u := store.checkBasicAuth("Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong"))); u != nil {
		t.Fatal("wrong password must not authenticate")
	}

	// Password change must immediately invalidate old cached successes.
	if err := store.Update(func(c *Config) error {
		for i := range c.Users {
			if c.Users[i].Username == "alice" {
				h, _ := HashPassword("newpass123")
				c.Users[i].PasswordHash = h
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if u := store.checkBasicAuth(hdr); u != nil {
		t.Fatal("old password must be rejected after a password change")
	}
	newHdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:newpass123"))
	if u := store.checkBasicAuth(newHdr); u == nil {
		t.Fatal("new password must authenticate after the change")
	}
}

// TestVerifyCacheBounded: distinct credentials get cached (proving the
// memoization path works) without exceeding the cap, and the cache never
// poisons a correct password. Uses a small count to keep the suite fast
// (each distinct wrong password costs one real PBKDF2).
func TestVerifyCacheBounded(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Update(func(c *Config) error {
		c.Users = append(c.Users, *mustUser("alice", "secret123"))
		return nil
	})
	for i := 0; i < 20; i++ {
		hdr := "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("alice:pw-%d", i)))
		if u := store.checkBasicAuth(hdr); u != nil {
			t.Fatalf("password pw-%d must not authenticate", i)
		}
	}
	store.authCacheMu.Lock()
	n := len(store.authCache)
	store.authCacheMu.Unlock()
	if n < 20 {
		t.Fatalf("expected the 20 distinct credentials to be cached, cache has %d", n)
	}
	if n > authCacheMax {
		t.Fatalf("cache exceeded authCacheMax: %d", n)
	}
	// The correct password still works after all those misses.
	hdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret123"))
	if u := store.checkBasicAuth(hdr); u == nil {
		t.Fatal("correct password must still authenticate after cache fill")
	}
}

// TestProxyAuthThrottle: 30 failed proxy-port authentications from one IP
// put it into a 60s cooldown during which even correct credentials are
// refused with 429 BEFORE any PBKDF2 work; a success clears the state.
func TestProxyAuthThrottle(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Update(func(c *Config) error {
		c.Proxy.RequireAuth = true
		c.Users = append(c.Users, *mustUser("alice", "secret123"))
		return nil
	})
	p := NewProxy(store, t.TempDir())
	req := func(pass string) *http.Request {
		hdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+pass))
		r := httptest.NewRequest("GET", "http://example.com/", nil)
		r.Header.Set("Proxy-Authorization", hdr)
		return r
	}
	// 30 failures from 10.0.0.1: each is a 407 (auth required).
	for i := 0; i < proxyMaxFails; i++ {
		u, ok, st, _ := p.authorize(req("wrong-pass"), "10.0.0.1")
		if ok || st != http.StatusProxyAuthRequired {
			t.Fatalf("failure %d: ok=%v status=%d, want 407", i+1, ok, st)
		}
		if u != nil {
			t.Fatal("failed auth must not return a user")
		}
	}
	// 31st attempt — correct password — must be refused while in cooldown.
	_, ok, st, reason := p.authorize(req("secret123"), "10.0.0.1")
	if ok || st != http.StatusTooManyRequests {
		t.Fatalf("attempt during cooldown: ok=%v status=%d (%s), want 429", ok, st, reason)
	}
	// A different IP is unaffected.
	if u, ok, st, _ := p.authorize(req("secret123"), "10.0.0.2"); !ok || st != 0 || u == nil {
		t.Fatalf("other IP must still authenticate: ok=%v status=%d", ok, st)
	}
	// A success clears the throttled IP's state.
	p.proxyAuthOK("10.0.0.1")
	if u, ok, st, _ := p.authorize(req("secret123"), "10.0.0.1"); !ok || st != 0 || u == nil {
		t.Fatalf("after proxyAuthOK the IP must authenticate again: ok=%v status=%d", ok, st)
	}
}

// TestDefaultPasswordCached: the default-password badge is computed once
// per (user, hash) and flips immediately after a password change.
func TestDefaultPasswordCached(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Update(func(c *Config) error {
		c.Users = append(c.Users, *mustUser("bob", "admin123")) // factory default
		return nil
	})
	p := NewProxy(store, t.TempDir())
	bob := store.FindUserByName("bob")
	if !p.isDefaultPassword(bob) {
		t.Fatal("admin123 must be flagged as the default password")
	}
	// Change the password: the cached flag must reflect the new hash.
	if err := store.Update(func(c *Config) error {
		for i := range c.Users {
			if c.Users[i].Username == "bob" {
				h, _ := HashPassword("newpass456")
				c.Users[i].PasswordHash = h
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if p.isDefaultPassword(store.FindUserByName("bob")) {
		t.Fatal("after a password change the default flag must be false")
	}
}

// TestUpdateSilent: UpdateSilent persists but does not notify listeners.
func TestUpdateSilent(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	notified := 0
	store.AddOnChange(func(Config) { notified++ })
	if err := store.Update(func(c *Config) error { c.Proxy.ListenAddr = ":3988"; return nil }); err != nil {
		t.Fatal(err)
	}
	if notified != 1 {
		t.Fatalf("Update notified %d times, want 1", notified)
	}
	if err := store.UpdateSilent(func(c *Config) error { c.Proxy.ListenAddr = ":3989"; return nil }); err != nil {
		t.Fatal(err)
	}
	if notified != 1 {
		t.Fatalf("UpdateSilent must not notify listeners (notified %d)", notified)
	}
	// Persisted: a reload sees the silent change.
	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Config().Proxy.ListenAddr != ":3989" {
		t.Fatalf("silent update not persisted: %q", reloaded.Config().Proxy.ListenAddr)
	}
}

// TestTryBind: tryBind succeeds on a free address and fails on a bound one.
func TestTryBind(t *testing.T) {
	if err := tryBind("127.0.0.1:0"); err != nil {
		t.Fatalf("tryBind on ephemeral port failed: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := tryBind(ln.Addr().String()); err == nil {
		t.Fatal("tryBind must fail for an already-bound address")
	}
}

// TestAPISettingsRejectsUnbindable: persisting a listen address that cannot
// be bound must be rejected with 400 (it would crash-loop on restart).
func TestAPISettingsRejectsUnbindable(t *testing.T) {
	srv, _, tok := newAdminTest(t)
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	addr := blocked.Addr().String()

	// Change only the admin address to the occupied port: must be 400.
	st, body := adminDo(t, srv, tok, "PUT", "/admin/api/settings", map[string]any{
		"proxy": map[string]any{
			"enabled": true, "listen_addr": ":1", "admin_listen_addr": addr,
			"require_auth": true, "allow_http": true, "allow_https": true,
			"connect_timeout_sec": 15, "read_timeout_sec": 300,
			"default_max_conns": 25, "max_global_conns": 0,
		},
		"logs": map[string]any{"ring_size": 20000, "file_max_mb": 0, "to_file": false},
	})
	if st != 400 {
		t.Fatalf("unbindable admin address: %d %v (want 400)", st, body)
	}
	// Saving the current addresses unchanged is fine (bind check skipped).
	st, _ = adminDo(t, srv, tok, "PUT", "/admin/api/settings", map[string]any{
		"proxy": map[string]any{
			"enabled": true, "listen_addr": ":1", "admin_listen_addr": ":1",
			"require_auth": true, "allow_http": true, "allow_https": true,
			"connect_timeout_sec": 15, "read_timeout_sec": 300,
			"default_max_conns": 25, "max_global_conns": 0,
		},
		"logs": map[string]any{"ring_size": 20000, "file_max_mb": 0, "to_file": false},
	})
	if st != 200 {
		t.Fatalf("saving current addresses should succeed: %d", st)
	}
}

func mustUser(name, pass string) *User {
	u, err := NewUser(name, pass, "user")
	if err != nil {
		panic(err)
	}
	return u
}

// TestAPILogsClear: DELETE /admin/api/logs empties the activity log and
// requires admin credentials.
func TestAPILogsClear(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	srv := httptest.NewServer(p.AdminHandler())
	t.Cleanup(func() {
		srv.Close()
		p.Shutdown()
	})
	tok, err := issueToken(store.Config().SessionKey, "admin", time.Hour, store.FindUserByName("admin").TokenEpoch)
	if err != nil {
		t.Fatal(err)
	}
	// No auth: the endpoint must be admin-gated.
	req, _ := http.NewRequest("DELETE", srv.URL+"/admin/api/logs", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated DELETE logs = %d, want 401", resp.StatusCode)
	}

	// Populate the ring, then clear via the API.
	p.logs.Add(LogEntry{Time: "2026-01-01T00:00:00Z", User: "alice", Method: "GET", Host: "a.com", Outcome: "ALLOWED", Status: 200})
	if got := len(p.logs.Recent(100, "", "")); got != 1 {
		t.Fatalf("expected 1 entry, got %d", got)
	}
	st, body := adminDo(t, srv, tok, "DELETE", "/admin/api/logs", nil)
	if st != 200 {
		t.Fatalf("DELETE logs: %d %v (want 200)", st, body)
	}
	if got := len(p.logs.Recent(100, "", "")); got != 0 {
		t.Fatalf("ring not empty after API clear: %d entries", got)
	}
	// Logging continues afterwards.
	p.logs.Add(LogEntry{Time: "2026-01-01T00:00:01Z", User: "bob", Method: "GET", Host: "b.com", Outcome: "ALLOWED", Status: 200})
	if got := len(p.logs.Recent(100, "", "")); got != 1 {
		t.Fatalf("logging after clear broken: %d entries", got)
	}
}

// ---- 1.0.8: batch A/B/C ----

// TestForwardByteTransparent: with DisableCompression the proxy must pass
// upstream response bytes (and their Content-Encoding header) through
// untouched, never transparently decompressing.
func TestForwardByteTransparent(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef}) // fake gzip magic
			return
		}
		w.Write([]byte("plain"))
	}))
	defer origin.Close()

	p, _ := newProxyOnEphemeral(t)
	req := httptest.NewRequest("GET", origin.URL+"/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	if got := w.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip (byte-transparent)", got)
	}
	if body := w.Body.Bytes(); !bytes.Equal(body, []byte{0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("body was rewritten (transparent decompression?): %x", body)
	}
}

// TestSettingsMergeSemantics: a partial settings PUT must only touch the
// fields it sends; omitted fields must stay unchanged.
func TestSettingsMergeSemantics(t *testing.T) {
	srv, store, tok := newAdminTest(t)
	before := store.Config()

	st, body := adminDo(t, srv, tok, "PUT", "/admin/api/settings", map[string]any{
		"logs": map[string]any{"ring_size": 500},
	})
	if st != 200 {
		t.Fatalf("partial PUT: %d %v (want 200)", st, body)
	}
	after := store.Config()
	if after.Logs.RingSize != 500 {
		t.Fatalf("ring_size = %d, want 500", after.Logs.RingSize)
	}
	if after.Proxy.ListenAddr != before.Proxy.ListenAddr ||
		after.Proxy.Enabled != before.Proxy.Enabled ||
		after.Proxy.RequireAuth != before.Proxy.RequireAuth {
		t.Fatalf("omitted proxy settings were clobbered: %+v", after.Proxy)
	}
	if after.Logs.FileMaxMB != before.Logs.FileMaxMB || after.Logs.ToFile != before.Logs.ToFile {
		t.Fatalf("omitted log settings were clobbered: %+v", after.Logs)
	}
	// A PUT with neither proxy nor logs is rejected.
	st, _ = adminDo(t, srv, tok, "PUT", "/admin/api/settings", map[string]any{})
	if st != 400 {
		t.Fatalf("empty PUT: %d (want 400)", st)
	}
}

// TestAdminBodyLimit: oversized admin request bodies are rejected.
func TestAdminBodyLimit(t *testing.T) {
	srv, _, tok := newAdminTest(t)
	big := strings.Repeat("x", 2<<20)
	st, body := adminDo(t, srv, tok, "POST", "/admin/api/users", map[string]any{
		"username": "bob", "password": big, "role": "user",
	})
	if st != 400 {
		t.Fatalf("oversized body: %d %v (want 400)", st, body)
	}
}

// TestAuditLog: admin actions are recorded in the audit log (which survives
// activity-log clears), and are readable via /admin/api/audit.
func TestAuditLog(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	srv := httptest.NewServer(p.AdminHandler())
	t.Cleanup(func() {
		srv.Close()
		p.Shutdown()
	})
	tok, err := issueToken(store.Config().SessionKey, "admin", time.Hour, store.FindUserByName("admin").TokenEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := adminDo(t, srv, tok, "POST", "/admin/api/users", map[string]any{
		"username": "alice", "password": "alicepw123", "role": "user",
	}); st != 201 {
		t.Fatalf("create user: %d", st)
	}
	// Record a log clear too.
	p.logs.Add(LogEntry{Time: "2026-01-01T00:00:00Z", User: "alice", Method: "GET", Host: "a.com", Outcome: "ALLOWED", Status: 200})
	if st, _ := adminDo(t, srv, tok, "DELETE", "/admin/api/logs", nil); st != 200 {
		t.Fatalf("clear logs: %d", st)
	}

	// Audit must contain user.create and logs.clear even though the
	// activity log is now empty.
	req, _ := http.NewRequest("GET", srv.URL+"/admin/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var entries []AuditEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	for _, want := range []string{"user.create", "logs.clear"} {
		if !slices.Contains(actions, want) {
			t.Fatalf("audit missing %q; got %v", want, actions)
		}
	}
	if got := len(p.logs.Recent(100, "", "")); got != 0 {
		t.Fatalf("activity log should be empty after clear, got %d", got)
	}
}

// TestSessionInvalidatedOnPasswordChange: tokens carry the user's token
// epoch, so a password change immediately revokes previously issued sessions.
func TestSessionInvalidatedOnPasswordChange(t *testing.T) {
	srv, store, tok := newAdminTest(t)
	status := func(header string) int {
		req, _ := http.NewRequest("GET", srv.URL+"/admin/api/status", nil)
		req.Header.Set("Authorization", header)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := status("Bearer " + tok); got != 200 {
		t.Fatalf("token should work before password change: %d", got)
	}
	adminID := store.FindUserByName("admin").ID
	st, body := adminDo(t, srv, tok, "POST", "/admin/api/users/"+adminID+"/password", map[string]any{"password": "newpass456"})
	if st != 200 {
		t.Fatalf("password change: %d %v", st, body)
	}
	if got := status("Bearer " + tok); got != http.StatusUnauthorized {
		t.Fatalf("old token must be rejected after password change: %d", got)
	}
	// A fresh login works and yields a valid token.
	newTok := loginToken(t, srv, "admin", "newpass456")
	if got := status("Bearer " + newTok); got != 200 {
		t.Fatalf("fresh token after password change must work: %d", got)
	}
}

// TestAccountLoginThrottle: the per-account limiter (exercised directly —
// through a real HTTP server every request arrives from the same TCP peer
// IP, so the per-IP limiter would mask the account-level behavior).
func TestAccountLoginThrottle(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	if !p.accountAllowed("admin") {
		t.Fatal("fresh account must be allowed")
	}
	for i := 0; i < loginMaxFails; i++ {
		p.accountFail("admin")
	}
	if p.accountAllowed("admin") {
		t.Fatal("account must be locked after 10 failures")
	}
	if !p.accountAllowed("carol") {
		t.Fatal("a different account must be unaffected")
	}
	p.accountOK("admin")
	if !p.accountAllowed("admin") {
		t.Fatal("accountOK must clear the lockout")
	}
	// HTTP-level sanity: 10 wrong logins then a correct one is 429 (both
	// the per-IP and per-account limiters are armed; the TCP peer is the
	// same 127.0.0.1 for every request).
	srv := httptest.NewServer(p.AdminHandler())
	t.Cleanup(func() {
		srv.Close()
		p.Shutdown()
	})
	login := func(pass string) int {
		body, _ := json.Marshal(map[string]string{"username": "admin", "password": pass})
		req, _ := http.NewRequest("POST", srv.URL+"/admin/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < loginMaxFails; i++ {
		if got := login("wrong-pass"); got != 401 {
			t.Fatalf("failure %d: %d (want 401)", i+1, got)
		}
	}
	if got := login("admin123"); got != http.StatusTooManyRequests {
		t.Fatalf("locked login: %d (want 429)", got)
	}
}

// TestAdminTLSOptional: when TLS_CERT_FILE/TLS_KEY_FILE are set, the admin
// listener serves HTTPS; without them it stays plaintext.
func TestAdminTLSOptional(t *testing.T) {
	certFile, keyFile := makeTestCert(t)
	t.Setenv("TLS_CERT_FILE", certFile)
	t.Setenv("TLS_KEY_FILE", keyFile)

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(c *Config) error {
		c.Proxy.ListenAddr = "127.0.0.1:0"
		c.Proxy.AdminListenAddr = "127.0.0.1:0"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	p.OnConfigChanged(store.Config())
	if err := p.Start(store.Config()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Shutdown)
	addr := p.ListenerAddr("admin")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + addr + "/admin/healthz")
	if err != nil {
		t.Fatalf("https admin request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("https healthz = %d, want 200", resp.StatusCode)
	}
	// Plain http on the TLS listener must NOT serve the admin API (Go
	// answers plaintext-on-TLS with 400 "Client sent an HTTP request to an
	// HTTPS server", never with the API content).
	if resp, err := http.Get("http://" + addr + "/admin/healthz"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("plaintext http served the admin API on the TLS listener")
		}
	}
}

func makeTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// ---- 1.0.9: admin-Basic throttle, user index, config backup, reset, cookie ----

// TestAdminAPIBasicThrottle: Basic credentials on the admin API are limited
// per IP and per account — after 10 failures a correct password gets 429,
// and clearing the state restores access. (Every test request arrives from
// the same 127.0.0.1 TCP peer, so both limiters are armed.)
func TestAdminAPIBasicThrottle(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, t.TempDir())
	srv := httptest.NewServer(p.AdminHandler())
	t.Cleanup(func() {
		srv.Close()
		p.Shutdown()
	})
	status := func(user, pass string) int {
		req, _ := http.NewRequest("GET", srv.URL+"/admin/api/status", nil)
		req.SetBasicAuth(user, pass)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Failures 1..10 are plain 401s; the 10th arms the account lockout.
	for i := 0; i < loginMaxFails; i++ {
		if got := status("admin", "wrong-pass"); got != 401 {
			t.Fatalf("failure %d: %d (want 401)", i+1, got)
		}
	}
	// Correct password while locked out: 429 (account-level lockout).
	if got := status("admin", "admin123"); got != http.StatusTooManyRequests {
		t.Fatalf("correct password during lockout: %d (want 429)", got)
	}
	// Cookie sessions are unaffected by the Basic limiter.
	tok, err := issueToken(store.Config().SessionKey, "admin", time.Hour, store.FindUserByName("admin").TokenEpoch)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/admin/api/status", nil)
	req.AddCookie(&http.Cookie{Name: "fpx_session", Value: tok})
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("cookie session during Basic lockout: %d (want 200)", resp.StatusCode)
	}
	// Clearing the state restores Basic access.
	p.proxyAuthOK("127.0.0.1")
	p.accountOK("admin")
	if got := status("admin", "admin123"); got != 200 {
		t.Fatalf("Basic auth after clearing state: %d (want 200)", got)
	}
}

// TestUserIndex: the O(1) lookup index stays consistent across creates,
// renames (including case changes), and deletes.
func TestUserIndex(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Update(func(c *Config) error {
		c.Users = append(c.Users, *mustUser("alice", "pw123456"), *mustUser("bob", "pw123456"))
		return nil
	})
	if u := store.FindUserByName("ALICE"); u == nil || u.Username != "alice" {
		t.Fatalf("FindUserByName(ALICE) = %+v", u)
	}
	alice := store.FindUserByName("alice")
	if store.FindUser(alice.ID) == nil {
		t.Fatal("FindUser by id must find alice")
	}
	// Rename bob -> robert; the old name must no longer resolve, the new
	// one must (case-insensitively).
	bob := store.FindUserByName("bob")
	if err := store.Update(func(c *Config) error {
		for i := range c.Users {
			if c.Users[i].ID == bob.ID {
				c.Users[i].Username = "robert"
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if store.FindUserByName("bob") != nil {
		t.Fatal("old name must no longer resolve after rename")
	}
	if u := store.FindUserByName("ROBERT"); u == nil || u.Username != "robert" {
		t.Fatalf("new name must resolve case-insensitively: %+v", u)
	}
	// Delete alice; lookups must miss.
	if err := store.Update(func(c *Config) error {
		for i := range c.Users {
			if c.Users[i].ID == alice.ID {
				c.Users = append(c.Users[:i], c.Users[i+1:]...)
				return nil
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if store.FindUser(alice.ID) != nil || store.FindUserByName("alice") != nil {
		t.Fatal("deleted user must not be found")
	}
}

// TestConfigBackup: every save keeps a parseable config.json.bak holding the
// previous config.
func TestConfigBackup(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := store.Update(func(c *Config) error {
		c.Proxy.ListenAddr = ":4123"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	var prev Config
	if err := json.Unmarshal(bak, &prev); err != nil {
		t.Fatalf("config.json.bak is not valid JSON: %v", err)
	}
	// The backup predates the update: it must still have the old address.
	if prev.Proxy.ListenAddr == ":4123" {
		t.Fatal("backup should hold the pre-update config")
	}
}

// TestDailyReset: resetDaily clears the counter immediately and an
// exceeded daily cap becomes usable again; the API endpoint is audited.
func TestDailyReset(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Update(func(c *Config) error {
		c.Users = append(c.Users, *mustUser("carol", "secret123"))
		c.Users[len(c.Users)-1].DailyTrafficMB = 1
		return nil
	})
	p := NewProxy(store, t.TempDir())
	carol := store.FindUserByName("carol")
	cfg := store.Config()

	// Fill 2 MiB: the cap (1 MB) is exceeded → denied.
	p.addDaily(carol.ID, 2*1024*1024)
	if st, _ := p.checkAccess(carol, cfg, "example.com"); st == 0 {
		t.Fatal("daily cap must deny after 2 MiB used with a 1 MB cap")
	}

	// API-level reset (admin) clears it.
	srv := httptest.NewServer(p.AdminHandler())
	t.Cleanup(func() {
		srv.Close()
		p.Shutdown()
	})
	tok, err := issueToken(store.Config().SessionKey, "admin", time.Hour, store.FindUserByName("admin").TokenEpoch)
	if err != nil {
		t.Fatal(err)
	}
	st, body := adminDo(t, srv, tok, "POST", "/admin/api/users/"+carol.ID+"/reset", nil)
	if st != 200 {
		t.Fatalf("reset: %d %v (want 200)", st, body)
	}
	if st, _ := p.checkAccess(carol, cfg, "example.com"); st != 0 {
		t.Fatal("access must be allowed again after the reset")
	}
	// The action is audited.
	req, _ := http.NewRequest("GET", srv.URL+"/admin/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var entries []AuditEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "user.reset" && strings.Contains(e.Detail, "carol") {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit missing user.reset for carol: %+v", entries)
	}
}

// TestSecureCookieUnderTLS: the session cookie carries Secure only when the
// admin connection is TLS.
func TestSecureCookieUnderTLS(t *testing.T) {
	login := func(srv *httptest.Server) bool {
		resp, err := http.Post(srv.URL+"/admin/api/login", "application/json",
			strings.NewReader(`{"username":"admin","password":"admin123"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		for _, c := range resp.Cookies() {
			if c.Name == "fpx_session" {
				return c.Secure
			}
		}
		return false
	}
	store, _ := NewStore(t.TempDir())
	p := NewProxy(store, t.TempDir())

	plain := httptest.NewServer(p.AdminHandler())
	defer plain.Close()
	if login(plain) {
		t.Fatal("plaintext admin must not set a Secure cookie")
	}

	tlsSrv := httptest.NewTLSServer(p.AdminHandler())
	defer tlsSrv.Close()
	client := tlsSrv.Client()
	resp, err := client.Post(tlsSrv.URL+"/admin/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"admin123"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	secure := false
	for _, c := range resp.Cookies() {
		if c.Name == "fpx_session" && c.Secure {
			secure = true
		}
	}
	if !secure {
		t.Fatal("TLS admin must set a Secure cookie")
	}
}

// ---- 1.0.10: config export / import ----

func exportSnapshot(t *testing.T, srv *httptest.Server, tok string) configExport {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+"/admin/api/export", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("export: %d", resp.StatusCode)
	}
	var exp configExport
	if err := json.NewDecoder(resp.Body).Decode(&exp); err != nil {
		t.Fatal(err)
	}
	return exp
}

func importSnapshot(t *testing.T, srv *httptest.Server, tok string, exp any) (int, map[string]any) {
	t.Helper()
	return adminDo(t, srv, tok, "POST", "/admin/api/import", exp)
}

// TestExportImportRoundtrip: export → modify → import → the live config
// matches, the session key is untouched, and the action is audited.
func TestExportImportRoundtrip(t *testing.T) {
	srv, store, tok := newAdminTest(t)
	// Build a non-trivial config: a second user, global rules, log settings.
	if st, _ := adminDo(t, srv, tok, "POST", "/admin/api/users", map[string]any{
		"username": "alice", "password": "alicepw123", "role": "user",
	}); st != 201 {
		t.Fatalf("create alice: %d", st)
	}
	if st, _ := adminDo(t, srv, tok, "PUT", "/admin/api/global-rules", map[string]any{
		"whitelist_only": true, "whitelist": []string{"good.example.com"}, "blacklist": []string{},
	}); st != 200 {
		t.Fatalf("rules: %d", st)
	}
	if st, _ := adminDo(t, srv, tok, "PUT", "/admin/api/settings", map[string]any{
		"logs": map[string]any{"ring_size": 5000, "file_max_mb": 0, "to_file": false},
	}); st != 200 {
		t.Fatalf("settings: %d", st)
	}
	keyBefore := store.Config().SessionKey

	exp := exportSnapshot(t, srv, tok)
	// Mutate the snapshot: rename alice, tweak settings.
	for i := range exp.Users {
		if exp.Users[i].Username == "alice" {
			exp.Users[i].Username = "alice2"
		}
	}
	exp.Logs.RingSize = 7000
	exp.Proxy.ReadTimeoutSec = 120

	st, body := importSnapshot(t, srv, tok, exp)
	if st != 200 {
		t.Fatalf("import: %d %v", st, body)
	}
	cfg := store.Config()
	if cfg.Logs.RingSize != 7000 || cfg.Proxy.ReadTimeoutSec != 120 {
		t.Fatalf("imported settings not applied: ring=%d rt=%d", cfg.Logs.RingSize, cfg.Proxy.ReadTimeoutSec)
	}
	if !cfg.GlobalRules.WhitelistOnly || len(cfg.GlobalRules.Whitelist) != 1 {
		t.Fatalf("imported rules not applied: %+v", cfg.GlobalRules)
	}
	if store.FindUserByName("alice") != nil || store.FindUserByName("alice2") == nil {
		t.Fatal("imported users not applied correctly")
	}
	if cfg.SessionKey != keyBefore {
		t.Fatal("import must never replace the session key")
	}

	// Audit trail contains the import.
	req, _ := http.NewRequest("GET", srv.URL+"/admin/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var entries []AuditEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	imported := false
	for _, e := range entries {
		if e.Action == "config.import" {
			imported = true
		}
	}
	if !imported {
		t.Fatal("audit missing config.import")
	}

	// Export after import reflects the imported state.
	exp2 := exportSnapshot(t, srv, tok)
	if exp2.Logs.RingSize != 7000 {
		t.Fatalf("re-export ring=%d, want 7000", exp2.Logs.RingSize)
	}
}

// TestImportValidation: malformed or unsafe snapshots are rejected with 400
// and leave the live config untouched.
func TestImportValidation(t *testing.T) {
	srv, store, tok := newAdminTest(t)
	base := exportSnapshot(t, srv, tok)

	cases := []struct {
		name string
		mut  func(*configExport)
	}{
		{"no enabled admin", func(e *configExport) {
			for i := range e.Users {
				e.Users[i].Role = "user"
			}
		}},
		{"invalid listen addr", func(e *configExport) { e.Proxy.ListenAddr = "not-an-address" }},
		{"invalid ring size", func(e *configExport) { e.Logs.RingSize = 5 }},
		{"invalid password hash", func(e *configExport) {
			e.Users[0].PasswordHash = "plaintext"
		}},
		{"duplicate usernames", func(e *configExport) {
			e.Users = append(e.Users, e.Users[0])
		}},
		{"invalid whitelist pattern", func(e *configExport) {
			e.GlobalRules.Whitelist = []string{"http://bad"}
		}},
	}
	before := store.Config()
	for _, tc := range cases {
		exp := base
		exp.Users = append([]User(nil), base.Users...)
		tc.mut(&exp)
		st, _ := importSnapshot(t, srv, tok, exp)
		if st != 400 {
			t.Fatalf("%s: import = %d, want 400", tc.name, st)
		}
	}
	// Invalid JSON body.
	req, _ := http.NewRequest("POST", srv.URL+"/admin/api/import", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("invalid JSON import = %d, want 400", resp.StatusCode)
	}
	// Unbindable address (occupied port) is rejected.
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	exp := base
	exp.Proxy.AdminListenAddr = blocked.Addr().String()
	if st, _ := importSnapshot(t, srv, tok, exp); st != 400 {
		t.Fatalf("unbindable admin addr import = %d, want 400", st)
	}
	// The live config is untouched by all the rejected imports.
	after := store.Config()
	if after.Logs.RingSize != before.Logs.RingSize || len(after.Users) != len(before.Users) {
		t.Fatal("rejected imports must not change the live config")
	}

	// Importing a snapshot without the current admin warns but succeeds
	// when another enabled admin exists.
	exp2 := base
	exp2.Users = append([]User(nil), base.Users...)
	for i := range exp2.Users {
		if exp2.Users[i].Username == "admin" {
			exp2.Users[i].Username = "boss"
		}
	}
	st, body := importSnapshot(t, srv, tok, exp2)
	if st != 200 {
		t.Fatalf("admin-renaming import: %d %v", st, body)
	}
	warns, _ := body["warnings"].([]any)
	if len(warns) == 0 {
		t.Fatal("expected a warning when the current admin loses access")
	}
}

// ---- 1.0.11: security fixes ----

// TestAuthTimingEqualization: the dummy PBKDF2 must run only when a username
// does not resolve to an enabled user, so unknown / disabled / wrong-password
// all cost about one KDF (verified structurally via the verify cache).
func TestAuthTimingEqualization(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Update(func(c *Config) error {
		disabled := *mustUser("oldcarol", "pw123456")
		disabled.Enabled = false
		c.Users = append(c.Users, disabled)
		return nil
	})
	p := NewProxy(store, t.TempDir())
	dummy := p.getDummyHash()
	if dummy == "" {
		t.Fatal("dummy hash must exist")
	}
	hasCacheKey := func(pw string) bool {
		key := dummy + "\x00\x00" + pw
		store.authCacheMu.Lock()
		defer store.authCacheMu.Unlock()
		_, ok := store.authCache[key]
		return ok
	}
	// Known + enabled user: the real verify already paid; no dummy entry.
	p.equalizeAuthTiming("admin", "known-wrong-pw")
	if hasCacheKey("known-wrong-pw") {
		t.Fatal("dummy PBKDF2 must not run for a known enabled user")
	}
	// Unknown and disabled users: the dummy runs (entry cached).
	p.equalizeAuthTiming("nosuchuser", "unknown-pw")
	if !hasCacheKey("unknown-pw") {
		t.Fatal("dummy PBKDF2 must run for an unknown user")
	}
	p.equalizeAuthTiming("oldcarol", "disabled-pw")
	if !hasCacheKey("disabled-pw") {
		t.Fatal("dummy PBKDF2 must run for a disabled user")
	}
}

// TestPBKDF2Iterations: new hashes use the current iteration count and older
// hashes (with their own embedded count) keep verifying.
func TestPBKDF2Iterations(t *testing.T) {
	h, err := HashPassword("s3cret-pw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, fmt.Sprintf("pbkdf2$%d$", pbkdf2Iterations)) {
		t.Fatalf("new hash must embed %d iterations, got %q", pbkdf2Iterations, h[:20])
	}
	if !VerifyPassword(h, "s3cret-pw") {
		t.Fatal("roundtrip verify failed")
	}
	// Backward compatibility: a hash created with the old iteration count
	// (210k) must still verify.
	salt := []byte("0123456789abcdef")
	dk := pbkdf2SHA256([]byte("oldpw"), salt, 210000, pbkdf2KeyLen)
	old := fmt.Sprintf("pbkdf2$210000$%x$%x", salt, dk)
	if !VerifyPassword(old, "oldpw") {
		t.Fatal("old-format hash must still verify")
	}
	if VerifyPassword(old, "wrongpw") {
		t.Fatal("old-format hash must reject a wrong password")
	}
}

// TestCSRFOrigin: state-changing admin requests with a mismatched Origin are
// rejected; read-only requests, no-Origin requests, and matching-Origin
// requests are unaffected.
func TestCSRFOrigin(t *testing.T) {
	srv, _, tok := newAdminTest(t)
	do := func(method, path, origin string, withTok bool) int {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if withTok {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	evil := "https://evil.example"
	// Cross-origin state changes are rejected (with or without auth).
	if got := do("POST", "/admin/api/logout", evil, false); got != http.StatusForbidden {
		t.Fatalf("cross-origin logout = %d, want 403", got)
	}
	if got := do("DELETE", "/admin/api/logs", evil, true); got != http.StatusForbidden {
		t.Fatalf("cross-origin DELETE logs = %d, want 403", got)
	}
	if got := do("POST", "/admin/api/import", evil, true); got != http.StatusForbidden {
		t.Fatalf("cross-origin import = %d, want 403", got)
	}
	// Read-only requests are always allowed.
	if got := do("GET", "/admin/api/status", evil, true); got != 200 {
		t.Fatalf("cross-origin GET status = %d, want 200", got)
	}
	// No Origin (curl / non-browser) is unaffected.
	if got := do("POST", "/admin/api/logout", "", false); got != 200 {
		t.Fatalf("no-origin logout = %d, want 200", got)
	}
	// Matching Origin (same host:port) is allowed.
	if got := do("POST", "/admin/api/logout", srv.URL, false); got != 200 {
		t.Fatalf("same-origin logout = %d, want 200", got)
	}
}
