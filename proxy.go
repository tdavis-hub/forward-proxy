package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Version is the proxy build version.
// 1.0.4 — bug fixes: daily traffic limits reset again at UTC midnight (stale
// counters were reused, permanently locking out users once a limit was hit);
// connection caps are enforced atomically (no overshoot under races) and
// denials are sent before the connection is hijacked; CONNECT: pipelined
// bytes sent after the request headers (e.g. first TLS ClientHello bytes)
// are forwarded to the upstream instead of dropped, hosts are normalized
// (brackets, missing ports) so IPv6 and "host:" targets work; forwarded
// requests now cancel upstream on client disconnect (r.Clone inherits the
// request context); non-http absolute-form URLs are rejected with 400;
// tunnels apply idle deadlines to the write side too (no leaked tunnels);
// the outbound transport is only rebuilt when the connect timeout changes
// (upstream keepalive pools survive config edits).
// 1.0.5 — clearer error reporting: when a target hostname resolves only to a
// DNS sinkhole address (0.0.0.0 / :: — how DNS filters and ad-blockers block
// domains), failed dials now say so explicitly instead of the misleading
// "dial tcp 0.0.0.0:443: connect: connection refused".
// 1.0.6 — performance & reliability: PBKDF2 verification results are cached
// (bounded, TTL'd, keyed by stored hash so password changes invalidate
// immediately), turning the ~170ms per-request auth cost into a one-time cost
// per credential and removing the ~6 req/s/core ceiling; failed proxy-port
// authentications are rate-limited per client IP (30 fails / 10 min → 60 s
// cooldown) with PBKDF2 timing equalization for the username-existence
// oracle, and both per-IP failure maps are pruned periodically (no unbounded
// growth); the "default password" badge is memoized per (user, hash) instead
// of re-hashing on every status/users API call; the 5s stats flush no longer
// recompiles all rules (UpdateSilent) and request byte counting is race-free
// (atomic counter); settings saves reject listen addresses that cannot be
// bound, so a bad address can no longer crash-loop the container on restart;
// activity-log text search works again (Recent query filter bug).
// 1.0.7 — feature: the admin activity-log page has a "Clear log" button
// (DELETE /admin/api/logs) that empties the in-memory ring and truncates the
// JSONL file; user stats are unaffected.
// 1.0.8 — perf & hardening batch: proxied responses are streamed (flushed
// per chunk) and forwarded byte-transparently (no transparent gzip);
// duplicate usernames are rejected case-insensitively; log file writes are
// buffered (periodic flush) with one-shot failure warnings and cached parsed
// timestamps; the shared config mutex is split into per-domain mutexes;
// admin actions are recorded in an append-only audit log (audit.log +
// /admin/api/audit + UI view) that survives activity-log clears; admin
// sessions are invalidated on password change (token epoch); the admin
// listener can be wrapped in TLS via TLS_CERT_FILE/TLS_KEY_FILE (healthcheck
// now uses the proxy port); login attempts are throttled per account as well
// as per IP; settings PUT applies merge semantics (partial updates no longer
// zero omitted fields) and all admin bodies are size-limited.
// 1.0.9 — admin-API Basic credentials are now throttled per IP and per
// account (closing the last unthrottled PBKDF2/brute-force surface), with
// timing equalization; users are looked up through an O(1) index rebuilt on
// config changes; every config save keeps a config.json.bak; a "Reset"
// button clears a user's daily traffic counter immediately (audited); the
// admin session cookie gets the Secure flag when the listener is TLS; the
// dashboard auto-refreshes every 30 s without a loading flash; fuzz targets
// were added for the parsers. The live container is deployed pinned to the
// version tag with a restart policy.
// 1.0.10 — config export/import: GET /admin/api/export streams a full
// snapshot (users with password hashes, global rules, proxy + log settings;
// the session key is never exported), and POST /admin/api/import restores
// one after strict validation (addresses, ranges, unique IDs/usernames,
// valid patterns and password-hash formats, at least one enabled admin,
// bindability of changed addresses) with atomic rollback and an audit
// record; the Settings UI gains a Backup / restore panel.
// 1.0.11 — security fixes from the sweep: the user-existence timing oracle
// is closed (the dummy PBKDF2 now runs only when a username does not resolve
// to an enabled user, so unknown / disabled / wrong-password all cost ~one
// KDF on all three auth paths); PBKDF2 iterations for new hashes are raised
// to 600k per OWASP guidance (old hashes keep their embedded count); admin
// state-changing requests are rejected when their Origin header does not
// match the request host (server-side CSRF defense beyond SameSite=Lax).
const Version = "1.0.11"

var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailers", "Trailer", "Transfer-Encoding", "Upgrade",
}

// liveStats keeps fast in-memory per-user counters, flushed to disk periodically.
type liveStats struct {
	mu       sync.Mutex
	requests map[string]uint64
	bytesIn  map[string]uint64
	bytesOut map[string]uint64
	lastUsed map[string]time.Time
}

func newLiveStats() *liveStats {
	return &liveStats{
		requests: map[string]uint64{},
		bytesIn:  map[string]uint64{},
		bytesOut: map[string]uint64{},
		lastUsed: map[string]time.Time{},
	}
}

func (l *liveStats) add(uid string, in, out uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if uid == "" {
		return
	}
	l.requests[uid] += 1
	l.bytesIn[uid] += in
	l.bytesOut[uid] += out
	l.lastUsed[uid] = time.Now().UTC()
}

type dailyTraffic struct {
	date  string
	bytes uint64
}

// loginFails tracks failed admin logins per client IP for rate limiting.
type loginFails struct {
	count  int
	window time.Time // start of the current failure window
	until  time.Time // lockout expiry; zero means not locked out
}

// Proxy is the forward proxy server.
type Proxy struct {
	store     *Store
	rules     *RulesEngine
	logs      *LogStore
	audit     *AuditLog
	transport *http.Transport
	live      *liveStats

	bindMu      sync.Mutex // guards listener state (servers, listeners, addrs)
	connMu      sync.Mutex // guards userConns map
	dailyMu     sync.Mutex // guards daily traffic map
	proxySrv    *http.Server
	adminSrv    *http.Server
	adminTLS    *tls.Config // optional TLS for the admin listener (env certs)
	proxyLn     net.Listener
	adminLn     net.Listener
	proxyAddr   string
	adminAddr   string
	userConns   map[string]*atomic.Int32
	globalConns atomic.Int32
	daily       map[string]*dailyTraffic

	connectTimeoutSec int // last applied connect timeout; skips transport rebuilds

	loginMu       sync.Mutex
	loginFails    map[string]*loginFails
	accountFails  map[string]*loginFails // per-username login throttling
	dummyHash     string                 // lazy PBKDF2 hash for timing equalization
	dummyHashOnce sync.Once

	// proxyAuthFails rate-limits failed proxy-port authentications per
	// client IP: reaching proxyMaxFails within proxyFailWindow puts the IP
	// into a short cooldown during which auth requests are rejected before
	// any PBKDF2 work. This caps the CPU cost of credential brute-forcing
	// on the proxy port (which, unlike /admin/api/login, has no lockout of
	// its own) without a full lockout that would break shared-NAT clients.
	proxyAuthMu    sync.Mutex
	proxyAuthFails map[string]*loginFails

	// defaultPass caches "is this user's password the factory default?"
	// per (userID, passwordHash). The hash is part of the key, so password
	// changes invalidate immediately; entries are bounded by user count.
	defaultPassMu    sync.Mutex
	defaultPassCache map[string]bool

	startedAt time.Time
}

// Proxy-port authentication throttling constants. Generous: 30 failed
// attempts from one IP within 10 minutes triggers a 60-second cooldown
// during which further attempts are refused with 429 before any PBKDF2
// verification (legitimate users with correct credentials are unaffected
// unless their shared IP accumulated 30 failures).
const (
	proxyMaxFails   = 30
	proxyFailWindow = 10 * time.Minute
	proxyCooldown   = 60 * time.Second
)

func NewProxy(store *Store, dir string) *Proxy {
	p := &Proxy{
		store:            store,
		rules:            NewRulesEngine(),
		logs:             NewLogStore(store, dir),
		audit:            NewAuditLog(dir),
		live:             newLiveStats(),
		userConns:        map[string]*atomic.Int32{},
		daily:            map[string]*dailyTraffic{},
		loginFails:       map[string]*loginFails{},
		accountFails:     map[string]*loginFails{},
		proxyAuthFails:   map[string]*loginFails{},
		defaultPassCache: map[string]bool{},
		adminTLS:         loadAdminTLS(),
		startedAt:        time.Now(),
	}
	p.applyTransport(store.Config())
	p.rules.Rebuild(store.Config())
	return p
}

// loadAdminTLS builds a TLS config for the admin listener when both
// TLS_CERT_FILE and TLS_KEY_FILE are set (PEM files, e.g. mounted secrets).
// Returns nil (plaintext admin) when either is missing or unreadable.
func loadAdminTLS() *tls.Config {
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile == "" || keyFile == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("WARN: TLS_CERT_FILE/TLS_KEY_FILE set but unusable (%v); admin listener stays plaintext", err)
		return nil
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// OnConfigChanged applies a new config snapshot: transport settings, rule
// recompilation, and listener re-binding when addresses changed.
func (p *Proxy) OnConfigChanged(cfg Config) {
	p.applyTransport(cfg)
	p.rules.Rebuild(cfg)
	p.rebindIfChanged(cfg)
}

func (p *Proxy) applyTransport(cfg Config) {
	connectSec := cfg.Proxy.ConnectTimeoutSec
	if connectSec <= 0 {
		connectSec = 15
	}
	// Rebuilding the transport closes idle upstream connections, so only do
	// it when the connect timeout actually changed.
	if p.transport != nil && connectSec == p.connectTimeoutSec {
		return
	}
	connect := time.Duration(connectSec) * time.Second
	p.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: connect, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		// Byte-transparent: a proxy must pass response bytes through
		// untouched. Without this the transport would transparently
		// decompress upstream gzip and strip Content-Encoding/Length,
		// rewriting what the client receives and costing CPU on both ends.
		DisableCompression: true,
	}
	p.connectTimeoutSec = connectSec
}

// Start binds both listeners and begins serving.
func (p *Proxy) Start(cfg Config) error {
	if err := p.bind("proxy", cfg.Proxy.ListenAddr, p); err != nil {
		return err
	}
	if err := p.bind("admin", cfg.Proxy.AdminListenAddr, p.AdminHandler()); err != nil {
		return err
	}
	return nil
}

func (p *Proxy) bind(kind, addr string, h http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind %s %s: %w", kind, addr, err)
	}
	if kind == "admin" && p.adminTLS != nil {
		ln = tls.NewListener(ln, p.adminTLS)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		// ReadTimeout/WriteTimeout left at 0: CONNECT tunnels are long-lived;
		// per-request timeouts are enforced inside the handlers.
	}
	go func() { _ = srv.Serve(ln) }()
	p.bindMu.Lock()
	if kind == "proxy" {
		p.proxySrv = srv
		p.proxyLn = ln
		p.proxyAddr = addr
	} else {
		p.adminSrv = srv
		p.adminLn = ln
		p.adminAddr = addr
	}
	p.bindMu.Unlock()
	return nil
}

// ListenerAddr returns the resolved (bound) address of the given listener,
// useful when it was started on an ephemeral port.
func (p *Proxy) ListenerAddr(kind string) string {
	p.bindMu.Lock()
	defer p.bindMu.Unlock()
	var ln net.Listener
	if kind == "proxy" {
		ln = p.proxyLn
	} else {
		ln = p.adminLn
	}
	if ln != nil {
		return ln.Addr().String()
	}
	return ""
}

// rebindIfChanged re-creates listeners when their addresses changed in config.
// The previous server is captured before the new bind and shut down
// afterwards, so the new listener is the one that survives and the old port is
// actually released.
func (p *Proxy) rebindIfChanged(cfg Config) {
	p.bindMu.Lock()
	needProxy := cfg.Proxy.ListenAddr != p.proxyAddr
	needAdmin := cfg.Proxy.AdminListenAddr != p.adminAddr
	var oldProxy, oldAdmin *http.Server
	if needProxy {
		oldProxy = p.proxySrv
	}
	if needAdmin {
		oldAdmin = p.adminSrv
	}
	p.bindMu.Unlock()
	if needProxy {
		if err := p.bind("proxy", cfg.Proxy.ListenAddr, p); err != nil {
			log.Printf("WARN: proxy rebind to %s failed: %v (keeping previous listener)", cfg.Proxy.ListenAddr, err)
		} else {
			go p.shutdownServer(oldProxy)
		}
	}
	if needAdmin {
		if err := p.bind("admin", cfg.Proxy.AdminListenAddr, p.AdminHandler()); err != nil {
			log.Printf("WARN: admin rebind to %s failed: %v (keeping previous listener)", cfg.Proxy.AdminListenAddr, err)
		} else {
			go p.shutdownServer(oldAdmin)
		}
	}
}

// shutdownServer gracefully stops a listener server. Connections that are
// still active after the timeout (e.g. long-lived CONNECT tunnels) are cut.
func (p *Proxy) shutdownServer(s *http.Server) {
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Shutdown(ctx)
}

// Shutdown stops both servers and flushes pending stats.
func (p *Proxy) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p.bindMu.Lock()
	ps, as := p.proxySrv, p.adminSrv
	p.bindMu.Unlock()
	if ps != nil {
		_ = ps.Shutdown(ctx)
	}
	if as != nil {
		_ = as.Shutdown(ctx)
	}
	p.FlushStats()
	p.logs.Flush()
}

// ServeHTTP dispatches proxy traffic on the proxy port.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if r.URL == nil || !r.URL.IsAbs() {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(200)
			w.Write([]byte("ok"))
		case "", "/":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, "forward-proxy v"+Version+" is listening. This is a forward proxy: clients must send absolute-form URLs (or CONNECT).\n")
		default:
			p.deny(w, r, 400, "absolute-form request URI required for proxying")
		}
		return
	}
	p.handleForward(w, r)
}

func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authorize resolves the caller identity for a proxied request.
// Returns (user, ok, httpStatus, reason). user may be nil for anonymous access.
func (p *Proxy) authorize(r *http.Request, clientIP string) (*User, bool, int, string) {
	cfg := p.store.Config()
	if !cfg.Proxy.RequireAuth {
		return nil, true, 0, ""
	}
	// Proxies are authenticated with Proxy-Authorization; accept
	// Authorization as a fallback for clients that use it instead.
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		authHeader = r.Header.Get("Authorization")
	}
	// Throttle before any PBKDF2 work: an IP that has accumulated many
	// recent failures is refused cheaply, so credential brute-forcing
	// cannot saturate CPU. Verified credentials reset the failure count.
	if !p.proxyAuthAllowed(clientIP) {
		return nil, false, http.StatusTooManyRequests, "too many failed authentication attempts from this address, try again shortly"
	}
	user := p.store.checkBasicAuth(authHeader)
	if user == nil {
		name := basicUserName(authHeader)
		p.proxyAuthFail(clientIP)
		// Timing equalization: close the user-existence oracle on the
		// proxy port (unknown / disabled / wrong-password all cost ~one
		// PBKDF2; results are cached so repeated probes stay cheap).
		p.equalizeAuthTiming(name, basicPassword(authHeader))
		return nil, false, http.StatusProxyAuthRequired, "authentication required: invalid or missing credentials" + userNameHint(name)
	}
	p.proxyAuthOK(clientIP)
	return user, true, 0, ""
}

// proxyAuthAllowed reports whether a proxied-auth attempt from clientIP may
// proceed (the IP is not currently in cooldown). Expired state is cleaned up.
func (p *Proxy) proxyAuthAllowed(clientIP string) bool {
	now := time.Now()
	p.proxyAuthMu.Lock()
	defer p.proxyAuthMu.Unlock()
	f := p.proxyAuthFails[clientIP]
	if f == nil {
		return true
	}
	if !f.until.IsZero() {
		if now.Before(f.until) {
			return false
		}
		delete(p.proxyAuthFails, clientIP) // cooldown expired
		return true
	}
	if now.Sub(f.window) > proxyFailWindow {
		delete(p.proxyAuthFails, clientIP) // failure window elapsed
	}
	return true
}

// proxyAuthFail records a failed proxied-auth attempt from clientIP.
func (p *Proxy) proxyAuthFail(clientIP string) {
	now := time.Now()
	p.proxyAuthMu.Lock()
	defer p.proxyAuthMu.Unlock()
	f := p.proxyAuthFails[clientIP]
	if f == nil || now.Sub(f.window) > proxyFailWindow {
		f = &loginFails{window: now}
		p.proxyAuthFails[clientIP] = f
	}
	f.count++
	if f.count >= proxyMaxFails {
		f.until = now.Add(proxyCooldown)
		f.count = 0
		f.window = now
	}
}

// proxyAuthOK clears any failure/cooldown state for clientIP.
func (p *Proxy) proxyAuthOK(clientIP string) {
	p.proxyAuthMu.Lock()
	delete(p.proxyAuthFails, clientIP)
	p.proxyAuthMu.Unlock()
}

// pruneAuthFailures drops expired per-IP failure entries so the maps stay
// bounded under distributed brute-forcing. Called from FlushStats.
func (p *Proxy) pruneAuthFailures(now time.Time) {
	p.loginMu.Lock()
	for ip, f := range p.loginFails {
		if now.Sub(f.window) > loginFailWindow {
			delete(p.loginFails, ip)
		}
	}
	for name, f := range p.accountFails {
		if now.Sub(f.window) > loginFailWindow {
			delete(p.accountFails, name)
		}
	}
	p.loginMu.Unlock()
	p.proxyAuthMu.Lock()
	for ip, f := range p.proxyAuthFails {
		if now.Sub(f.window) > proxyFailWindow {
			delete(p.proxyAuthFails, ip)
		}
	}
	p.proxyAuthMu.Unlock()
}

func basicUserName(authHeader string) string {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return ""
	}
	cred := string(decoded)
	if i := strings.IndexByte(cred, ':'); i >= 0 {
		return cred[:i]
	}
	return ""
}

func userNameHint(name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf(" (user %q not found or password incorrect)", name)
}

// checkAccess evaluates rules and daily traffic limits. Returns
// (httpStatus, reason); status 0 means allowed. Connection caps are not
// checked here: tryEnterConn enforces them atomically just before the
// connection is accepted (and before any hijack, so denials are plain HTTP
// responses).
func (p *Proxy) checkAccess(user *User, cfg Config, host string) (int, string) {
	h := normalizeHost(host)
	if h == "" {
		return 400, "no target host"
	}
	d := p.rules.Evaluate(user, h)
	if !d.Allowed {
		return 403, d.Reason
	}
	if user != nil && user.DailyTrafficMB > 0 {
		used := p.dailyBytes(user.ID)
		limit := uint64(user.DailyTrafficMB) * 1024 * 1024
		if used >= limit {
			return 403, fmt.Sprintf("daily traffic limit exceeded (%d MB)", user.DailyTrafficMB)
		}
	}
	return 0, ""
}

func (p *Proxy) userConnCount(uid string) int32 {
	p.connMu.Lock()
	c := p.userConns[uid]
	p.connMu.Unlock()
	if c == nil {
		return 0
	}
	return c.Load()
}

// tryEnterConn atomically reserves the caller's connection slot(s): the
// per-user counter and the global counter are incremented and validated
// under the same lock, so caps can never be exceeded under concurrent
// load (the old check-then-act race allowed overshoot). On rejection it
// rolls back everything it reserved and returns the denial to send:
// 429 for the per-user cap, 503 for the global one. The caller must call
// exitConn exactly once after a successful reservation.
func (p *Proxy) tryEnterConn(user *User, cfg Config) (int, string) {
	if user != nil {
		cap := user.MaxConns
		if cap == 0 {
			cap = cfg.Proxy.DefaultMaxConns
		}
		p.connMu.Lock()
		c := p.userConns[user.ID]
		if c == nil {
			c = &atomic.Int32{}
			p.userConns[user.ID] = c
		}
		c.Add(1)
		if cap > 0 && c.Load() > int32(cap) {
			// Over the cap: roll the slot back and deny.
			c.Add(-1)
			p.connMu.Unlock()
			return 429, "per-user concurrent connection limit reached"
		}
		p.connMu.Unlock()
	}
	p.globalConns.Add(1)
	if cfg.Proxy.MaxGlobalConns > 0 && int64(p.globalConns.Load()) > int64(cfg.Proxy.MaxGlobalConns) {
		p.globalConns.Add(-1)
		if user != nil {
			p.connMu.Lock()
			if c := p.userConns[user.ID]; c != nil {
				c.Add(-1)
			}
			p.connMu.Unlock()
		}
		return 503, "global concurrent connection limit reached"
	}
	return 0, ""
}

func (p *Proxy) exitConn(uid string) {
	p.globalConns.Add(-1)
	if uid == "" {
		return
	}
	p.connMu.Lock()
	c := p.userConns[uid]
	p.connMu.Unlock()
	if c != nil {
		c.Add(-1)
	}
}

// todayUTC returns the current UTC date in "2006-01-02" format.
func todayUTC() string {
	return time.Now().UTC().Format("2006-01-02")
}

// dailyBytes returns the user's traffic counter for today only; counters
// from previous days are treated as zero so daily limits reset at UTC
// midnight without a restart.
func (p *Proxy) dailyBytes(uid string) uint64 {
	p.dailyMu.Lock()
	d := p.daily[uid]
	p.dailyMu.Unlock()
	if d == nil || d.date != todayUTC() {
		return 0
	}
	return d.bytes
}

func (p *Proxy) addDaily(uid string, bytes uint64) {
	if uid == "" {
		return
	}
	today := todayUTC()
	p.dailyMu.Lock()
	defer p.dailyMu.Unlock()
	d := p.daily[uid]
	if d == nil || d.date != today {
		d = &dailyTraffic{date: today}
		p.daily[uid] = d
	}
	d.bytes += bytes
}

// resetDaily clears a user's daily traffic counter (e.g. after an admin
// raises a quota that was already hit).
func (p *Proxy) resetDaily(uid string) {
	p.dailyMu.Lock()
	delete(p.daily, uid)
	p.dailyMu.Unlock()
}

// handleForward proxies a plain-HTTP request.
func (p *Proxy) handleForward(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	cfg := p.store.Config()
	clientIP := clientAddr(r)
	target := r.URL
	uid := ""
	user := (*User)(nil)

	if !cfg.Proxy.Enabled {
		p.deny(w, r, 503, "proxy is disabled")
		return
	}
	if !cfg.Proxy.AllowHTTP {
		p.deny(w, r, 403, "plain-HTTP proxying is disabled")
		return
	}
	if target.Scheme != "" && target.Scheme != "http" {
		// Absolute-form URLs must be plain HTTP; https belongs to CONNECT
		// and other schemes (file://, gopher://, …) cannot be forwarded.
		// Rejected before authentication so junk costs no PBKDF2 work.
		p.deny(w, r, 400, "unsupported URL scheme: "+target.Scheme)
		return
	}

	u, ok, status, reason := p.authorize(r, clientIP)
	if !ok {
		p.deny(w, r, status, reason)
		return
	}
	user = u
	if user != nil {
		uid = user.ID
	}

	if st, reason := p.checkAccess(user, cfg, target.Host); st != 0 {
		p.denyAs(user, w, r, st, reason)
		return
	}

	// Reserve the connection slot atomically before doing any work; on a
	// cap denial we still have a normal response writer.
	if st, reason := p.tryEnterConn(user, cfg); st != 0 {
		p.denyAs(user, w, r, st, reason)
		return
	}
	defer p.exitConn(uid)

	// Clone with the client's request context (not Background) so an
	// aborted client cancels the in-flight upstream request.
	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopHeaders(out.Header)
	xff := out.Header.Get("X-Forwarded-For")
	if xff != "" {
		xff += ", "
	}
	out.Header.Set("X-Forwarded-For", xff+clientIP)
	out.Header.Set("X-Forwarded-By", "forward-proxy/"+Version)

	var reqBytes atomic.Int64
	if r.Body != nil {
		out.Body = &countReader{r: r.Body, n: &reqBytes}
	}
	out.ContentLength = r.ContentLength
	timeout := time.Duration(cfg.Proxy.ReadTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	ctx, cancel := context.WithTimeout(out.Context(), timeout)
	defer cancel()
	out = out.WithContext(ctx)

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		status := 502
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = 504
		}
		reason := "upstream error: " + err.Error()
		if sr := dialSinkholeReason(target.Host); sr != "" {
			reason = "upstream error: " + sr
		}
		p.denyAs(user, w, r, status, reason)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(resp.Header, w)
	w.WriteHeader(resp.StatusCode)
	// Streaming: flush after each read chunk so SSE / long-poll / video
	// responses reach the client as they arrive instead of being buffered
	// until the 4KB server buffer fills or the response completes.
	var n int64
	if fl, ok := w.(http.Flusher); ok {
		buf := make([]byte, 32*1024)
		for {
			nr, rerr := resp.Body.Read(buf)
			if nr > 0 {
				nn, werr := w.Write(buf[:nr])
				n += int64(nn)
				fl.Flush()
				if werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
	} else {
		n, _ = io.Copy(w, resp.Body)
	}

	p.live.add(uid, uint64(maxInt64(reqBytes.Load())), uint64(n))
	p.addDaily(uid, uint64(maxInt64(reqBytes.Load()))+uint64(n))
	p.logs.Add(LogEntry{
		User:       whoName(user),
		Method:     r.Method,
		Host:       normalizeHost(target.Host),
		Path:       target.RequestURI()[:min(200, len(target.RequestURI()))],
		Status:     resp.StatusCode,
		Outcome:    "ALLOWED",
		BytesIn:    uint64(maxInt64(reqBytes.Load())),
		BytesOut:   uint64(n),
		DurationMs: time.Since(t0).Milliseconds(),
		Client:     clientIP,
	})
}

func (p *Proxy) denyAs(user *User, w http.ResponseWriter, r *http.Request, status int, reason string) {
	name := whoName(user)
	if name == "" {
		hdr := r.Header.Get("Proxy-Authorization")
		if hdr == "" {
			hdr = r.Header.Get("Authorization")
		}
		name = basicUserName(hdr)
	}
	if status == http.StatusProxyAuthRequired {
		// RFC 7235: 407 from a proxy must carry Proxy-Authenticate;
		// also send WWW-Authenticate for older clients that only check it.
		w.Header().Set("Proxy-Authenticate", `Basic realm="forward-proxy"`)
		w.Header().Set("WWW-Authenticate", `Basic realm="forward-proxy"`)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, "forward-proxy: "+reason+"\n")
	target := ""
	if r.URL != nil {
		target = r.URL.Host
	}
	p.logs.Add(LogEntry{
		User:    name,
		Method:  r.Method,
		Host:    normalizeHost(target),
		Path:    shortPath(r),
		Status:  status,
		Outcome: "DENIED: " + reason,
		Client:  clientAddr(r),
	})
}

func (p *Proxy) deny(w http.ResponseWriter, r *http.Request, status int, reason string) {
	p.denyAs(nil, w, r, status, reason)
}

// isSinkholeAddress reports whether an IP address is a DNS sinkhole answer:
// the unspecified addresses 0.0.0.0 (IPv4) and :: (IPv6) that DNS filters
// and ad-blockers return for blocked domains. Localhost (127.0.0.1 / ::1) is
// deliberately NOT treated as a sinkhole — it is a legitimate target.
func isSinkholeAddress(ip net.IP) bool {
	return ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6unspecified)
}

// dialSinkholeReason explains a failed outbound dial when the target
// hostname resolved ONLY to sinkhole addresses (0.0.0.0 / ::). Without this,
// the failure surfaces as the confusing "dial tcp 0.0.0.0:443: connect:
// connection refused", which reads like a network or TLS problem although
// the site is fine and a DNS filter is blocking it. Returns "" when no
// sinkhole is involved (hostname missing, lookup failed, or any real address
// present), in which case the caller keeps the original error.
func dialSinkholeReason(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if host == "" {
		return ""
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	all := true
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || !isSinkholeAddress(ip) {
			all = false
			break
		}
	}
	if !all {
		return ""
	}
	return fmt.Sprintf("DNS resolved %q only to a blocked address (%s); the domain appears to be blocked by a DNS filter or ad-blocker",
		host, strings.Join(addrs, ", "))
}

// handleConnect tunnels a CONNECT request (HTTPS).
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	cfg := p.store.Config()
	clientIP := clientAddr(r)

	if !cfg.Proxy.Enabled {
		p.deny(w, r, 503, "proxy is disabled")
		return
	}
	if !cfg.Proxy.AllowHTTPS {
		p.deny(w, r, 403, "HTTPS CONNECT is disabled")
		return
	}

	user, ok, status, reason := p.authorize(r, clientIP)
	if !ok {
		p.deny(w, r, status, reason)
		return
	}
	uid := ""
	if user != nil {
		uid = user.ID
	}

	// Normalize the CONNECT target: "host" -> "host:443", "host:" ->
	// "host:443", "[v6]" -> "[v6]:443"; IPv6 literals stay bracketed.
	target := normalizeTarget(r.Host)
	if target == "" {
		p.deny(w, r, 400, "CONNECT target missing")
		return
	}
	if st, reason := p.checkAccess(user, cfg, target); st != 0 {
		p.denyAs(user, w, r, st, reason)
		return
	}
	// Reserve the connection slot before hijacking: on a cap denial we
	// still have a normal response writer to answer with.
	if st, reason := p.tryEnterConn(user, cfg); st != 0 {
		p.denyAs(user, w, r, st, reason)
		return
	}
	defer p.exitConn(uid)

	hj, okj := w.(http.Hijacker)
	if !okj {
		p.deny(w, r, 502, "hijacking unsupported")
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		p.deny(w, r, 502, "hijack failed: "+err.Error())
		return
	}
	// We now own the client connection for its whole lifetime.

	timeout := time.Duration(cfg.Proxy.ConnectTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	upstream, err := p.transport.DialContext(r.Context(), "tcp", target)
	if err != nil {
		reason := err.Error()
		if sr := dialSinkholeReason(target); sr != "" {
			reason = sr
		}
		p.writeRawStatus(client, 502, "upstream connect failed: "+reason)
		client.Close()
		p.logs.Add(LogEntry{
			User: whoName(user), Method: "CONNECT", Host: normalizeHost(target),
			Status: 502, Outcome: "ERROR: " + reason, Client: clientIP,
			DurationMs: time.Since(t0).Milliseconds(),
		})
		return
	}

	if err := client.SetWriteDeadline(time.Now().Add(timeout)); err == nil {
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}
	// buf holds bytes the client pipelined right after the request
	// headers — for TLS this is usually the first bytes of the
	// ClientHello. Forward them to the upstream before the tunnel starts,
	// otherwise the handshake fails with "wrong version number".
	// NOTE: buf.Available() is the writer's free space, and Peek on it
	// would block; use the reader's Buffered() count and consume exactly
	// those bytes.
	if n := buf.Reader.Buffered(); n > 0 {
		leftover := make([]byte, n)
		if _, rerr := io.ReadFull(buf.Reader, leftover); rerr == nil {
			// A peer that accepts the connection but never reads must not
			// hang this handler goroutine forever: bound the write.
			_ = upstream.SetWriteDeadline(time.Now().Add(timeout))
			if _, werr := upstream.Write(leftover); werr != nil {
				client.Close()
				upstream.Close()
				return
			}
			pipelined := uint64(len(leftover))
			p.live.add(uid, pipelined, 0)
			p.addDaily(uid, pipelined)
		}
	}

	var bytesIn, bytesOut uint64
	idle := time.Duration(cfg.Proxy.ReadTimeoutSec) * time.Second
	if idle <= 0 {
		idle = 300 * time.Second
	}
	p.runTunnel(client, upstream, idle, &bytesIn, &bytesOut)
	client.Close()
	upstream.Close()

	p.live.add(uid, bytesIn, bytesOut)
	p.addDaily(uid, bytesIn+bytesOut)
	p.logs.Add(LogEntry{
		User: whoName(user), Method: "CONNECT", Host: normalizeHost(target),
		Status: 200, Outcome: "CONNECT",
		BytesIn: bytesIn, BytesOut: bytesOut,
		DurationMs: time.Since(t0).Milliseconds(), Client: clientIP,
	})
}

// runTunnel copies bytes in both directions until either side closes or idles.
func (p *Proxy) runTunnel(a, b net.Conn, idle time.Duration, aToB, bToA *uint64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copySide(b, a, aToB, idle)
		_ = b.Close()
	}()
	go func() {
		defer wg.Done()
		copySide(a, b, bToA, idle)
		_ = a.Close()
	}()
	wg.Wait()
}

func copySide(dst, src net.Conn, n *uint64, idle time.Duration) {
	buf := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idle))
		nn, err := src.Read(buf)
		if nn > 0 {
			*n += uint64(nn)
			// A write deadline too: a peer that stops reading (or is gone)
			// must not hang the tunnel and leak the connection pair.
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := dst.Write(buf[:nn]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// writeRawStatus writes a plain HTTP status to a hijacked connection.
func (p *Proxy) writeRawStatus(c net.Conn, status int, reason string) {
	body := "forward-proxy: " + reason + "\n"
	msg := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	_, _ = c.Write([]byte(msg))
}

// FlushStats merges live in-memory counters into the persisted config.
func (p *Proxy) FlushStats() {
	// Prune expired per-IP failure state so the maps stay bounded even
	// under distributed brute-forcing (entries were previously only
	// removed when the same IP tried again).
	p.pruneAuthFailures(time.Now())

	// Push buffered activity-log lines to disk (the JSONL writer is
	// buffered; without this, quiet traffic would leave lines unwritten
	// for a long time).
	p.logs.Flush()

	// Prune daily traffic counters from previous days (they are treated
	// as zero by dailyBytes); run on every tick even without traffic so
	// the map stays small across midnight.
	today := todayUTC()
	p.dailyMu.Lock()
	for uid, d := range p.daily {
		if d.date != today {
			delete(p.daily, uid)
		}
	}
	p.dailyMu.Unlock()

	p.live.mu.Lock()
	requests, bytesIn, bytesOut := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	lastUsed := map[string]time.Time{}
	for k, v := range p.live.requests {
		requests[k] = v
	}
	for k, v := range p.live.bytesIn {
		bytesIn[k] = v
	}
	for k, v := range p.live.bytesOut {
		bytesOut[k] = v
	}
	for k, v := range p.live.lastUsed {
		lastUsed[k] = v
	}
	p.live.requests = map[string]uint64{}
	p.live.bytesIn = map[string]uint64{}
	p.live.bytesOut = map[string]uint64{}
	p.live.lastUsed = map[string]time.Time{}
	p.live.mu.Unlock()

	if len(requests) == 0 && len(lastUsed) == 0 {
		return
	}
	// Silent update: persisting stats must not recompile rules or rebind
	// listeners on every 5-second tick (that was happening via Update).
	_ = p.store.UpdateSilent(func(c *Config) error {
		for i := range c.Users {
			uid := c.Users[i].ID
			if d, ok := requests[uid]; ok {
				c.Users[i].Stats.Requests += d
			}
			if d, ok := bytesIn[uid]; ok {
				c.Users[i].Stats.BytesIn += d
			}
			if d, ok := bytesOut[uid]; ok {
				c.Users[i].Stats.BytesOut += d
			}
			if t, ok := lastUsed[uid]; ok {
				c.Users[i].LastUsedAt = t.Format(time.RFC3339)
			}
		}
		return nil
	})
}

// MergedStats returns persisted + live counters for a user.
func (p *Proxy) MergedStats(u *User) UserStats {
	p.live.mu.Lock()
	defer p.live.mu.Unlock()
	s := u.Stats
	if r, ok := p.live.requests[u.ID]; ok {
		s.Requests += r
	}
	if b, ok := p.live.bytesIn[u.ID]; ok {
		s.BytesIn += b
	}
	if b, ok := p.live.bytesOut[u.ID]; ok {
		s.BytesOut += b
	}
	return s
}

// isDefaultPassword reports whether a user still uses the factory-default
// password, memoized per (userID, passwordHash): the hash is part of the key,
// so password changes invalidate immediately and the flag is only ever
// computed once per distinct stored hash (the admin status/users APIs call
// this for every user on every request, and a raw PBKDF2 would cost ~170ms
// each).
func (p *Proxy) isDefaultPassword(u *User) bool {
	key := u.ID + "\x00\x00" + u.PasswordHash
	p.defaultPassMu.Lock()
	if v, ok := p.defaultPassCache[key]; ok {
		p.defaultPassMu.Unlock()
		return v
	}
	p.defaultPassMu.Unlock()
	v := IsDefaultPassword(u.PasswordHash)
	p.defaultPassMu.Lock()
	p.defaultPassCache[key] = v
	p.defaultPassMu.Unlock()
	return v
}

// ActiveConns returns global + per-user active connection counts.
func (p *Proxy) ActiveConns(uid string) (global int32, user int32) {
	global = p.globalConns.Load()
	user = p.userConnCount(uid)
	return global, user
}

// ---- small helpers ----

type countReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countReader) Close() error {
	if rc, ok := c.r.(io.Closer); ok {
		return rc.Close()
	}
	return nil
}

func removeHopHeaders(h http.Header) {
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func copyResponseHeaders(src http.Header, dst http.ResponseWriter) {
	for k, vv := range src {
		lk := strings.ToLower(k)
		if isHop(lk) {
			continue
		}
		for _, v := range vv {
			dst.Header().Add(k, v)
		}
	}
}

func isHop(lk string) bool {
	for _, k := range hopByHopHeaders {
		if strings.EqualFold(k, lk) {
			return true
		}
	}
	return false
}

func whoName(u *User) string {
	if u == nil {
		return "anonymous"
	}
	return u.Username
}

func shortPath(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	p := r.URL.RequestURI()
	if len(p) > 200 {
		return p[:200]
	}
	return p
}

func maxInt64(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}
