package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)

const sessionTTL = 12 * time.Hour

// Sentinel errors returned from Store.Update callbacks so handlers can
// map them to the right HTTP status.
var (
	errLastAdmin     = errors.New("last enabled admin would be removed")
	errDuplicateName = errors.New("username already exists")
)

// adminName returns the authenticated admin's username from the request
// (set by requireAdmin), used for audit records.
func adminName(r *http.Request) string {
	return r.Header.Get("X-Admin-User")
}

// usernameTaken reports whether name is already used by a user other
// than excludeID ("", when creating). Case-insensitive, matching the
// login lookup (FindUserByName), so "Bob" and "bob" cannot both exist
// (that would make logins ambiguous).
func usernameTaken(c *Config, name, excludeID string) bool {
	for i := range c.Users {
		if c.Users[i].ID != excludeID && strings.EqualFold(c.Users[i].Username, name) {
			return true
		}
	}
	return false
}

// AdminHandler builds the management UI + API handler.
func (p *Proxy) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/admin/api/login", p.apiLogin)
	mux.HandleFunc("/admin/api/logout", p.apiLogout)
	mux.HandleFunc("/admin/api/self", p.apiSelf)
	mux.HandleFunc("/admin/api/", p.adminAPI)
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		data, err := webFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "ui not found", 500)
			return
		}
		w.Write(data)
	})
	return csrfGuard(mux)
}

// csrfGuard rejects cross-origin state-changing requests. Cookie-based admin
// sessions are otherwise only protected by SameSite=Lax (modern browsers);
// this closes the gap for older browsers and non-conforming clients. The
// check only fires when an Origin header is present (curl and non-browser
// clients don't send one and are unaffected): if it is, its host:port must
// match the request's Host. Read-only methods are always allowed.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// Read-only: cross-site GETs cannot read responses (SOP), and
			// no admin state changes are GET-triggered.
		default:
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Proxy) adminAPI(w http.ResponseWriter, r *http.Request) {
	handler := requireAdmin(p)
	sub := strings.TrimPrefix(r.URL.Path, "/admin/api/")
	switch {
	case sub == "status" && r.Method == http.MethodGet:
		handler(p.apiStatus)(w, r)
	case sub == "users" && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		handler(p.apiUsers)(w, r)
	case strings.HasPrefix(sub, "users/") && sub != "users/":
		p.routeUser(w, r, sub, handler)
	case sub == "global-rules" && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		handler(p.apiGlobalRules)(w, r)
	case sub == "settings" && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		handler(p.apiSettings)(w, r)
	case sub == "logs" && r.Method == http.MethodGet:
		handler(p.apiLogs)(w, r)
	case sub == "logs" && r.Method == http.MethodDelete:
		handler(p.apiLogsClear)(w, r)
	case sub == "logs/export" && r.Method == http.MethodGet:
		handler(p.apiLogsExport)(w, r)
	case sub == "audit" && r.Method == http.MethodGet:
		handler(p.apiAudit)(w, r)
	case sub == "export" && r.Method == http.MethodGet:
		handler(p.apiExport)(w, r)
	case sub == "import" && r.Method == http.MethodPost:
		handler(p.apiImport)(w, r)
	case sub == "stats/timeline" && r.Method == http.MethodGet:
		handler(p.apiStatsTimeline)(w, r)
	default:
		writeJSON(w, 404, map[string]any{"error": "not found"})
	}
}

func (p *Proxy) routeUser(w http.ResponseWriter, r *http.Request, sub string, handler func(http.HandlerFunc) http.HandlerFunc) {
	rest := strings.TrimPrefix(sub, "users/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		writeJSON(w, 404, map[string]any{"error": "user id required"})
		return
	}
	switch {
	case len(parts) == 1:
		switch r.Method {
		case http.MethodGet:
			handler(p.apiUserGet)(w, r)
		case http.MethodPut:
			handler(p.apiUserUpdate)(w, r)
		case http.MethodDelete:
			handler(p.apiUserDelete)(w, r)
		default:
			writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		}
	case len(parts) == 2 && parts[1] == "password" && r.Method == http.MethodPost:
		handler(p.apiUserPassword)(w, r)
	case len(parts) == 2 && parts[1] == "reset" && r.Method == http.MethodPost:
		handler(p.apiUserReset)(w, r)
	default:
		writeJSON(w, 404, map[string]any{"error": "not found"})
	}
}

// ---- auth endpoints ----

// Login rate limiting: after loginMaxFails failed attempts from one IP
// within loginFailWindow, that IP is locked out of /api/login for
// loginLockoutTime.
const (
	loginMaxFails    = 10
	loginFailWindow  = 15 * time.Minute
	loginLockoutTime = 10 * time.Minute
)

// loginAllowed reports whether a login attempt from clientIP may proceed
// (the IP is not currently locked out).
func (p *Proxy) loginAllowed(clientIP string) bool {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	f := p.loginFails[clientIP]
	if f == nil {
		return true
	}
	now := time.Now()
	if !f.until.IsZero() {
		if now.Before(f.until) {
			return false
		}
		delete(p.loginFails, clientIP) // lockout expired
		return true
	}
	if now.Sub(f.window) > loginFailWindow {
		delete(p.loginFails, clientIP) // failure window elapsed
	}
	return true
}

// loginFail records a failed login attempt from clientIP; reaching
// loginMaxFails within the window locks the IP out.
func (p *Proxy) loginFail(clientIP string) {
	now := time.Now()
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	f := p.loginFails[clientIP]
	if f == nil || now.Sub(f.window) > loginFailWindow {
		f = &loginFails{window: now}
		p.loginFails[clientIP] = f
	}
	f.count++
	if f.count >= loginMaxFails {
		f.until = now.Add(loginLockoutTime)
		f.count = 0
		f.window = now
	}
}

// loginOK clears any failure/lockout state for clientIP.
func (p *Proxy) loginOK(clientIP string) {
	p.loginMu.Lock()
	delete(p.loginFails, clientIP)
	p.loginMu.Unlock()
}

// Per-account login throttling: the same thresholds as the per-IP limiter,
// keyed by (case-insensitive) username. A distributed brute force across
// many client IPs targeting one account is capped here even though no single
// IP trips the per-IP limiter.

func (p *Proxy) accountAllowed(username string) bool {
	if username == "" {
		return true
	}
	key := strings.ToLower(username)
	now := time.Now()
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	f := p.accountFails[key]
	if f == nil {
		return true
	}
	if !f.until.IsZero() {
		if now.Before(f.until) {
			return false
		}
		delete(p.accountFails, key) // lockout expired
		return true
	}
	if now.Sub(f.window) > loginFailWindow {
		delete(p.accountFails, key) // failure window elapsed
	}
	return true
}

func (p *Proxy) accountFail(username string) {
	if username == "" {
		return
	}
	key := strings.ToLower(username)
	now := time.Now()
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	f := p.accountFails[key]
	if f == nil || now.Sub(f.window) > loginFailWindow {
		f = &loginFails{window: now}
		p.accountFails[key] = f
	}
	f.count++
	if f.count >= loginMaxFails {
		f.until = now.Add(loginLockoutTime)
		f.count = 0
		f.window = now
	}
}

func (p *Proxy) accountOK(username string) {
	if username == "" {
		return
	}
	p.loginMu.Lock()
	delete(p.accountFails, strings.ToLower(username))
	p.loginMu.Unlock()
}

// getDummyHash returns a fixed PBKDF2 hash (created once) used to
// equalize response timing on login.
func (p *Proxy) getDummyHash() string {
	p.dummyHashOnce.Do(func() {
		if h, err := HashPassword("dummy-password-for-timing"); err == nil {
			p.dummyHash = h
		}
	})
	return p.dummyHash
}

func (p *Proxy) apiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	clientIP := clientAddr(r)
	if !p.loginAllowed(clientIP) {
		writeJSON(w, 429, map[string]any{"error": "too many failed login attempts, try again later"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid body"})
		return
	}
	if !p.accountAllowed(body.Username) {
		writeJSON(w, 429, map[string]any{"error": "too many failed login attempts for this account, try again later"})
		return
	}
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(body.Username+":"+body.Password))
	u := p.store.checkBasicAuth(header)
	if u == nil {
		p.loginFail(clientIP)
		p.accountFail(body.Username)
		// Timing equalization: close the user-existence oracle (unknown /
		// disabled / wrong-password all cost ~one PBKDF2).
		p.equalizeAuthTiming(body.Username, body.Password)
		p.audit.Record("login.fail", body.Username, "client="+clientIP)
		writeJSON(w, 401, map[string]any{"error": "invalid credentials"})
		return
	}
	if u.Role != "admin" {
		// Valid credentials, wrong role: not a failure for lockout
		// purposes (an attacker cannot reach this path without the
		// password, so it cannot be used for enumeration).
		writeJSON(w, 403, map[string]any{"error": "admin role required to access the management interface"})
		return
	}
	p.loginOK(clientIP)
	p.accountOK(body.Username)
	cfg := p.store.Config()
	tok, err := issueToken(cfg.SessionKey, u.Username, sessionTTL, u.TokenEpoch)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "token error"})
		return
	}
	p.audit.Record("login.ok", u.Username, "client="+clientIP)
	http.SetCookie(w, &http.Cookie{
		Name:     "fpx_session",
		Value:    tok,
		Path:     "/admin",
		HttpOnly: true,
		// Secure only when the admin listener is served over TLS; the
		// plaintext (default) admin port must keep cookies sendable.
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
	writeJSON(w, 200, map[string]any{"ok": true, "username": u.Username})
}

func (p *Proxy) apiLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "fpx_session", Value: "", Path: "/admin", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (p *Proxy) apiSelf(w http.ResponseWriter, r *http.Request) {
	tok := sessionToken(r)
	if tok == "" {
		writeJSON(w, 401, map[string]any{"error": "not authenticated"})
		return
	}
	u, exp, epoch, ok := verifyToken(p.store.Config().SessionKey, tok)
	if !ok || time.Now().Unix() >= exp {
		writeJSON(w, 401, map[string]any{"error": "session expired"})
		return
	}
	user := p.store.FindUserByName(u)
	if user == nil || !user.Enabled || user.Role != "admin" || user.TokenEpoch != epoch {
		writeJSON(w, 401, map[string]any{"error": "not authenticated"})
		return
	}
	writeJSON(w, 200, map[string]any{"username": user.Username, "role": user.Role})
}

// ---- status / dashboard ----

type userView struct {
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	Role            string    `json:"role"`
	Enabled         bool      `json:"enabled"`
	WhitelistOnly   bool      `json:"whitelist_only"`
	Whitelist       []string  `json:"whitelist"`
	Blacklist       []string  `json:"blacklist"`
	MaxConns        int       `json:"max_conns"`
	DailyTrafficMB  int       `json:"daily_traffic_mb"`
	CreatedAt       string    `json:"created_at"`
	LastUsedAt      string    `json:"last_used_at"`
	Stats           UserStats `json:"stats"`
	ActiveConns     int32     `json:"active_conns"`
	DefaultPassword bool      `json:"default_password"`
}

func (p *Proxy) toView(u *User) userView {
	v := userView{
		ID: u.ID, Username: u.Username, Role: u.Role, Enabled: u.Enabled,
		WhitelistOnly: u.WhitelistOnly, Whitelist: u.Whitelist, Blacklist: u.Blacklist,
		MaxConns: u.MaxConns, DailyTrafficMB: u.DailyTrafficMB,
		CreatedAt: u.CreatedAt, LastUsedAt: u.LastUsedAt,
		Stats: p.MergedStats(u),
	}
	v.ActiveConns = p.userConnCount(u.ID)
	v.DefaultPassword = p.isDefaultPassword(u)
	return v
}

func (p *Proxy) apiStatus(w http.ResponseWriter, r *http.Request) {
	cfg := p.store.Config()
	type totalsView struct {
		Requests    uint64 `json:"requests"`
		BytesIn     uint64 `json:"bytes_in"`
		BytesOut    uint64 `json:"bytes_out"`
		ActiveConns int32  `json:"active_conns"`
		UserCount   int    `json:"user_count"`
	}
	tot := totalsView{UserCount: len(cfg.Users)}
	views := make([]userView, 0, len(cfg.Users))
	defaultAdmin := false
	for i := range cfg.Users {
		u := cfg.Users[i]
		v := p.toView(&u)
		tot.Requests += v.Stats.Requests
		tot.BytesIn += v.Stats.BytesIn
		tot.BytesOut += v.Stats.BytesOut
		if v.DefaultPassword && u.Role == "admin" {
			defaultAdmin = true
		}
		views = append(views, v)
	}
	tot.ActiveConns = p.globalConns.Load()
	writeJSON(w, 200, map[string]any{
		"version":                Version,
		"uptime_sec":             int64(time.Since(p.startedAt).Seconds()),
		"proxy":                  cfg.Proxy,
		"global_rules":           cfg.GlobalRules,
		"logs":                   cfg.Logs,
		"totals":                 tot,
		"users":                  views,
		"recent_logs":            p.logs.Recent(50, "", ""),
		"default_admin_password": defaultAdmin,
	})
}

// ---- user management ----

// userBody accepts both full and partial updates: pointer fields that are
// absent from the JSON leave the corresponding user field untouched.
type userBody struct {
	Username       string    `json:"username"`
	Password       string    `json:"password"`
	Role           string    `json:"role"`
	Enabled        *bool     `json:"enabled"`
	WhitelistOnly  *bool     `json:"whitelist_only"`
	Whitelist      *[]string `json:"whitelist"`
	Blacklist      *[]string `json:"blacklist"`
	MaxConns       *int      `json:"max_conns"`
	DailyTrafficMB *int      `json:"daily_traffic_mb"`
}

func (b *userBody) validate(create bool) error {
	if create {
		if !usernameRe.MatchString(b.Username) {
			return fmt.Errorf("username must be 2-64 chars: letters, digits, dot, dash, underscore")
		}
		if b.Role != "user" && b.Role != "admin" {
			return fmt.Errorf("role must be user or admin")
		}
		if len(b.Password) < 6 {
			return fmt.Errorf("password must be at least 6 characters")
		}
	} else {
		if b.Username != "" && !usernameRe.MatchString(b.Username) {
			return fmt.Errorf("username must be 2-64 chars: letters, digits, dot, dash, underscore")
		}
		if b.Role != "" && b.Role != "user" && b.Role != "admin" {
			return fmt.Errorf("role must be user or admin")
		}
		if b.Password != "" && len(b.Password) < 6 {
			return fmt.Errorf("password must be at least 6 characters")
		}
	}
	if b.MaxConns != nil && (*b.MaxConns < 0 || *b.MaxConns > 100000) {
		return fmt.Errorf("max_conns out of range")
	}
	if b.DailyTrafficMB != nil && (*b.DailyTrafficMB < 0 || *b.DailyTrafficMB > 1000000) {
		return fmt.Errorf("daily_traffic_mb out of range")
	}
	for _, list := range []*[]string{b.Whitelist, b.Blacklist} {
		if list != nil {
			if err := validatePatterns(*list); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePatterns(patterns []string) error {
	for _, pat := range patterns {
		if strings.TrimSpace(pat) == "" {
			continue
		}
		if _, err := compilePattern(pat); err != nil {
			return fmt.Errorf("invalid pattern %q: %v", pat, err)
		}
	}
	return nil
}

func (p *Proxy) countEnabledAdmins(cfg *Config, excludeID string) int {
	n := 0
	for i := range cfg.Users {
		if cfg.Users[i].Role == "admin" && cfg.Users[i].Enabled && cfg.Users[i].ID != excludeID {
			n++
		}
	}
	return n
}

func (p *Proxy) apiUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := p.store.Config()
		views := make([]userView, 0, len(cfg.Users))
		for i := range cfg.Users {
			views = append(views, p.toView(&cfg.Users[i]))
		}
		writeJSON(w, 200, views)
	case http.MethodPost:
		var b userBody
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody)).Decode(&b); err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid body"})
			return
		}
		if err := b.validate(true); err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		if p.store.FindUserByName(b.Username) != nil {
			writeJSON(w, 409, map[string]any{"error": "username already exists"})
			return
		}
		u, err := NewUser(b.Username, b.Password, b.Role)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		if b.WhitelistOnly != nil {
			u.WhitelistOnly = *b.WhitelistOnly
		}
		if b.Whitelist != nil {
			u.Whitelist = *b.Whitelist
		}
		if b.Blacklist != nil {
			u.Blacklist = *b.Blacklist
		}
		if b.MaxConns != nil {
			u.MaxConns = *b.MaxConns
		}
		if b.DailyTrafficMB != nil {
			u.DailyTrafficMB = *b.DailyTrafficMB
		}
		if b.Enabled != nil {
			u.Enabled = *b.Enabled
		}
		if err := p.store.Update(func(c *Config) error {
			// Authoritative duplicate check inside the update transaction
			// (closes the check-then-act race between two concurrent
			// creates).
			if usernameTaken(c, u.Username, "") {
				return errDuplicateName
			}
			c.Users = append(c.Users, *u)
			return nil
		}); err != nil {
			if errors.Is(err, errDuplicateName) {
				writeJSON(w, 409, map[string]any{"error": "username already exists"})
				return
			}
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		p.addDaily(u.ID, 0)
		p.audit.Record("user.create", adminName(r), fmt.Sprintf("username=%s role=%s", u.Username, u.Role))
		writeJSON(w, 201, p.toView(u))
	}
}

func (p *Proxy) apiUserGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
	id = strings.Split(id, "/")[0]
	u := p.store.FindUser(id)
	if u == nil {
		writeJSON(w, 404, map[string]any{"error": "user not found"})
		return
	}
	writeJSON(w, 200, p.toView(u))
}

func (p *Proxy) apiUserUpdate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
	id = strings.Split(id, "/")[0]
	var b userBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody)).Decode(&b); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid body"})
		return
	}
	if err := b.validate(false); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if other := p.store.FindUserByName(b.Username); other != nil && other.ID != id {
		writeJSON(w, 409, map[string]any{"error": "username already exists"})
		return
	}
	err := p.store.Update(func(c *Config) error {
		for i := range c.Users {
			if c.Users[i].ID != id {
				continue
			}
			u := &c.Users[i]
			if b.Username != "" {
				u.Username = b.Username
			}
			// Authoritative duplicate check inside the update transaction
			// (a rename can race another rename onto the same name).
			if usernameTaken(c, u.Username, id) {
				return errDuplicateName
			}
			if b.Role != "" {
				u.Role = b.Role
			}
			if b.WhitelistOnly != nil {
				u.WhitelistOnly = *b.WhitelistOnly
			}
			if b.Whitelist != nil {
				u.Whitelist = *b.Whitelist
			}
			if b.Blacklist != nil {
				u.Blacklist = *b.Blacklist
			}
			if b.MaxConns != nil {
				u.MaxConns = *b.MaxConns
			}
			if b.DailyTrafficMB != nil {
				u.DailyTrafficMB = *b.DailyTrafficMB
			}
			if b.Enabled != nil {
				u.Enabled = *b.Enabled
			}
			if b.Password != "" {
				hash, err := HashPassword(b.Password)
				if err != nil {
					return err
				}
				u.PasswordHash = hash
				// Invalidate any sessions issued before this change.
				u.TokenEpoch++
			}
			// Guard: never allow an update that would leave zero enabled
			// admins — whether by disabling the admin or by demoting it
			// (role change) — both used to slip through the old
			// disable-only check and lock everyone out of the admin UI.
			if (u.Role != "admin" || !u.Enabled) && p.countEnabledAdmins(c, id) == 0 {
				return errLastAdmin
			}
			return nil
		}
		return fmt.Errorf("user not found")
	})
	if err != nil {
		switch {
		case errors.Is(err, errDuplicateName):
			writeJSON(w, 409, map[string]any{"error": "username already exists"})
		case errors.Is(err, errLastAdmin):
			writeJSON(w, 400, map[string]any{"error": "cannot remove the last enabled admin"})
		default:
			writeJSON(w, 400, map[string]any{"error": err.Error()})
		}
		return
	}
	p.auditUserUpdate(r, id, &b)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiUserUpdate audit: record what changed (captured after the update).
func (p *Proxy) auditUserUpdate(r *http.Request, id string, b *userBody) {
	u := p.store.FindUser(id)
	if u == nil {
		return
	}
	detail := "username=" + u.Username
	if b.Role != "" {
		detail += fmt.Sprintf(" role=%s", b.Role)
	}
	if b.Enabled != nil {
		detail += fmt.Sprintf(" enabled=%v", *b.Enabled)
	}
	if b.MaxConns != nil {
		detail += fmt.Sprintf(" max_conns=%d", *b.MaxConns)
	}
	if b.DailyTrafficMB != nil {
		detail += fmt.Sprintf(" daily_mb=%d", *b.DailyTrafficMB)
	}
	if b.Password != "" {
		detail += " password=changed"
	}
	p.audit.Record("user.update", adminName(r), detail)
}

func (p *Proxy) apiUserDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
	id = strings.Split(id, "/")[0]
	deleted := ""
	err := p.store.Update(func(c *Config) error {
		for i := range c.Users {
			if c.Users[i].ID != id {
				continue
			}
			u := &c.Users[i]
			// Deleting the last enabled admin would lock everyone out of
			// the admin UI (a demoted/disabled admin does not count, so
			// only an *enabled* admin triggers this).
			if u.Role == "admin" && u.Enabled && p.countEnabledAdmins(c, id) == 0 {
				return errLastAdmin
			}
			deleted = u.Username
			c.Users = append(c.Users[:i], c.Users[i+1:]...)
			return nil
		}
		return fmt.Errorf("user not found")
	})
	if err != nil {
		if errors.Is(err, errLastAdmin) {
			writeJSON(w, 400, map[string]any{"error": "cannot remove the last enabled admin"})
			return
		}
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	p.audit.Record("user.delete", adminName(r), "username="+deleted)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (p *Proxy) apiUserPassword(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
	id = strings.Split(id, "/")[0]
	var b struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody)).Decode(&b); err != nil || len(b.Password) < 6 {
		writeJSON(w, 400, map[string]any{"error": "password must be at least 6 characters"})
		return
	}
	hash, err := HashPassword(b.Password)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	who := ""
	err = p.store.Update(func(c *Config) error {
		for i := range c.Users {
			if c.Users[i].ID == id {
				c.Users[i].PasswordHash = hash
				// Invalidate any sessions issued before this change.
				c.Users[i].TokenEpoch++
				who = c.Users[i].Username
				return nil
			}
		}
		return fmt.Errorf("user not found")
	})
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	p.audit.Record("user.password", adminName(r), "username="+who)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiUserReset clears a user's daily traffic counter (admin action, audited).
func (p *Proxy) apiUserReset(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
	id = strings.Split(id, "/")[0]
	u := p.store.FindUser(id)
	if u == nil {
		writeJSON(w, 404, map[string]any{"error": "user not found"})
		return
	}
	p.resetDaily(id)
	p.audit.Record("user.reset", adminName(r), fmt.Sprintf("username=%s daily usage cleared", u.Username))
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- global rules ----

type rulesBody struct {
	WhitelistOnly bool     `json:"whitelist_only"`
	Whitelist     []string `json:"whitelist"`
	Blacklist     []string `json:"blacklist"`
}

func (p *Proxy) apiGlobalRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := p.store.Config()
		writeJSON(w, 200, cfg.GlobalRules)
	case http.MethodPut:
		var b rulesBody
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody)).Decode(&b); err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid body"})
			return
		}
		for _, list := range [][]string{b.Whitelist, b.Blacklist} {
			if err := validatePatterns(list); err != nil {
				writeJSON(w, 400, map[string]any{"error": err.Error()})
				return
			}
		}
		if err := p.store.Update(func(c *Config) error {
			c.GlobalRules = GlobalRules(b)
			return nil
		}); err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		p.audit.Record("rules.update", adminName(r), fmt.Sprintf("whitelist_only=%v wl=%d bl=%d",
			b.WhitelistOnly, len(b.Whitelist), len(b.Blacklist)))
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// ---- settings ----

func validListenAddr(addr string) bool {
	if addr == "" {
		return false
	}
	if strings.HasPrefix(addr, ":") {
		n, err := strconv.Atoi(addr[1:])
		return err == nil && n > 0 && n < 65536
	}
	if _, port, err := net.SplitHostPort(addr); err == nil {
		n, e := strconv.Atoi(port)
		return e == nil && n > 0 && n < 65536
	}
	return false
}

// tryBind verifies that addr can actually be bound right now. A settings
// save that persists an unbindable address (e.g. a privileged port while
// running as non-root, or an unresolvable host) would crash-loop the
// container on the next start, because Startup treats a failed bind as
// fatal. The check is skipped when the address is already bound (the
// current listener), which would otherwise report EADDRINUSE.
func tryBind(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

func (p *Proxy) apiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := p.store.Config()
		writeJSON(w, 200, map[string]any{"proxy": cfg.Proxy, "logs": cfg.Logs})
	case http.MethodPut:
		var b struct {
			Proxy *proxySettingsPatch `json:"proxy"`
			Logs  *logSettingsPatch   `json:"logs"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody)).Decode(&b); err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid body"})
			return
		}
		if b.Proxy == nil && b.Logs == nil {
			writeJSON(w, 400, map[string]any{"error": "no settings provided (send a \"proxy\" and/or \"logs\" object)"})
			return
		}
		// Merge semantics: only fields present in the JSON are applied, so
		// a partial PUT can never silently zero out omitted settings
		// (previously any omitted field, e.g. "enabled", was reset).
		cur := p.store.Config()
		next := cur
		if b.Proxy != nil {
			applyProxyPatch(&next.Proxy, b.Proxy)
		}
		if b.Logs != nil {
			applyLogPatch(&next.Logs, b.Logs)
		}
		if !validListenAddr(next.Proxy.ListenAddr) || !validListenAddr(next.Proxy.AdminListenAddr) {
			writeJSON(w, 400, map[string]any{"error": "invalid listen address (use :port or host:port)"})
			return
		}
		// Reject addresses that cannot actually be bound: persisting them
		// would crash-loop the container on the next start. Skip the check
		// for addresses that are already bound (current listeners).
		if next.Proxy.ListenAddr != cur.Proxy.ListenAddr {
			if err := tryBind(next.Proxy.ListenAddr); err != nil {
				writeJSON(w, 400, map[string]any{"error": "proxy listen address cannot be bound: " + err.Error()})
				return
			}
		}
		if next.Proxy.AdminListenAddr != cur.Proxy.AdminListenAddr {
			if err := tryBind(next.Proxy.AdminListenAddr); err != nil {
				writeJSON(w, 400, map[string]any{"error": "admin listen address cannot be bound: " + err.Error()})
				return
			}
		}
		for name, v := range map[string]int{
			"connect_timeout_sec": next.Proxy.ConnectTimeoutSec, "read_timeout_sec": next.Proxy.ReadTimeoutSec,
			"default_max_conns": next.Proxy.DefaultMaxConns, "max_global_conns": next.Proxy.MaxGlobalConns,
		} {
			if v < 0 || v > 100000 {
				writeJSON(w, 400, map[string]any{"error": name + " out of range"})
				return
			}
		}
		if next.Logs.RingSize < 100 || next.Logs.RingSize > 200000 {
			writeJSON(w, 400, map[string]any{"error": "ring_size must be 100..200000"})
			return
		}
		if next.Logs.FileMaxMB < 0 || next.Logs.FileMaxMB > 10000 {
			writeJSON(w, 400, map[string]any{"error": "file_max_mb out of range"})
			return
		}
		if err := p.store.Update(func(c *Config) error {
			c.Proxy = next.Proxy
			c.Logs = next.Logs
			return nil
		}); err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		p.audit.Record("settings.update", adminName(r), fmt.Sprintf("proxy_addr=%s admin_addr=%s ring=%d to_file=%v",
			next.Proxy.ListenAddr, next.Proxy.AdminListenAddr, next.Logs.RingSize, next.Logs.ToFile))
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// maxAdminBody bounds admin API request bodies (settings/users payloads are
// tiny; a multi-MB body is never legitimate).
const maxAdminBody = 1 << 20

// proxySettingsPatch / logSettingsPatch are partial settings updates: a nil
// pointer means "leave unchanged", so a PUT can change one field without
// resetting the others.
type proxySettingsPatch struct {
	Enabled           *bool   `json:"enabled"`
	ListenAddr        *string `json:"listen_addr"`
	AdminListenAddr   *string `json:"admin_listen_addr"`
	RequireAuth       *bool   `json:"require_auth"`
	AllowHTTP         *bool   `json:"allow_http"`
	AllowHTTPS        *bool   `json:"allow_https"`
	ConnectTimeoutSec *int    `json:"connect_timeout_sec"`
	ReadTimeoutSec    *int    `json:"read_timeout_sec"`
	DefaultMaxConns   *int    `json:"default_max_conns"`
	MaxGlobalConns    *int    `json:"max_global_conns"`
}

type logSettingsPatch struct {
	RingSize  *int  `json:"ring_size"`
	FileMaxMB *int  `json:"file_max_mb"`
	ToFile    *bool `json:"to_file"`
}

func applyProxyPatch(dst *ProxySettings, p *proxySettingsPatch) {
	if p.Enabled != nil {
		dst.Enabled = *p.Enabled
	}
	if p.ListenAddr != nil {
		dst.ListenAddr = *p.ListenAddr
	}
	if p.AdminListenAddr != nil {
		dst.AdminListenAddr = *p.AdminListenAddr
	}
	if p.RequireAuth != nil {
		dst.RequireAuth = *p.RequireAuth
	}
	if p.AllowHTTP != nil {
		dst.AllowHTTP = *p.AllowHTTP
	}
	if p.AllowHTTPS != nil {
		dst.AllowHTTPS = *p.AllowHTTPS
	}
	if p.ConnectTimeoutSec != nil {
		dst.ConnectTimeoutSec = *p.ConnectTimeoutSec
	}
	if p.ReadTimeoutSec != nil {
		dst.ReadTimeoutSec = *p.ReadTimeoutSec
	}
	if p.DefaultMaxConns != nil {
		dst.DefaultMaxConns = *p.DefaultMaxConns
	}
	if p.MaxGlobalConns != nil {
		dst.MaxGlobalConns = *p.MaxGlobalConns
	}
}

func applyLogPatch(dst *LogSettings, p *logSettingsPatch) {
	if p.RingSize != nil {
		dst.RingSize = *p.RingSize
	}
	if p.FileMaxMB != nil {
		dst.FileMaxMB = *p.FileMaxMB
	}
	if p.ToFile != nil {
		dst.ToFile = *p.ToFile
	}
}

// ---- logs ----

func (p *Proxy) apiLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	entries := p.logs.Recent(limit, q.Get("user"), q.Get("q"))
	writeJSON(w, 200, entries)
}

// apiLogsClear empties the activity log (in-memory ring + JSONL file).
func (p *Proxy) apiLogsClear(w http.ResponseWriter, r *http.Request) {
	n := p.logs.Count()
	p.logs.Clear()
	p.audit.Record("logs.clear", adminName(r), fmt.Sprintf("%d entries removed", n))
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiAudit returns the most recent admin-audit entries (newest first).
func (p *Proxy) apiAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, 200, p.audit.Recent(limit))
}

// ---- config export / import (backup & restore) ----

// configExport is the portable snapshot format: everything needed to restore
// a deployment except the session signing key (which is always regenerated
// on boot and is never exported or imported).
type configExport struct {
	Version     int           `json:"version"`
	Proxy       ProxySettings `json:"proxy"`
	GlobalRules GlobalRules   `json:"global_rules"`
	Logs        LogSettings   `json:"logs"`
	Users       []User        `json:"users"`
}

// maxImportBody bounds import snapshots (larger than the regular admin
// bodies: a config with thousands of users is legitimate).
const maxImportBody = 8 << 20

// apiExport streams the full configuration as a downloadable JSON snapshot.
func (p *Proxy) apiExport(w http.ResponseWriter, r *http.Request) {
	cfg := p.store.Config()
	exp := configExport{
		Version:     cfg.Version,
		Proxy:       cfg.Proxy,
		GlobalRules: cfg.GlobalRules,
		Logs:        cfg.Logs,
		Users:       cfg.Users,
	}
	p.audit.Record("config.export", adminName(r), fmt.Sprintf("users=%d", len(cfg.Users)))
	w.Header().Set("Content-Disposition", `attachment; filename="forward-proxy-config.json"`)
	writeJSON(w, 200, exp)
}

// apiImport replaces the live configuration with a validated snapshot. The
// session key is never imported; the change is atomic (Store.Update rolls
// back on failure) and audited.
func (p *Proxy) apiImport(w http.ResponseWriter, r *http.Request) {
	var exp configExport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxImportBody)).Decode(&exp); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid snapshot: " + err.Error()})
		return
	}
	if err := validateImportSnapshot(&exp); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	cur := p.store.Config()
	// Crash-loop guard: an imported address that cannot be bound would kill
	// the container on the next restart. Skip the check for the addresses
	// that are already bound.
	if exp.Proxy.ListenAddr != cur.Proxy.ListenAddr {
		if err := tryBind(exp.Proxy.ListenAddr); err != nil {
			writeJSON(w, 400, map[string]any{"error": "proxy listen address cannot be bound: " + err.Error()})
			return
		}
	}
	if exp.Proxy.AdminListenAddr != cur.Proxy.AdminListenAddr {
		if err := tryBind(exp.Proxy.AdminListenAddr); err != nil {
			writeJSON(w, 400, map[string]any{"error": "admin listen address cannot be bound: " + err.Error()})
			return
		}
	}
	if err := p.store.Update(func(c *Config) error {
		c.Version = 1
		c.Proxy = exp.Proxy
		c.GlobalRules = exp.GlobalRules
		c.Logs = exp.Logs
		c.Users = exp.Users
		// c.SessionKey deliberately untouched: signing keys are never
		// imported (all sessions invalidate on boot by design anyway).
		return nil
	}); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	who := adminName(r)
	p.audit.Record("config.import", who, fmt.Sprintf("users=%d proxy_addr=%s admin_addr=%s",
		len(exp.Users), exp.Proxy.ListenAddr, exp.Proxy.AdminListenAddr))
	resp := map[string]any{"ok": true, "users": len(exp.Users)}
	// Warn (do not block) when the importing admin would lose access: a
	// migration between deployments may legitimately use different admin
	// names, but a self-lockout should never be a surprise.
	if who != "" && !configHasEnabledAdminNamed(&exp, who) {
		resp["warnings"] = []string{fmt.Sprintf("the current admin user %q will no longer have access after this import"+
			" — make sure an enabled admin exists in the snapshot", who)}
	}
	writeJSON(w, 200, resp)
}

// configHasEnabledAdminNamed reports whether the snapshot contains an
// enabled admin with the given (case-insensitive) username.
func configHasEnabledAdminNamed(exp *configExport, name string) bool {
	for i := range exp.Users {
		if exp.Users[i].Enabled && exp.Users[i].Role == "admin" && strings.EqualFold(exp.Users[i].Username, name) {
			return true
		}
	}
	return false
}

// validateImportSnapshot checks every field of an imported snapshot so a bad
// file cannot produce a config that will not boot (invalid addresses,
// unparsable password hashes, duplicate users, no admin, ...).
func validateImportSnapshot(exp *configExport) error {
	if exp == nil {
		return fmt.Errorf("empty snapshot")
	}
	if !validListenAddr(exp.Proxy.ListenAddr) || !validListenAddr(exp.Proxy.AdminListenAddr) {
		return fmt.Errorf("invalid listen address (use :port or host:port)")
	}
	for name, v := range map[string]int{
		"connect_timeout_sec": exp.Proxy.ConnectTimeoutSec, "read_timeout_sec": exp.Proxy.ReadTimeoutSec,
		"default_max_conns": exp.Proxy.DefaultMaxConns, "max_global_conns": exp.Proxy.MaxGlobalConns,
	} {
		if v < 0 || v > 100000 {
			return fmt.Errorf("%s out of range", name)
		}
	}
	if exp.Logs.RingSize < 100 || exp.Logs.RingSize > 200000 {
		return fmt.Errorf("ring_size must be 100..200000")
	}
	if exp.Logs.FileMaxMB < 0 || exp.Logs.FileMaxMB > 10000 {
		return fmt.Errorf("file_max_mb out of range")
	}
	if err := validatePatterns(exp.GlobalRules.Whitelist); err != nil {
		return fmt.Errorf("global whitelist: %w", err)
	}
	if err := validatePatterns(exp.GlobalRules.Blacklist); err != nil {
		return fmt.Errorf("global blacklist: %w", err)
	}
	seenIDs := map[string]bool{}
	seenNames := map[string]bool{}
	admins := 0
	for i := range exp.Users {
		u := &exp.Users[i]
		if u.ID == "" {
			return fmt.Errorf("user #%d: missing id", i+1)
		}
		if seenIDs[u.ID] {
			return fmt.Errorf("duplicate user id %q", u.ID)
		}
		seenIDs[u.ID] = true
		name := strings.TrimSpace(u.Username)
		if !usernameRe.MatchString(name) {
			return fmt.Errorf("invalid username %q", u.Username)
		}
		key := strings.ToLower(name)
		if seenNames[key] {
			return fmt.Errorf("duplicate username %q", name)
		}
		seenNames[key] = true
		if u.Role != "user" && u.Role != "admin" {
			return fmt.Errorf("user %q: role must be user or admin", name)
		}
		if !validPasswordHash(u.PasswordHash) {
			return fmt.Errorf("user %q: invalid password hash", name)
		}
		if err := validatePatterns(u.Whitelist); err != nil {
			return fmt.Errorf("user %q whitelist: %w", name, err)
		}
		if err := validatePatterns(u.Blacklist); err != nil {
			return fmt.Errorf("user %q blacklist: %w", name, err)
		}
		if u.MaxConns < 0 || u.MaxConns > 100000 {
			return fmt.Errorf("user %q: max_conns out of range", name)
		}
		if u.DailyTrafficMB < 0 || u.DailyTrafficMB > 1000000 {
			return fmt.Errorf("user %q: daily_traffic_mb out of range", name)
		}
		if u.Role == "admin" && u.Enabled {
			admins++
		}
	}
	if admins == 0 {
		return fmt.Errorf("snapshot must contain at least one enabled admin")
	}
	return nil
}

// validPasswordHash checks a stored hash's format without running the KDF
// (verifying every user's hash on import would cost ~170 ms each).
func validPasswordHash(hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	n := 0
	fmt.Sscanf(parts[1], "%d", &n)
	return n >= 10000
}

func (p *Proxy) apiLogsExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	entries := p.logs.Recent(limit, q.Get("user"), q.Get("q"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="proxy-activity.csv"`)
	w.Write([]byte(p.logs.CSV(entries)))
}

// apiStatsTimeline returns time-bucketed traffic stats for the dashboard charts.
// Query: hours (1..168, default 24), bucket (seconds; auto when omitted),
// user (optional, case-insensitive).
func (p *Proxy) apiStatsTimeline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	bucket, _ := strconv.Atoi(q.Get("bucket"))
	if bucket <= 0 {
		bucket = (hours*3600 + 35) / 36 // ~36 buckets across the window
		if bucket < 60 {
			bucket = 60
		}
	}
	if bucket < 10 {
		bucket = 10
	}
	if bucket > 86400 {
		bucket = 86400
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	points, top := p.logs.Timeline(since, bucket, q.Get("user"))
	writeJSON(w, 200, map[string]any{
		"hours":      hours,
		"bucket_sec": bucket,
		"points":     points,
		"top_users":  top,
	})
}
