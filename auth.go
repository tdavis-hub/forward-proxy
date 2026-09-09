package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// pbkdf2 iter / block size used for password hashing. Iterations follow
// current OWASP guidance (600k for HMAC-SHA256). The iteration count is
// embedded in every hash string ("pbkdf2$iter$salt$hash"), so existing
// hashes keep verifying with their original count — only new hashes (new
// users, password changes) use the raised value. The verification cache
// keeps the per-request cost amortized.
const (
	pbkdf2Iterations = 600_000
	pbkdf2KeyLen     = 32

	// authCacheTTL / authCacheMax bound the PBKDF2 verification cache:
	// entries live at most authCacheTTL and the map holds at most
	// authCacheMax (hash, password) keys. The stored hash is part of the
	// key, so password changes invalidate entries immediately.
	authCacheTTL = 5 * time.Minute
	authCacheMax = 4096
)

// authCacheEntry is one cached verification result.
type authCacheEntry struct {
	ok      bool
	expires time.Time
}

// pbkdf2SHA256 implements RFC 2898 PBKDF2 with HMAC-SHA256 (stdlib only).
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(data []byte) []byte {
		mac := hmac.New(sha256.New, password)
		mac.Write(data)
		return mac.Sum(nil)
	}
	hashLen := len(prf(nil))
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		// U1 = PRF(password, salt || INT_32_BE(block))
		buf := make([]byte, len(salt)+4)
		copy(buf, salt)
		buf[len(salt)+0] = byte(block >> 24)
		buf[len(salt)+1] = byte(block >> 16)
		buf[len(salt)+2] = byte(block >> 8)
		buf[len(salt)+3] = byte(block)
		u := prf(buf)
		t := make([]byte, hashLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			u = prf(u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// HashPassword produces a "pbkdf2$iter$salt$hash" string (salt+hash hex-encoded).
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return fmt.Sprintf("pbkdf2$%d$%s$%s", pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// VerifyPassword checks a password against a stored hash.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iterations := 0
	fmt.Sscanf(parts[1], "%d", &iterations)
	if iterations < 10000 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// IsDefaultPassword reports whether a stored hash matches the factory default.
func IsDefaultPassword(hash string) bool {
	return VerifyPassword(hash, "admin123")
}

// ---- Admin session tokens (stateless, HMAC-signed) ----

// issueToken creates a session token: base64(payload).base64(hmac).
// Payload is {"u":"<username>","exp":unix,"v":<tokenEpoch>}. The epoch is
// the user's TokenEpoch at issue time; password changes bump it, so old
// tokens are rejected once the stored epoch moves past theirs.
func issueToken(sessionKey, username string, ttl time.Duration, tokenEpoch int64) (string, error) {
	payload, err := json.Marshal(map[string]any{
		"u":   username,
		"exp": time.Now().Add(ttl).Unix(),
		"v":   tokenEpoch,
	})
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(sessionKey))
	mac.Write([]byte(p))
	s := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return p + "." + s, nil
}

// verifyToken checks a session token and returns the username, expiry, and
// the token epoch embedded at issue time.
func verifyToken(sessionKey, token string) (username string, exp int64, epoch int64, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", 0, 0, false
	}
	p, s := parts[0], parts[1]
	rawMac, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", 0, 0, false
	}
	mac := hmac.New(sha256.New, []byte(sessionKey))
	mac.Write([]byte(p))
	if !hmac.Equal(rawMac, mac.Sum(nil)) {
		return "", 0, 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return "", 0, 0, false
	}
	var pl struct {
		U   string `json:"u"`
		Exp int64  `json:"exp"`
		V   int64  `json:"v"`
	}
	if err := json.Unmarshal(raw, &pl); err != nil || pl.U == "" {
		return "", 0, 0, false
	}
	if pl.Exp < time.Now().Unix() {
		return "", 0, 0, false
	}
	return pl.U, pl.Exp, pl.V, true
}

// verifyCached runs VerifyPassword with memoization: repeated requests with
// the same (stored hash, password) pair skip the ~170ms PBKDF2 and reuse the
// last result (TTL-bounded). The hash is in the key, so a password change
// immediately produces cache misses for the old password. The KDF is never
// run while holding the cache lock.
func (s *Store) verifyCached(hash, password string) bool {
	key := hash + "\x00\x00" + password
	now := time.Now()
	s.authCacheMu.Lock()
	if e, ok := s.authCache[key]; ok && now.Before(e.expires) {
		s.authCacheMu.Unlock()
		return e.ok
	}
	s.authCacheMu.Unlock()

	ok := VerifyPassword(hash, password)

	s.authCacheMu.Lock()
	if len(s.authCache) >= authCacheMax {
		for k, e := range s.authCache {
			if now.After(e.expires) {
				delete(s.authCache, k)
			}
		}
		if len(s.authCache) >= authCacheMax {
			// Still full of live entries: skip caching rather than evict
			// (the map is already bounded by authCacheMax).
			s.authCacheMu.Unlock()
			return ok
		}
	}
	s.authCache[key] = authCacheEntry{ok: ok, expires: now.Add(authCacheTTL)}
	s.authCacheMu.Unlock()
	return ok
}

// checkBasicAuth verifies an HTTP Basic header against the user store.
func (s *Store) checkBasicAuth(authHeader string) *User {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return nil
	}
	cred := string(decoded)
	i := strings.IndexByte(cred, ':')
	if i < 0 {
		return nil
	}
	user := s.FindUserByName(cred[:i])
	if user == nil || !user.Enabled {
		return nil
	}
	if !s.verifyCached(user.PasswordHash, cred[i+1:]) {
		return nil
	}
	return user
}

// validAdminFromRequest tries to authenticate the request as an enabled
// admin, in this order: session cookie, bearer token, then basic auth.
// Each credential source is tried independently, so a stale or invalid
// session cookie no longer shadows a valid bearer/basic credential
// (previously a lingering cookie forced 401 even with a fresh token).
func (s *Store) validAdminFromRequest(r *http.Request) *User {
	tokens := make([]string, 0, 2)
	if c, err := r.Cookie("fpx_session"); err == nil && c.Value != "" {
		tokens = append(tokens, c.Value)
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if tok := strings.TrimPrefix(h, "Bearer "); tok != "" {
			tokens = append(tokens, tok)
		}
	}
	for _, tok := range tokens {
		if u, _, epoch, ok := verifyToken(s.Config().SessionKey, tok); ok {
			if user := s.FindUserByName(u); user != nil && user.Enabled && user.Role == "admin" && user.TokenEpoch == epoch {
				return user
			}
		}
	}
	if h := r.Header.Get("Authorization"); h != "" {
		if user := s.checkBasicAuth(h); user != nil && user.Role == "admin" {
			return user
		}
	}
	return nil
}

// requireAdmin guards admin API handlers. It accepts a session cookie,
// a bearer token, or basic auth; any of them authenticating as an
// enabled admin is sufficient. Basic credentials are rate-limited per IP
// and per account (the same limiters as the proxy port and /api/login):
// without this, an attacker could brute-force the admin password and burn
// PBKDF2 CPU through any admin endpoint with random Basic headers.
func requireAdmin(p *Proxy) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			basic := isBasicAuth(r)
			ip := clientAddr(r)
			// Throttle before any PBKDF2 work. A valid session cookie or
			// bearer token exempts the request (the Basic header — if
			// present — is then irrelevant).
			if basic && !adminSessionValid(p, r) {
				if !p.proxyAuthAllowed(ip) || !p.accountAllowed(basicUserName(r.Header.Get("Authorization"))) {
					writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many failed authentication attempts, try again shortly"})
					return
				}
			}
			user := p.store.validAdminFromRequest(r)
			if user == nil {
				if basic && !adminSessionValid(p, r) {
					h := r.Header.Get("Authorization")
					p.proxyAuthFail(ip)
					p.accountFail(basicUserName(h))
					// Timing equalization for the username-existence oracle.
					p.equalizeAuthTiming(basicUserName(h), basicPassword(h))
				}
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "admin credentials required"})
				return
			}
			if basic {
				p.proxyAuthOK(ip)
				p.accountOK(user.Username)
			}
			r.Header.Set("X-Admin-User", user.Username)
			next(w, r)
		}
	}
}

// isBasicAuth reports whether the request carries an HTTP Basic credential.
func isBasicAuth(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Basic ")
}

// adminSessionValid reports whether the request carries a valid session
// cookie or bearer token (cheap HMAC verification; used to exempt
// token-authenticated requests from the Basic-credential limiter).
func adminSessionValid(p *Proxy, r *http.Request) bool {
	key := p.store.Config().SessionKey
	for _, tok := range sessionTokens(r) {
		if u, _, _, ok := verifyToken(key, tok); ok && u != "" {
			return true
		}
	}
	return false
}

func sessionToken(r *http.Request) string {
	toks := sessionTokens(r)
	if len(toks) > 0 {
		return toks[0]
	}
	return ""
}

// sessionTokens returns all session credentials present on the request:
// the fpx_session cookie and/or a Bearer token, in that order.
func sessionTokens(r *http.Request) []string {
	toks := make([]string, 0, 2)
	if c, err := r.Cookie("fpx_session"); err == nil && c.Value != "" {
		toks = append(toks, c.Value)
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if tok := strings.TrimPrefix(h, "Bearer "); tok != "" {
			toks = append(toks, tok)
		}
	}
	return toks
}

// equalizeAuthTiming runs a throwaway PBKDF2 when the username does not
// resolve to an enabled user, so "unknown user", "disabled user", and
// "wrong password" all cost about the same (one PBKDF2). For a known
// enabled user with a wrong password, the real verification has already
// paid that cost, so nothing more is needed — running the dummy there too
// would make the failure take twice as long and re-open a measurable
// user-existence timing oracle. Results are cached, so repeated probes of
// the same password stay cheap (and equal on both sides).
func (p *Proxy) equalizeAuthTiming(username, password string) {
	if username == "" {
		return
	}
	if u := p.store.FindUserByName(username); u != nil && u.Enabled {
		return // the real verification already ran
	}
	if h := p.getDummyHash(); h != "" {
		_ = p.store.verifyCached(h, password)
	}
}

// basicPassword extracts the password half of a Basic authorization header
// ("" when the header is missing or malformed). Used for timing equalization
// of failed proxy auth attempts.
func basicPassword(authHeader string) string {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return ""
	}
	cred := string(decoded)
	if i := strings.IndexByte(cred, ':'); i >= 0 {
		return cred[i+1:]
	}
	return ""
}

// writeJSON emits a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
