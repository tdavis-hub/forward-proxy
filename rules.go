package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
)

// Rule is a compiled whitelist/blacklist pattern.
type Rule struct {
	pattern string // original pattern text
	exact   string // exact-match host ("" if not exact)
	suffix  string // for "*.domain" patterns: the base domain
	regex   *regexp.Regexp
	cidr    *net.IPNet
}

// matches reports whether host satisfies the rule.
func (r *Rule) matches(host string) bool {
	if r.exact != "" {
		return host == r.exact
	}
	if r.suffix != "" {
		return host == r.suffix || strings.HasSuffix(host, "."+r.suffix)
	}
	if r.regex != nil {
		return r.regex.MatchString(host)
	}
	if r.cidr != nil {
		if ip := net.ParseIP(host); ip != nil {
			return r.cidr.Contains(ip)
		}
	}
	return false
}

// compilePattern compiles one pattern into a Rule.
// Supported: exact host, "*.domain", glob (*, ?), CIDR, bare IP.
func compilePattern(p string) (Rule, error) {
	r := Rule{pattern: p}
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return r, fmt.Errorf("empty pattern")
	}
	if strings.HasPrefix(p, "*.") {
		base := strings.TrimPrefix(p, "*.")
		if !validDomainPart(base) {
			return r, fmt.Errorf("bad wildcard base %q", base)
		}
		r.suffix = base
		return r, nil
	}
	if strings.Contains(p, "*") || strings.Contains(p, "?") {
		re, err := globToRegexp(p)
		if err != nil {
			return r, err
		}
		r.regex = re
		return r, nil
	}
	if _, _, err := net.ParseCIDR(p); err == nil {
		_, r.cidr, _ = net.ParseCIDR(p)
		return r, nil
	}
	if ip := net.ParseIP(p); ip != nil {
		// Bare IP literal (v4 or v6): store the canonical form so e.g.
		// "2001:0DB8::1" matches requests to "2001:db8::1".
		r.exact = ip.String()
		return r, nil
	}
	if validHost(p) {
		r.exact = p
		return r, nil
	}
	return r, fmt.Errorf("unrecognized pattern %q", p)
}

// globToRegexp converts a host glob ("*"/"?") into an anchored regexp.
func globToRegexp(g string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for _, c := range g {
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

func validDomainPart(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	return validDomainPart(s)
}

// matchAny returns the first rule matching host, or nil.
func matchAny(rules []Rule, host string) *Rule {
	for i := range rules {
		if rules[i].matches(host) {
			return &rules[i]
		}
	}
	return nil
}

// compileList compiles a list of patterns; invalid ones are skipped with a warning.
func compileList(patterns []string, label string) []Rule {
	out := make([]Rule, 0, len(patterns))
	for _, p := range patterns {
		r, err := compilePattern(p)
		if err != nil {
			log.Printf("WARN: skipping %s rule %q: %v", label, p, err)
			continue
		}
		out = append(out, r)
	}
	return out
}

// RulesEngine holds compiled rules for the current config snapshot.
// It is rebuilt on every config change; Evaluate must not take Store locks.
type RulesEngine struct {
	mu sync.RWMutex

	globalWhitelistOnly bool
	globalBlack         []Rule
	globalWhite         []Rule
	userRules           map[string]userRules
}

type userRules struct {
	whitelist []Rule
	blacklist []Rule
}

func NewRulesEngine() *RulesEngine {
	return &RulesEngine{userRules: map[string]userRules{}}
}

// Rebuild recompiles all rules from a config snapshot.
func (e *RulesEngine) Rebuild(cfg Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.globalWhitelistOnly = cfg.GlobalRules.WhitelistOnly
	e.globalBlack = compileList(cfg.GlobalRules.Blacklist, "global blacklist")
	e.globalWhite = compileList(cfg.GlobalRules.Whitelist, "global whitelist")
	e.userRules = make(map[string]userRules, len(cfg.Users))
	for _, u := range cfg.Users {
		e.userRules[u.ID] = userRules{
			whitelist: compileList(u.Whitelist, u.Username+" whitelist"),
			blacklist: compileList(u.Blacklist, u.Username+" blacklist"),
		}
	}
}

// RuleDecision is the outcome of evaluating a target host.
type RuleDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Matched string `json:"matched"` // pattern that decided ("" if allow-by-default)
}

// normalizeHost lowercases a host, strips brackets, and strips a port —
// including a bare trailing colon ("example.com:" → "example.com"), which
// previously escaped rule matching and let blacklist entries like
// "example.com" be bypassed with "http://example.com:/". IP literals are
// returned in canonical form without port mangling.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		port := h[i+1:]
		if port == "" || isNumericPort(port) {
			h = h[:i]
		}
	}
	return h
}

// normalizeTarget normalizes a CONNECT target (the value of the Host
// header in a CONNECT request) into a dialable "host:port" address.
// Missing and empty ports default to 443; IPv6 literals are bracketed
// (bare input arrives without them). Bracketed input is parsed manually
// because net.SplitHostPort rejects "[::1]" (no port) as an error.
func normalizeTarget(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	host, port := s, ""
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			host = s[1:i]
			if rest := s[i+1:]; strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
		}
	} else if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		port = "443"
	}
	return host + ":" + port
}

func isNumericPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Evaluate decides whether the given user may access the target host.
// A nil user (auth disabled, or a user not in the current snapshot) is
// judged by the global rules only and never panics.
// Precedence: global blacklist > user blacklist > whitelist (if any defined) > allow.
func (e *RulesEngine) Evaluate(user *User, host string) RuleDecision {
	h := normalizeHost(host)
	if h == "" {
		return RuleDecision{Allowed: false, Reason: "empty host"}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	if r := matchAny(e.globalBlack, h); r != nil {
		return RuleDecision{Allowed: false, Reason: fmt.Sprintf("blocked by global blacklist rule %q", r.pattern), Matched: r.pattern}
	}

	// Resolve the user's compiled rules; a missing user is treated like a
	// nil user (auth disabled / deleted mid-session) and judged by the
	// global whitelist gate only.
	known := user != nil
	var ur userRules
	if known {
		var ok bool
		ur, ok = e.userRules[user.ID]
		known = ok
	}
	if !known {
		if e.globalWhitelistOnly || len(e.globalWhite) > 0 {
			return whitelistGate(h, ur, e.globalWhite)
		}
		return RuleDecision{Allowed: true}
	}

	if r := matchAny(ur.blacklist, h); r != nil {
		return RuleDecision{Allowed: false, Reason: fmt.Sprintf("blocked by user blacklist rule %q", r.pattern), Matched: r.pattern}
	}
	needWhitelist := e.globalWhitelistOnly || user.WhitelistOnly ||
		len(e.globalWhite) > 0 || len(ur.whitelist) > 0
	if needWhitelist {
		return whitelistGate(h, ur, e.globalWhite)
	}
	return RuleDecision{Allowed: true}
}

// whitelistGate checks the user's whitelist, then the global whitelist;
// deny if neither matches.
func whitelistGate(h string, ur userRules, globalWhite []Rule) RuleDecision {
	if r := matchAny(ur.whitelist, h); r != nil {
		return RuleDecision{Allowed: true, Matched: r.pattern}
	}
	if r := matchAny(globalWhite, h); r != nil {
		return RuleDecision{Allowed: true, Matched: r.pattern}
	}
	return RuleDecision{Allowed: false, Reason: "host not in whitelist (whitelist mode active)"}
}
