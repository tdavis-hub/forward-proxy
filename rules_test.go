package main

import (
	"strings"
	"testing"
	"time"
)

func TestCompileAndMatch(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "sub.example.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "notexample.com", false},
		{"*.example.com", "a.b.example.com", true},
		{"sub.*.example.com", "sub.x.example.com", true},
		{"sub.*.example.com", "sub.example.com", false},
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "192.168.1.1", false},
		{"192.168.1.1", "192.168.1.1", true},
		{"192.168.1.1", "192.168.1.2", false},
		{"*evil*", "somewhatevilhost", true},
		{"*evil*", "goodhost", false},
		{"?oogle.com", "google.com", true},
		{"?oogle.com", "xgoogle.com", false},
	}
	for _, c := range cases {
		r, err := compilePattern(c.pattern)
		if err != nil {
			t.Fatalf("compile %q: %v", c.pattern, err)
		}
		h := normalizeHost(c.host)
		if got := r.matches(h); got != c.want {
			t.Errorf("pattern %q vs host %q: got %v want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Example.com":      "example.com",
		"example.com:8080": "example.com",
		"[::1]:443":        "::1",
		"[2001:DB8::1]":    "2001:db8::1",
		"  host.example  ": "host.example",
		"":                 "",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBadPatterns(t *testing.T) {
	for _, p := range []string{"", "   ", "http://x", "bad host!", "10.0.0.0/33", "*."} {
		if _, err := compilePattern(p); err == nil {
			t.Errorf("expected error for pattern %q", p)
		}
	}
}

func TestEvaluatePrecedence(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	u, err := NewUser("alice", "password123", "user")
	if err != nil {
		t.Fatal(err)
	}
	u.Whitelist = []string{"good.example.com"}
	u.Blacklist = []string{"nope.example.com"}
	err = store.Update(func(c *Config) error {
		c.Users = append(c.Users, *u)
		c.GlobalRules.Blacklist = []string{"bad.example.com"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	re := NewRulesEngine()
	re.Rebuild(store.Config())

	if d := re.Evaluate(u, "good.example.com"); !d.Allowed {
		t.Errorf("whitelisted host should be allowed, got: %v", d.Reason)
	}
	if d := re.Evaluate(u, "bad.example.com"); d.Allowed {
		t.Errorf("global blacklist must win over user whitelist")
	}
	if d := re.Evaluate(u, "nope.example.com"); d.Allowed {
		t.Errorf("user blacklist must win over user whitelist")
	}
	if d := re.Evaluate(u, "other.example.com"); d.Allowed {
		t.Errorf("non-listed host must be denied when a whitelist exists: %v", d.Reason)
	}
	if d := re.Evaluate(u, "bad.example.com:443"); d.Allowed {
		t.Errorf("port-suffixed blacklisted host must be denied")
	}
}

func TestWhitelistOnlyMode(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := NewUser("bob", "password123", "user")
	err = store.Update(func(c *Config) error {
		c.Users = append(c.Users, *u)
		c.GlobalRules.WhitelistOnly = false
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	re := NewRulesEngine()
	re.Rebuild(store.Config())
	if d := re.Evaluate(u, "anything.example.com"); !d.Allowed {
		t.Errorf("no rules defined should default-allow: %v", d.Reason)
	}
	// whitelist-only with empty lists denies everything
	err = store.Update(func(c *Config) error {
		c.GlobalRules.WhitelistOnly = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	re.Rebuild(store.Config())
	if d := re.Evaluate(u, "anything.example.com"); d.Allowed {
		t.Errorf("whitelist_only with empty lists must deny")
	}
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("s3cret-pw")
	if err != nil {
		t.Fatal(err)
	}
	if h == "" || h == "s3cret-pw" {
		t.Fatal("hash must not be empty or the raw password")
	}
	if !VerifyPassword(h, "s3cret-pw") {
		t.Error("verify should succeed for correct password")
	}
	if VerifyPassword(h, "wrong-pw") {
		t.Error("verify should fail for wrong password")
	}
	dh, _ := HashPassword("admin123")
	if !IsDefaultPassword(dh) {
		t.Error("admin123 should be detected as default")
	}
	if IsDefaultPassword(h) {
		t.Error("s3cret-pw should not be detected as default")
	}
}

func TestSessionTokenRoundtrip(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	tok, err := issueToken(key, "admin", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	user, exp, _, ok := verifyToken(key, tok)
	if !ok || user != "admin" {
		t.Fatalf("token roundtrip failed: ok=%v user=%q exp=%d", ok, user, exp)
	}
	if _, _, _, ok := verifyToken("ffffffffffffffffffffffffffffffff", tok); ok {
		t.Error("token signed with a different key must be rejected")
	}
	old, _ := issueToken(key, "admin", -time.Minute, 0)
	if _, _, _, ok := verifyToken(key, old); ok {
		t.Error("expired token must be rejected")
	}
}

// TestUsernameValidation: the accepted charset and the documented 2-64 char
// length range (enforced both by the regex and by create validation).
func TestUsernameValidation(t *testing.T) {
	valid := []string{"ab", "alice", "a.b-c_d", strings.Repeat("a", 64)}
	for _, u := range valid {
		if !usernameRe.MatchString(u) {
			t.Fatalf("regex should accept %q", u)
		}
	}
	invalid := []string{"", "x", "a b", "ab!", strings.Repeat("a", 65)}
	for _, u := range invalid {
		if usernameRe.MatchString(u) {
			t.Fatalf("regex should reject %q", u)
		}
	}
	if err := (&userBody{Username: "x", Password: "secret1", Role: "user"}).validate(true); err == nil {
		t.Fatal("create validation should reject a 1-char username")
	}
	if err := (&userBody{Username: "ab", Password: "secret1", Role: "user"}).validate(true); err != nil {
		t.Fatalf("create validation should accept a 2-char username: %v", err)
	}
}

// ---- fuzz targets (seed corpus only; run `go test -fuzz` to fuzz) ----

func FuzzCompilePattern(f *testing.F) {
	for _, s := range []string{"example.com", "*.example.com", "10.0.0.0/8", "2001:DB8::1", "bad host!", "*", "a?b", "*.", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			t.Skip() // avoid pathological glob/regex compilation
		}
		r, err := compilePattern(s)
		if err != nil {
			return
		}
		// A compiled rule must never panic on arbitrary hosts.
		r.matches("anything.example.com")
		r.matches("")
		r.matches("\x00\x01")
	})
}

func FuzzNormalizeHost(f *testing.F) {
	for _, s := range []string{"example.com:8080", "[2001:db8::1]", "2001:DB8::1:", "10.0.0.1", "a:b:c", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		normalizeHost(s)
	})
}

func FuzzNormalizeTarget(f *testing.F) {
	for _, s := range []string{"example.com", "example.com:8443", "[::1]", "2001:db8::1", "EXAMPLE.com:", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		normalizeTarget(s)
	})
}

func FuzzVerifyToken(f *testing.F) {
	for _, s := range []string{"abc.def", "...", "a.b.c", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		verifyToken("0123456789abcdef0123456789abcdef", s)
	})
}
