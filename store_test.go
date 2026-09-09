package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func sameConfig(a, b Config) bool {
	ra, err1 := json.Marshal(a)
	rb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ra) == string(rb)
}

// sameConfigIgnoringKey compares configs with the session signing key
// excluded: it rotates on every boot by design, so a freshly loaded store
// never matches the previous boot's key even when everything else is equal.
func sameConfigIgnoringKey(a, b Config) bool {
	a.SessionKey, b.SessionKey = "", ""
	return sameConfig(a, b)
}

// TestUpdateRollback: a fn that mutates in place and then fails must not
// change the in-memory config nor the config file.
func TestUpdateRollback(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := st.Config()

	err = st.Update(func(c *Config) error {
		c.Users[0].Enabled = false
		c.Users[0].Blacklist = append(c.Users[0].Blacklist, "injected.example")
		c.Proxy.ListenAddr = ":9999"
		c.GlobalRules.Blacklist = append(c.GlobalRules.Blacklist, "injected.example")
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected error from fn")
	}

	after := st.Config()
	if !sameConfigIgnoringKey(after, before) {
		t.Fatalf("in-memory config not rolled back:\n got %+v\nwant %+v", after, before)
	}

	onDisk, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !sameConfigIgnoringKey(onDisk.Config(), before) {
		t.Fatalf("on-disk config not rolled back:\n got %+v\nwant %+v", onDisk.Config(), before)
	}
}

// TestUpdatePersistsAndNotifies: a successful update persists and fires the
// change listener with the new snapshot.
func TestUpdatePersistsAndNotifies(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got Config
	st.AddOnChange(func(c Config) { got = c })

	if err := st.Update(func(c *Config) error {
		c.Proxy.ListenAddr = ":3999"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got.Proxy.ListenAddr != ":3999" {
		t.Fatalf("listener snapshot wrong: %q", got.Proxy.ListenAddr)
	}
	onDisk, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.Config().Proxy.ListenAddr != ":3999" {
		t.Fatalf("disk not updated: %q", onDisk.Config().Proxy.ListenAddr)
	}
}

// TestSessionKeyRotatesOnBoot: the session signing key must be regenerated
// on every load (so admin sessions do not survive a container restart),
// even when a key was persisted by a previous boot.
func TestSessionKeyRotatesOnBoot(t *testing.T) {
	dir := t.TempDir()
	st1, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	key1 := st1.Config().SessionKey
	if key1 == "" {
		t.Fatal("fresh store must have a session key")
	}
	// Force the key to disk (any Update persists the whole config).
	if err := st1.Update(func(c *Config) error { c.Proxy.ListenAddr = ":3998"; return nil }); err != nil {
		t.Fatal(err)
	}
	st2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Config().SessionKey == key1 {
		t.Fatal("session key must be regenerated on a new boot")
	}
}

// TestConfigFileValid: the config file written by a fresh store parses back.
func TestConfigFileValid(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewStore(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil || len(b) == 0 {
		t.Fatalf("config file missing: %v", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if !c.Proxy.Enabled || c.Proxy.ListenAddr == "" {
		t.Fatalf("bad defaults: %+v", c.Proxy)
	}
}
