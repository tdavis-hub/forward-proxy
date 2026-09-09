package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ProxySettings holds the transport-level proxy configuration.
type ProxySettings struct {
	Enabled           bool   `json:"enabled"`             // master switch for the proxy
	ListenAddr        string `json:"listen_addr"`         // proxy listen address, e.g. :3128
	AdminListenAddr   string `json:"admin_listen_addr"`   // admin UI/API listen address, e.g. :8080
	RequireAuth       bool   `json:"require_auth"`        // require user credentials for proxied traffic
	AllowHTTP         bool   `json:"allow_http"`          // allow plain-HTTP forward requests
	AllowHTTPS        bool   `json:"allow_https"`         // allow CONNECT (HTTPS tunneling)
	ConnectTimeoutSec int    `json:"connect_timeout_sec"` // upstream connect timeout
	ReadTimeoutSec    int    `json:"read_timeout_sec"`    // per-request idle timeout
	DefaultMaxConns   int    `json:"default_max_conns"`   // per-user concurrent connection cap (0 = unlimited)
	MaxGlobalConns    int    `json:"max_global_conns"`    // global concurrent connection cap (0 = unlimited)
}

// LogSettings controls the activity log.
type LogSettings struct {
	RingSize  int  `json:"ring_size"`   // in-memory ring buffer size
	FileMaxMB int  `json:"file_max_mb"` // JSONL file max size in MB (0 = disable file logging)
	ToFile    bool `json:"to_file"`     // write JSONL activity file
}

// GlobalRules are rules that apply to every user, checked before per-user rules.
type GlobalRules struct {
	WhitelistOnly bool     `json:"whitelist_only"` // when true, only whitelisted hosts may be accessed
	Whitelist     []string `json:"whitelist"`
	Blacklist     []string `json:"blacklist"`
}

// UserStats are cumulative per-user counters.
type UserStats struct {
	Requests      uint64 `json:"requests"`
	BytesIn       uint64 `json:"bytes_in"`
	BytesOut      uint64 `json:"bytes_out"`
	LastRequestAt string `json:"last_request_at"`
}

// User is a single proxy account.
type User struct {
	ID             string    `json:"id"`
	Username       string    `json:"username"`
	PasswordHash   string    `json:"password_hash"`
	Enabled        bool      `json:"enabled"`
	Role           string    `json:"role"`           // "user" or "admin"
	WhitelistOnly  bool      `json:"whitelist_only"` // when true, user may only hit their whitelist
	Whitelist      []string  `json:"whitelist"`
	Blacklist      []string  `json:"blacklist"`
	MaxConns       int       `json:"max_conns"`        // 0 = use global default
	DailyTrafficMB int       `json:"daily_traffic_mb"` // 0 = unlimited
	CreatedAt      string    `json:"created_at"`
	LastUsedAt     string    `json:"last_used_at"`
	Stats          UserStats `json:"stats"`
	// TokenEpoch is bumped on every password change. Admin session tokens
	// carry the epoch they were issued at, so changing a password
	// immediately invalidates all previously issued sessions.
	TokenEpoch int64 `json:"token_epoch"`
}

// Config is the root configuration document.
type Config struct {
	Version     int           `json:"version"`
	SessionKey  string        `json:"session_key"`
	Proxy       ProxySettings `json:"proxy"`
	GlobalRules GlobalRules   `json:"global_rules"`
	Logs        LogSettings   `json:"logs"`
	Users       []User        `json:"users"`
}

// Store persists Config to a JSON file and notifies listeners on change.
// Listeners receive a snapshot copy and are invoked AFTER the lock is released.
type Store struct {
	mu       sync.RWMutex
	path     string
	cfg      Config
	onChange []func(Config)

	// byID / byName are O(1) lookup indexes over cfg.Users, rebuilt on
	// every successful Update and at load time. Names are indexed
	// lowercased, matching the case-insensitive login lookup.
	byID   map[string]int
	byName map[string]int

	// authCache memoizes PBKDF2 verification results so repeated proxy /
	// admin requests do not pay the full KDF cost on every call. The stored
	// password hash is part of the key, so a password change (new hash)
	// immediately invalidates old entries. Bounded and TTL'd.
	authCacheMu sync.Mutex
	authCache   map[string]authCacheEntry
}

// NewStore loads the config from path or creates a fresh default one.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dir, "config.json")
	s := &Store{path: path, authCache: map[string]authCacheEntry{}}

	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		if jerr := json.Unmarshal(raw, &s.cfg); jerr != nil {
			return nil, fmt.Errorf("parse %s: %w", path, jerr)
		}
		s.migrate()
	} else {
		s.cfg = defaultConfig()
		if err := s.Save(); err != nil {
			return nil, err
		}
	}
	s.rebuildIndex()
	return s, nil
}

// rebuildIndex rebuilds the user lookup maps; called under the write lock
// after every successful config change and once at load.
func (s *Store) rebuildIndex() {
	s.byID = make(map[string]int, len(s.cfg.Users))
	s.byName = make(map[string]int, len(s.cfg.Users))
	for i := range s.cfg.Users {
		s.byID[s.cfg.Users[i].ID] = i
		s.byName[strings.ToLower(s.cfg.Users[i].Username)] = i
	}
}

func (s *Store) migrate() {
	// The session signing key is deliberately NOT carried over from a
	// previous boot: regenerate it on every start so that stateless admin
	// session tokens are invalidated when the container restarts.
	s.cfg.SessionKey = randomHex(32)
	if s.cfg.Version < 1 {
		s.cfg.Version = 1
	}
	if s.cfg.Proxy.ConnectTimeoutSec == 0 {
		s.cfg.Proxy.ConnectTimeoutSec = 15
	}
	if s.cfg.Proxy.ReadTimeoutSec == 0 {
		s.cfg.Proxy.ReadTimeoutSec = 300
	}
	// Log settings: fill defaults only for a config that never had a Logs
	// block written (all fields zero, i.e. pre-v0). Explicit values —
	// including the valid "file logging disabled" settings ToFile=false /
	// FileMaxMB=0 exposed in the admin UI — are left untouched on every
	// subsequent boot.
	if logsNeverWritten(s.cfg.Logs) {
		s.cfg.Logs = LogSettings{RingSize: 20000, FileMaxMB: 10, ToFile: true}
	}
}

// logsNeverWritten reports whether a Logs block has never been populated
// (all fields zero), as in configs written before log settings existed.
func logsNeverWritten(l LogSettings) bool {
	return l.RingSize == 0 && l.FileMaxMB == 0 && !l.ToFile
}

func defaultConfig() Config {
	admin, _ := NewUser("admin", "admin123", "admin")
	return Config{
		Version:    1,
		SessionKey: randomHex(32),
		Proxy: ProxySettings{
			Enabled:           true,
			ListenAddr:        envOr("PROXY_ADDR", ":3128"),
			AdminListenAddr:   envOr("ADMIN_ADDR", ":8080"),
			RequireAuth:       true,
			AllowHTTP:         true,
			AllowHTTPS:        true,
			ConnectTimeoutSec: 15,
			ReadTimeoutSec:    300,
			DefaultMaxConns:   25,
			MaxGlobalConns:    0,
		},
		GlobalRules: GlobalRules{},
		Logs: LogSettings{
			RingSize:  20000,
			FileMaxMB: 10,
			ToFile:    true,
		},
		Users: []User{*admin},
	}
}

// Config returns a copy of the current config.
func (s *Store) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// WithConfig runs fn with a read lock held, passing a copy of the current config.
func (s *Store) WithConfig(fn func(Config)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(s.cfg)
}

// Update mutates the config under a write lock, then persists it and
// notifies listeners with a snapshot (lock already released).
// Update applies fn to the config under the write lock. fn receives a live
// pointer, so it may mutate in place; if it returns an error the in-memory
// config is rolled back to a deep snapshot taken beforehand (a plain struct
// copy would not suffice: slices are shared with fn's mutations). The config
// is only persisted and listeners only fire on success.
func (s *Store) Update(fn func(*Config) error) error {
	return s.update(fn, true)
}

// UpdateSilent is like Update but does not fire the onChange listeners. It
// is used for stats-only persistence (e.g. the periodic FlushStats tick),
// which must not recompile rules or rebind listeners.
func (s *Store) UpdateSilent(fn func(*Config) error) error {
	return s.update(fn, false)
}

func (s *Store) update(fn func(*Config) error, notify bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(s.cfg)
	if err != nil {
		return fmt.Errorf("snapshot config: %w", err)
	}
	if err := fn(&s.cfg); err != nil {
		if rerr := json.Unmarshal(raw, &s.cfg); rerr != nil {
			log.Printf("ERROR: config rollback failed: %v", rerr)
		}
		return err
	}
	if err := s.saveLocked(); err != nil {
		return err
	}
	s.rebuildIndex()
	if notify {
		snap := s.cfg
		for _, l := range s.onChange {
			l(snap)
		}
	}
	return nil
}

// AddOnChange registers a callback invoked after every successful Update.
func (s *Store) AddOnChange(fn func(Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, fn)
}

// Save writes the config atomically (temp file + rename).
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	// Keep a backup of the previous config file for manual recovery (e.g.
	// after a power loss mid-write or a bad manual edit). The file is
	// small; the cost of one extra write per save is negligible.
	if cur, err := os.ReadFile(s.path); err == nil {
		_ = os.WriteFile(s.path+".bak", cur, 0o600)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// FindUser returns the user with the given ID (or nil).
func (s *Store) FindUser(id string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.byID[id]
	if ok && i >= 0 && i < len(s.cfg.Users) && s.cfg.Users[i].ID == id {
		u := s.cfg.Users[i]
		return &u
	}
	return nil
}

// FindUserByName returns the user with the given username (or nil),
// case-insensitively.
func (s *Store) FindUserByName(name string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := strings.ToLower(name)
	i, ok := s.byName[key]
	if ok && i >= 0 && i < len(s.cfg.Users) && strings.EqualFold(s.cfg.Users[i].Username, name) {
		u := s.cfg.Users[i]
		return &u
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewUser creates a user with a hashed password.
func NewUser(username, password, role string) (*User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	if role != "admin" {
		role = "user"
	}
	return &User{
		ID:           randomHex(8),
		Username:     strings.TrimSpace(username),
		PasswordHash: hash,
		Enabled:      true,
		Role:         role,
		MaxConns:     0,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}
