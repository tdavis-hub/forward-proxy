package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTimelineAggregation: bucketing, zero-fill, outcome classification,
// per-user totals, and the user filter.
func TestTimelineAggregation(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(c *Config) error { c.Logs.ToFile = false; return nil }); err != nil {
		t.Fatal(err)
	}
	ls := NewLogStore(st, t.TempDir())

	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Truncate(time.Second).Format(time.RFC3339) }
	ls.Add(LogEntry{Time: ts(0), User: "alice", Method: "GET", Host: "a.com", Path: "/", Outcome: "ALLOWED", Status: 200, BytesOut: 1 << 20})
	ls.Add(LogEntry{Time: ts(-time.Minute), User: "alice", Method: "GET", Host: "b.com", Path: "/", Outcome: "DENIED: blacklisted", Status: 403})
	ls.Add(LogEntry{Time: ts(-2 * time.Minute), User: "bob", Method: "GET", Host: "c.com", Path: "/", Outcome: "ERROR: dial", Status: 502, BytesIn: 100})
	// Outside the 1h window: must not be counted.
	ls.Add(LogEntry{Time: ts(-2 * time.Hour), User: "alice", Method: "GET", Host: "d.com", Path: "/", Outcome: "ALLOWED", Status: 200, BytesOut: 9 << 20})

	since := time.Now().Add(-time.Hour)
	points, top := ls.Timeline(since, 60, "")

	var req, al, de, er int
	var bin, bout uint64
	var zeroGaps int
	for _, p := range points {
		req += p.Requests
		al += p.Allowed
		de += p.Denied
		er += p.Errors
		bin += p.BytesIn
		bout += p.BytesOut
		if p.Requests == 0 {
			zeroGaps++
		}
	}
	if len(points) < 60 || len(points) > 62 {
		t.Fatalf("expected ~61 one-minute buckets, got %d", len(points))
	}
	if zeroGaps == 0 {
		t.Fatal("expected zero-filled buckets in the middle of the window")
	}
	if req != 3 {
		t.Fatalf("requests: got %d want 3", req)
	}
	if al != 1 || de != 1 || er != 1 {
		t.Fatalf("classification: allowed=%d denied=%d errors=%d (want 1/1/1)", al, de, er)
	}
	if bin != 100 || bout != 1<<20 {
		t.Fatalf("bytes: in=%d want 100, out=%d want %d", bin, bout, 1<<20)
	}
	if len(top) != 2 || top[0].User != "alice" || top[1].User != "bob" {
		t.Fatalf("top users: %+v (want alice first, then bob)", top)
	}
	if top[0].Requests != 2 || top[0].BytesOut != 1<<20 {
		t.Fatalf("alice totals: %+v", top[0])
	}

	// User filter.
	points, top = ls.Timeline(since, 60, "ALICE")
	req = 0
	for _, p := range points {
		req += p.Requests
	}
	if req != 2 {
		t.Fatalf("filtered requests: got %d want 2", req)
	}
	if len(top) != 1 || top[0].User != "alice" {
		t.Fatalf("filtered top users: %+v", top)
	}
}

// TestRecentFiltering: the text-search filter must return matching entries
// (regression: an unconditional `continue` used to drop ALL matches, so the
// logs search box always showed zero results), and combine correctly with
// the per-user filter, case-insensitively.
func TestRecentFiltering(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ls := NewLogStore(st, t.TempDir())
	ls.Add(LogEntry{Time: "2026-01-01T00:00:00Z", User: "alice", Method: "GET", Host: "example.com", Path: "/a", Status: 200, Outcome: "ALLOWED"})
	ls.Add(LogEntry{Time: "2026-01-01T00:00:01Z", User: "bob", Method: "CONNECT", Host: "other.org", Path: "", Status: 502, Outcome: "ERROR: dial refused"})
	ls.Add(LogEntry{Time: "2026-01-01T00:00:02Z", User: "carol", Method: "GET", Host: "example.org", Path: "/b", Status: 403, Outcome: "DENIED: blacklisted"})

	if got := ls.Recent(100, "", ""); len(got) != 3 {
		t.Fatalf("no filter: got %d entries, want 3", len(got))
	}
	// Text query matches host / path / outcome / method / user.
	if got := ls.Recent(100, "", "example"); len(got) != 2 {
		t.Fatalf("query 'example': got %d entries, want 2 (host matches)", len(got))
	}
	if got := ls.Recent(100, "", "refused"); len(got) != 1 || got[0].Host != "other.org" {
		t.Fatalf("query 'refused': got %+v, want the ERROR entry", got)
	}
	// Case-insensitive.
	if got := ls.Recent(100, "", "EXAMPLE"); len(got) != 2 {
		t.Fatalf("query 'EXAMPLE' (case): got %d entries, want 2", len(got))
	}
	// User filter alone and combined with the text query.
	if got := ls.Recent(100, "alice", ""); len(got) != 1 || got[0].User != "alice" {
		t.Fatalf("user filter alice: got %+v", got)
	}
	if got := ls.Recent(100, "alice", "example"); len(got) != 1 {
		t.Fatalf("user+query: got %d entries, want 1", len(got))
	}
	if got := ls.Recent(100, "bob", "example"); len(got) != 0 {
		t.Fatalf("user+query no-match: got %d entries, want 0", len(got))
	}
	// Limit still applies with a query.
	if got := ls.Recent(1, "", "example"); len(got) != 1 {
		t.Fatalf("limit+query: got %d entries, want 1", len(got))
	}
}

// TestLogStoreClear: Clear empties the ring and truncates the JSONL file so
// a restart does not resurrect old entries, and logging continues to work
// afterwards.
func TestLogStoreClear(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(c *Config) error {
		c.Logs = LogSettings{RingSize: 1000, FileMaxMB: 10, ToFile: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ls := NewLogStore(st, dir)
	ls.Add(LogEntry{Time: "2026-01-01T00:00:00Z", User: "alice", Method: "GET", Host: "a.com", Outcome: "ALLOWED", Status: 200})
	ls.Add(LogEntry{Time: "2026-01-01T00:00:01Z", User: "bob", Method: "GET", Host: "b.com", Outcome: "DENIED", Status: 403})
	if got := ls.Recent(100, "", ""); len(got) != 2 {
		t.Fatalf("expected 2 entries before clear, got %d", len(got))
	}

	ls.Clear()
	if got := ls.Recent(100, "", ""); len(got) != 0 {
		t.Fatalf("ring not cleared: %d entries remain", len(got))
	}

	// Logging still works after the clear, and the new entry is persisted
	// (the JSONL writer is buffered; flush like a graceful shutdown would).
	ls.Add(LogEntry{Time: "2026-01-01T00:00:02Z", User: "carol", Method: "GET", Host: "c.com", Outcome: "ALLOWED", Status: 200})
	ls.Flush()
	if got := ls.Recent(100, "", ""); len(got) != 1 || got[0].User != "carol" {
		t.Fatalf("post-clear logging broken: %+v", got)
	}

	// A fresh store on the same dir must reload only the new entry: the
	// file was truncated, so the old entries cannot come back on restart.
	ls2 := NewLogStore(st, dir)
	if got := ls2.Recent(100, "", ""); len(got) != 1 || got[0].User != "carol" {
		t.Fatalf("reload after clear resurrected old entries: %+v", got)
	}
}

// TestLogStoreBufferedFlush: the JSONL writer is buffered — entries are
// only visible in the file after Flush (which the 5s ticker and shutdown
// call).
func TestLogStoreBufferedFlush(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(c *Config) error {
		c.Logs = LogSettings{RingSize: 1000, FileMaxMB: 10, ToFile: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ls := NewLogStore(st, dir)
	ls.Add(LogEntry{Time: "2026-01-01T00:00:00Z", User: "alice", Method: "GET", Host: "a.com", Outcome: "ALLOWED", Status: 200})

	path := filepath.Join(dir, "activity.jsonl")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ls.Flush()
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() <= before.Size() {
		t.Fatalf("Flush did not write buffered lines to disk (%d -> %d bytes)", before.Size(), after.Size())
	}
}

func FuzzCSVField(f *testing.F) {
	for _, s := range []string{"plain", `a"b,c`, "line\nbreak", "tab\there", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = csvField(s)
	})
}
