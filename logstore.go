package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogEntry is one activity record.
type LogEntry struct {
	Time       string `json:"time"`
	User       string `json:"user"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	Outcome    string `json:"outcome"` // "ALLOWED", "DENIED: reason", "CONNECT", "ERROR: reason"
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	DurationMs int64  `json:"duration_ms"`
	Client     string `json:"client"`

	// t is the parsed Unix timestamp of Time, set once at Add/load so
	// timeline aggregation never re-parses every entry string on each
	// dashboard poll. Never serialized.
	t int64
}

// LogStore keeps a bounded in-memory ring plus an optional JSONL file.
type LogStore struct {
	mu       sync.RWMutex
	store    *Store
	dir      string
	entries  []LogEntry
	file     *os.File
	bw       *bufio.Writer // buffered writer over file (nil when file is nil)
	fileSize int64         // logical bytes written (buffer may lag slightly)
	warned   bool          // one-shot write-failure warning
}

func NewLogStore(store *Store, dir string) *LogStore {
	l := &LogStore{store: store, dir: dir}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return l
	}
	l.openFile()
	l.loadFile()
	return l
}

func (l *LogStore) openFile() {
	path := filepath.Join(l.dir, "activity.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	l.file = f
	l.bw = bufio.NewWriterSize(f, 64*1024)
	if st, err := f.Stat(); err == nil {
		l.fileSize = st.Size()
	}
}

// loadFile reloads the most recent lines of the JSONL file into the ring
// buffer on start. To bound startup memory and time, at most the newest
// `max` (ring size) lines are loaded: the file is first walked
// backwards (1 MiB chunks) to find where those lines begin, and only
// that suffix is read (with a hard read cap), never the whole file.
func (l *LogStore) loadFile() {
	cfg := l.store.Config()
	if l.file == nil || !cfg.Logs.ToFile || cfg.Logs.FileMaxMB == 0 {
		return
	}
	max := cfg.Logs.RingSize
	if max <= 0 {
		max = 20000
	}
	f, err := os.OpenFile(l.file.Name(), os.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return
	}
	size := st.Size()

	// Pass 1: walk backwards from EOF counting newlines until the
	// (max+1)-th one from the end — the newest `max` lines start right
	// after it. Hitting the start of the file first means the whole
	// file holds fewer lines than that.
	const chunk = 1 << 20
	rem := max + 1
	off := int64(0)
	pos := size
	for pos > 0 {
		start := pos - chunk
		if start < 0 {
			start = 0
		}
		buf := make([]byte, pos-start)
		n, _ := f.ReadAt(buf, start)
		for i := n - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				rem--
				if rem == 0 {
					off = start + int64(i) + 1
					pos = 0
					break
				}
			}
		}
		if pos == 0 {
			break
		}
		pos = start
	}
	// Hard cap on the read: even a file made of very few (each up to 1
	// MiB, skipped) huge lines must not blow up memory.
	const maxRead = 64 << 20
	if size-off > maxRead {
		off = size - maxRead
	}
	tail := make([]byte, size-off)
	if _, err := f.ReadAt(tail, off); err != nil && err != io.EOF {
		return
	}
	var lines []string
	rest := tail
	for len(rest) > 0 {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			break // final line unterminated (truncated write) — skip it
		}
		line := rest[:i]
		if len(line) > 0 && len(line) <= 1<<20 {
			lines = append(lines, string(line))
		}
		rest = rest[i+1:]
	}
	// If the tail window was shrunk by the read cap, its first fragment
	// may start mid-line; drop it unless the byte before the window is a
	// newline (the normal case: off points right after a newline).
	if off > 0 && len(lines) > 0 {
		var b [1]byte
		if _, err := f.ReadAt(b[:], off-1); err == nil && b[0] != '\n' {
			lines = lines[1:]
		}
	}
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	l.mu.Lock()
	l.entries = make([]LogEntry, 0, len(lines))
	for _, line := range lines {
		var e LogEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
				e.t = t.Unix()
			}
			l.entries = append(l.entries, e)
		}
	}
	l.mu.Unlock()
}

// Clear empties the activity log: the in-memory ring is reset and the JSONL
// file is truncated (reopened with O_TRUNC), so a restart cannot resurrect
// the cleared entries. User stats are NOT affected — this only touches the
// activity log. If reopening the file fails, in-memory logging continues and
// file logging resumes on the next rotation.
func (l *LogStore) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = l.entries[:0]
	if l.file != nil {
		if l.bw != nil {
			_ = l.bw.Flush()
		}
		path := l.file.Name()
		l.file.Close()
		l.file = nil
		l.bw = nil
		l.fileSize = 0
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|os.O_TRUNC, 0o600); err == nil {
			l.file = f
			l.bw = bufio.NewWriterSize(f, 64*1024)
		}
	}
}

// Add records one activity entry.
func (l *LogStore) Add(e LogEntry) {
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
		e.t = t.Unix()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cfg := l.store.Config()
	l.entries = append(l.entries, e)
	max := cfg.Logs.RingSize
	if max <= 0 {
		max = 20000
	}
	if len(l.entries) > max {
		l.entries = l.entries[len(l.entries)-max:]
	}
	if cfg.Logs.ToFile && cfg.Logs.FileMaxMB > 0 {
		l.writeFileLocked(e, int64(cfg.Logs.FileMaxMB)*1024*1024)
	}
}

func (l *LogStore) writeFileLocked(e LogEntry, maxBytes int64) {
	if l.bw == nil {
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	if l.fileSize+int64(len(line)) > maxBytes {
		// Rotate: keep the tail half of the file.
		l.rotateLocked()
		if l.bw == nil {
			return
		}
	}
	if _, err := l.bw.Write(append(line, '\n')); err != nil {
		if !l.warned {
			log.Printf("WARN: activity log write failed: %v (file logging suspended until the next rotation)", err)
			l.warned = true
		}
		return
	}
	l.warned = false
	l.fileSize += int64(len(line) + 1)
}

// Count returns the number of entries currently in the ring.
func (l *LogStore) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// Flush pushes any buffered activity-log lines to disk. Called
// periodically (FlushStats tick) and on shutdown.
func (l *LogStore) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bw != nil {
		_ = l.bw.Flush()
	}
}

// rotateLocked truncates the activity file to its newest half. The
// rewrite is atomic (temp file + rename) and the append handle is
// reopened unconditionally, so any failure — bad disk, full FS, rename
// error — leaves file logging working instead of silently dead for the
// rest of the process lifetime.
func (l *LogStore) rotateLocked() {
	path := l.file.Name()
	if l.bw != nil {
		_ = l.bw.Flush() // push buffered lines before truncating
	}
	l.file.Close()
	l.file = nil
	l.bw = nil
	l.fileSize = 0

	if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
		defer f.Close()
		if st, err := f.Stat(); err == nil {
			size := st.Size()
			keep := size / 2
			if keep > 0 {
				if _, err := f.Seek(keep, 0); err == nil {
					data, _ := ioReadAll(f, size-keep)
					tmp := path + ".rot"
					if werr := os.WriteFile(tmp, data, 0o600); werr == nil {
						if rerr := os.Rename(tmp, path); rerr != nil {
							os.Remove(tmp)
						}
					} else {
						os.Remove(tmp)
					}
				}
			}
		}
	}
	// Always end with a usable append handle.
	l.openFile()
}

// ioReadAll reads exactly up to n bytes in one call.
func ioReadAll(f *os.File, n int64) ([]byte, error) {
	buf := make([]byte, n)
	m, _ := f.Read(buf)
	return buf[:m], nil
}

// Recent returns up to limit most-recent entries, newest first,
// optionally filtered by user and a substring query.
func (l *LogStore) Recent(limit int, user, query string) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}
	out := make([]LogEntry, 0, limit)
	for i := len(l.entries) - 1; i >= 0 && len(out) < limit; i-- {
		e := l.entries[i]
		if user != "" && !strings.EqualFold(e.User, user) {
			continue
		}
		if query != "" {
			q := strings.ToLower(query)
			hay := strings.ToLower(e.Method + " " + e.Host + " " + e.Path + " " + e.Outcome + " " + e.User)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// csvField renders one CSV field with RFC 4180 quoting: quoted (with
// embedded quotes doubled) when the field contains a quote, comma, or
// line break; passed through otherwise.
func csvField(s string) string {
	if strings.ContainsAny(s, `",`+"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// CSV renders entries as RFC 4180 CSV rows.
func (l *LogStore) CSV(entries []LogEntry) string {
	var b strings.Builder
	fmt.Fprintln(&b, "time,user,method,host,path,outcome,status,bytes_in,bytes_out,duration_ms,client")
	for _, e := range entries {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%s\n",
			csvField(e.Time), csvField(e.User), csvField(e.Method), csvField(e.Host),
			csvField(e.Path), csvField(e.Outcome), e.Status, e.BytesIn, e.BytesOut,
			e.DurationMs, csvField(e.Client))
	}
	return b.String()
}

// TimelinePoint is one aggregated time bucket.
type TimelinePoint struct {
	T        int64  `json:"t"`
	Requests int    `json:"requests"`
	Allowed  int    `json:"allowed"`
	Denied   int    `json:"denied"`
	Errors   int    `json:"errors"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

// UserAgg is per-user totals within a window.
type UserAgg struct {
	User     string `json:"user"`
	Requests int    `json:"requests"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

// Timeline aggregates all ring entries in [since, now] into buckets of
// bucketSec seconds, zero-filled across the whole window, plus per-user
// totals for the top 10 users by data. An optional user (case-insensitive)
// restricts the aggregation to that user.
func (l *LogStore) Timeline(since time.Time, bucketSec int, user string) ([]TimelinePoint, []UserAgg) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	bk := int64(bucketSec)
	type acc struct {
		requests, allowed, denied, errors int
		bin, bout                         uint64
	}
	buckets := make(map[int64]*acc)
	users := make(map[string]*acc)
	for i := range l.entries {
		e := &l.entries[i]
		var t time.Time
		if e.t != 0 {
			t = time.Unix(e.t, 0)
		} else {
			parsed, err := time.Parse(time.RFC3339, e.Time)
			if err != nil {
				continue
			}
			t = parsed
		}
		if t.Before(since) || t.After(now) {
			continue
		}
		if user != "" && !strings.EqualFold(e.User, user) {
			continue
		}
		b := t.Unix() / bk * bk
		a := buckets[b]
		if a == nil {
			a = &acc{}
			buckets[b] = a
		}
		a.requests++
		switch {
		case strings.HasPrefix(e.Outcome, "DENIED"):
			a.denied++
		case strings.HasPrefix(e.Outcome, "ERROR"):
			a.errors++
		default:
			a.allowed++
		}
		a.bin += e.BytesIn
		a.bout += e.BytesOut
		if e.User != "" {
			u := users[e.User]
			if u == nil {
				u = &acc{}
				users[e.User] = u
			}
			u.requests++
			u.bin += e.BytesIn
			u.bout += e.BytesOut
		}
	}
	first := since.Unix() / bk * bk
	last := now.Unix() / bk * bk
	n := int((last-first)/bk) + 1
	if n < 0 {
		n = 0
	}
	points := make([]TimelinePoint, 0, n)
	for b := first; b <= last; b += bk {
		p := TimelinePoint{T: b}
		if a := buckets[b]; a != nil {
			p.Requests = a.requests
			p.Denied = a.denied
			p.Errors = a.errors
			p.BytesIn = a.bin
			p.BytesOut = a.bout
			p.Allowed = a.requests - a.denied - a.errors
			if p.Allowed < 0 {
				p.Allowed = 0
			}
		}
		points = append(points, p)
	}
	top := make([]UserAgg, 0, len(users))
	for name, a := range users {
		top = append(top, UserAgg{User: name, Requests: a.requests, BytesIn: a.bin, BytesOut: a.bout})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].BytesOut != top[j].BytesOut {
			return top[i].BytesOut > top[j].BytesOut
		}
		return top[i].Requests > top[j].Requests
	})
	if len(top) > 10 {
		top = top[:10]
	}
	return points, top
}
