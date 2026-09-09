package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditEntry is one record of the append-only admin audit log.
type AuditEntry struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	Who    string `json:"who"`
	Detail string `json:"detail"`
}

// AuditLog is a simple append-only JSONL audit trail of admin actions. It
// deliberately lives apart from the (clearable) activity log so admin
// actions — including activity-log clears — leave a durable record. Rotated
// at auditMaxBytes keeping the newest half, like the activity file.
type AuditLog struct {
	mu     sync.Mutex
	path   string
	file   *os.File
	size   int64
	warned bool
}

const auditMaxBytes = 50 << 20 // 50 MB

func NewAuditLog(dir string) *AuditLog {
	a := &AuditLog{path: filepath.Join(dir, "audit.log")}
	a.open()
	return a
}

func (a *AuditLog) open() {
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	a.file = f
	if st, err := f.Stat(); err == nil {
		a.size = st.Size()
	}
}

// Record appends one audit entry. Errors are logged once, never fatal.
func (a *AuditLog) Record(action, who, detail string) {
	line, err := json.Marshal(AuditEntry{
		Time:   time.Now().UTC().Format(time.RFC3339),
		Action: action,
		Who:    who,
		Detail: detail,
	})
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return
	}
	if a.size+int64(len(line)) > auditMaxBytes {
		a.rotateLocked()
		if a.file == nil {
			return
		}
	}
	if _, err := a.file.Write(append(line, '\n')); err != nil {
		if !a.warned {
			log.Printf("WARN: audit log write failed: %v", err)
			a.warned = true
		}
		return
	}
	a.warned = false
	a.size += int64(len(line) + 1)
}

func (a *AuditLog) rotateLocked() {
	path := a.path
	a.file.Close()
	a.file = nil
	a.size = 0
	if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
		defer f.Close()
		if st, err := f.Stat(); err == nil && st.Size() > 0 {
			keep := st.Size() / 2
			if _, err := f.Seek(keep, 0); err == nil {
				data, _ := ioReadAll(f, st.Size()-keep)
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
	a.open()
}

// Recent returns up to limit newest audit entries, newest first. The read
// is bounded (last 1 MiB of the file) so a large audit file cannot OOM.
func (a *AuditLog) Recent(limit int) []AuditEntry {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	f, err := os.OpenFile(a.path, os.O_RDONLY, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return nil
	}
	const maxRead = 1 << 20
	off := st.Size() - maxRead
	if off < 0 {
		off = 0
	}
	data := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(data, off); err != nil && err != io.EOF {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	// If the window starts mid-line, drop the leading fragment (unless the
	// byte before the window is a newline, i.e. a clean boundary).
	if off > 0 && len(lines) > 0 {
		var b [1]byte
		if _, err := f.ReadAt(b[:], off-1); err == nil && b[0] != '\n' {
			lines = lines[1:]
		}
	}
	out := make([]AuditEntry, 0, limit)
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}
