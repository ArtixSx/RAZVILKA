// Package auditlog stores a bounded, secret-safe journal of control-plane
// actions. It never records request bodies, headers, cookies, tokens or query
// strings.
package auditlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultMaxBytes int64 = 2 << 20

type Event struct {
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	Path       string `json:"path"`
	Outcome    string `json:"outcome"`
	StatusCode int    `json:"status_code"`
	Actor      string `json:"actor"`
	RemoteIP   string `json:"remote_ip"`
	DurationMS int64  `json:"duration_ms"`
}

type Snapshot struct {
	Events          []Event `json:"events"`
	Available       bool    `json:"available"`
	LastError       string  `json:"last_error,omitempty"`
	ObservedAt      string  `json:"observed_at,omitempty"`
	MemoryOnly      bool    `json:"memory_only,omitempty"`
	HistoryComplete bool    `json:"history_complete"`
}

type Journal struct {
	Path     string
	MaxBytes int64
	mu       sync.Mutex
	lastErr  string
	current  atomic.Pointer[Snapshot]
}

func New(path string) *Journal {
	journal := &Journal{Path: path, MaxBytes: DefaultMaxBytes}
	journal.Read(500) // One bounded startup read, before serving requests.
	return journal
}

// Cached never waits for flash I/O or the writer mutex. Only successfully
// persisted events enter this presentation snapshot; it is not runtime proof.
func (journal *Journal) Cached(limit int) Snapshot {
	if journal == nil {
		return Snapshot{MemoryOnly: true, LastError: "audit journal is disabled"}
	}
	snapshot := journal.current.Load()
	if snapshot == nil {
		return Snapshot{MemoryOnly: true, LastError: "audit journal has not been observed"}
	}
	result := *snapshot
	result.Events = slices.Clone(result.Events[:min(auditLimit(limit), len(result.Events))])
	result.MemoryOnly = true
	return result
}

func auditLimit(limit int) int {
	if limit < 1 {
		return 50
	}
	return min(limit, 500)
}

func newestEvents(events []Event, limit int) []Event {
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp > events[j].Timestamp })
	return events[:min(limit, len(events))]
}

// Called with mu held; published slices are immutable and never returned to
// a caller without cloning. Read errors retain only explicitly dated history.
func (journal *Journal) publish(events []Event, lastError string, complete bool) Snapshot {
	snapshot := Snapshot{Events: slices.Clone(newestEvents(events, 500)), Available: lastError == "", LastError: lastError, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), HistoryComplete: complete}
	// A damaged historical line must not inflate the always-resident cache.
	for i := range snapshot.Events {
		e := &snapshot.Events[i]
		e.Timestamp = boundedField(e.Timestamp, 64)
		e.Action = boundedField(e.Action, 64)
		e.Path = boundedField(e.Path, 512)
		e.Outcome = boundedField(e.Outcome, 64)
		e.Actor = boundedField(e.Actor, 128)
		e.RemoteIP = boundedField(e.RemoteIP, 64)
	}
	journal.current.Store(&snapshot)
	return snapshot
}

func boundedField(s string, n int) string {
	if len(s) > n {
		return strings.Clone(s[:n])
	}
	return s
}

func (journal *Journal) Append(event Event) error {
	if journal == nil || strings.TrimSpace(journal.Path) == "" {
		return errors.New("audit journal path is empty")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(event)
	if err != nil {
		return journal.fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(journal.Path), 0o700); err != nil {
		return journal.fail(fmt.Errorf("create audit directory: %w", err))
	}
	if info, err := os.Lstat(journal.Path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return journal.fail(errors.New("audit journal must be a regular file"))
	}
	maxBytes := journal.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if info, err := os.Stat(journal.Path); err == nil && info.Size()+int64(len(line)+1) > maxBytes {
		backup := journal.Path + ".1"
		_ = os.Remove(backup)
		if err := os.Rename(journal.Path, backup); err != nil {
			return journal.fail(fmt.Errorf("rotate audit journal: %w", err))
		}
	}
	file, err := os.OpenFile(journal.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return journal.fail(fmt.Errorf("open audit journal: %w", err))
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return journal.fail(err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		return journal.fail(fmt.Errorf("append audit event: %w", err))
	}
	if err := file.Sync(); err != nil {
		return journal.fail(fmt.Errorf("sync audit event: %w", err))
	}
	journal.lastErr = ""
	events := []Event{event}
	complete := false
	if previous := journal.current.Load(); previous != nil {
		events = append(events, previous.Events...)
		complete = previous.HistoryComplete
	}
	journal.publish(events, "", complete)
	return nil
}

func (journal *Journal) Read(limit int) Snapshot {
	if journal == nil || strings.TrimSpace(journal.Path) == "" {
		return Snapshot{Available: false, LastError: "audit journal is disabled"}
	}
	limit = auditLimit(limit)
	journal.mu.Lock()
	defer journal.mu.Unlock()
	events := []Event{}
	for _, path := range []string{journal.Path + ".1", journal.Path} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			journal.fail(errors.New("audit history must be a readable regular file"))
			return journal.Cached(limit)
		}
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			journal.fail(err)
			return journal.Cached(limit)
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 4*DefaultMaxBytes))
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			var event Event
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				events = append(events, event)
				if len(events) >= 1000 {
					events = newestEvents(events, 500)
				}
			}
		}
		scanErr := scanner.Err()
		_ = file.Close()
		if scanErr != nil {
			journal.fail(scanErr)
			return journal.Cached(limit)
		}
	}
	snapshot := journal.publish(events, journal.lastErr, true)
	snapshot.Events = slices.Clone(snapshot.Events[:min(limit, len(snapshot.Events))])
	return snapshot
}

func (journal *Journal) fail(err error) error {
	journal.lastErr = err.Error()
	events := []Event{}
	complete := false
	if previous := journal.current.Load(); previous != nil {
		events = slices.Clone(previous.Events)
		complete = previous.HistoryComplete
	}
	journal.publish(events, journal.lastErr, complete)
	return err
}
