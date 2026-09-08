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
	"sort"
	"strings"
	"sync"
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
	Events    []Event `json:"events"`
	Available bool    `json:"available"`
	LastError string  `json:"last_error,omitempty"`
}

type Journal struct {
	Path     string
	MaxBytes int64
	mu       sync.Mutex
	lastErr  string
}

func New(path string) *Journal { return &Journal{Path: path, MaxBytes: DefaultMaxBytes} }

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
	return nil
}

func (journal *Journal) Read(limit int) Snapshot {
	if journal == nil || strings.TrimSpace(journal.Path) == "" {
		return Snapshot{Available: false, LastError: "audit journal is disabled"}
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	events := []Event{}
	for _, path := range []string{journal.Path + ".1", journal.Path} {
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Snapshot{Events: events, Available: false, LastError: err.Error()}
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 4*DefaultMaxBytes))
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			var event Event
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				events = append(events, event)
			}
		}
		scanErr := scanner.Err()
		_ = file.Close()
		if scanErr != nil {
			return Snapshot{Events: events, Available: false, LastError: scanErr.Error()}
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp > events[j].Timestamp })
	if len(events) > limit {
		events = events[:limit]
	}
	return Snapshot{Events: events, Available: journal.lastErr == "", LastError: journal.lastErr}
}

func (journal *Journal) fail(err error) error {
	journal.lastErr = err.Error()
	return err
}
