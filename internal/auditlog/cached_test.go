package auditlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCachedAuditSurvivesLockedWriterAndMissingFlash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	j := New(path)
	if err := j.Append(Event{Action: "POST", Path: "/api/v1/apply", Outcome: "failed"}); err != nil {
		t.Fatal(err)
	}
	j = New(path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	done := make(chan Snapshot, 1)
	go func() { done <- j.Cached(40) }()
	select {
	case snapshot := <-done:
		if !snapshot.Available || !snapshot.MemoryOnly || !snapshot.HistoryComplete || len(snapshot.Events) != 1 || snapshot.Events[0].Outcome != "failed" || snapshot.ObservedAt == "" {
			t.Fatalf("%+v", snapshot)
		}
		snapshot.Events[0].Outcome = "tampered"
		if j.Cached(40).Events[0].Outcome != "failed" {
			t.Fatal("mutable cache alias")
		}
	case <-time.After(time.Second):
		t.Fatal("memory read waited for disk/writer")
	}
}

func TestCachedAuditDoesNotPublishFailedAppend(t *testing.T) {
	root := t.TempDir()
	j := New(filepath.Join(root, "audit.jsonl"))
	if err := j.Append(Event{Action: "old"}); err != nil {
		t.Fatal(err)
	}
	j.Path = root // A directory cannot become a successful persisted action.
	if err := j.Append(Event{Action: "new"}); err == nil {
		t.Fatal("unexpected append")
	}
	snapshot := j.Cached(50)
	if snapshot.Available || snapshot.LastError == "" || len(snapshot.Events) != 1 || snapshot.Events[0].Action != "old" {
		t.Fatalf("%+v", snapshot)
	}
}

func TestCachedAuditBoundsHistoryAndDoesNotHideIncompleteStartup(t *testing.T) {
	j := New(t.TempDir())
	if j.Cached(50).HistoryComplete {
		t.Fatal("unread directory is not complete history")
	}
	j.Path = filepath.Join(t.TempDir(), "audit.jsonl")
	if err := j.Append(Event{Action: "new"}); err != nil {
		t.Fatal(err)
	}
	if j.Cached(50).HistoryComplete {
		t.Fatal("append invented older history")
	}
	events := make([]Event, 1200)
	for i := range events {
		events[i] = Event{Action: strings.Repeat("x", 4000), Path: strings.Repeat("y", 4000)}
	}
	j.mu.Lock()
	j.publish(events, "", true)
	j.mu.Unlock()
	snapshot := j.Cached(9999)
	if len(snapshot.Events) != 500 || len(snapshot.Events[0].Action) != 64 || len(snapshot.Events[0].Path) != 512 {
		t.Fatal("cache is unbounded")
	}
	if len(j.Cached(7).Events) != 7 {
		t.Fatal("limit ignored")
	}
}
