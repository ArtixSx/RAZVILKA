package auditlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalStoresOnlyExplicitEventFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	journal := New(path)
	if err := journal.Append(Event{Action: "POST", Path: "/api/v1/auth/login", Outcome: "denied", StatusCode: 401, Actor: "anonymous", RemoteIP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	snapshot := journal.Read(10)
	if !snapshot.Available || len(snapshot.Events) != 1 || snapshot.Events[0].Path != "/api/v1/auth/login" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password", "authorization", "cookie", "token"} {
		if strings.Contains(strings.ToLower(string(raw)), secret) {
			t.Fatalf("journal contains forbidden field %q: %s", secret, raw)
		}
	}
}

func TestJournalRotatesAndReturnsNewestFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	journal := New(path)
	journal.MaxBytes = 190
	for i := 0; i < 5; i++ {
		if err := journal.Append(Event{Timestamp: "2026-08-24T00:00:0" + string(rune('0'+i)) + "Z", Action: "PUT", Path: "/api/v1/services/example", Outcome: "ok", StatusCode: 200}); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := journal.Read(2)
	if len(snapshot.Events) != 2 || snapshot.Events[0].Timestamp <= snapshot.Events[1].Timestamp {
		t.Fatalf("events = %+v", snapshot.Events)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated journal missing: %v", err)
	}
}
