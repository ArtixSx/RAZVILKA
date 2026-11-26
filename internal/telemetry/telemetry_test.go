package telemetry

import "testing"

func TestStoreLifecycle(t *testing.T) {
	s := NewStore()
	if status := s.Status(); status.Live || status.Reason == "" {
		t.Fatalf("new store must not claim live telemetry: %+v", status)
	}
	s.Upsert(Connection{ID: "1", ServiceID: "youtube", Route: "nfqws2", Chain: []string{"YouTube", "NFQWS2"}})
	if status := s.Status(); !status.Live || status.Producer == "" {
		t.Fatalf("published evidence must mark its producer live: %+v", status)
	}
	rows := s.Snapshot(false)
	if len(rows) != 1 || !rows[0].Active || rows[0].Route != "nfqws2" {
		t.Fatalf("unexpected active snapshot: %+v", rows)
	}
	s.Close("1")
	if got := s.Snapshot(false); len(got) != 0 {
		t.Fatalf("expected no active connections, got %+v", got)
	}
	rows = s.Snapshot(true)
	if len(rows) != 1 || rows[0].Active {
		t.Fatalf("expected one closed connection, got %+v", rows)
	}
}
