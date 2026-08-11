package telemetry

import "testing"

func TestStoreLifecycle(t *testing.T) {
	s := NewStore()
	s.Upsert(Connection{ID: "1", ServiceID: "youtube", Route: "nfqws2", Chain: []string{"YouTube", "NFQWS2"}})
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
