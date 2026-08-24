package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArtixSx/razvilka/internal/app"
)

func TestCheckHealth(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234}`, app.Version)))
	}))
	defer server.Close()

	version, err := checkHealth(server.URL, 1234, false)
	if err != nil {
		t.Fatalf("checkHealth: %v", err)
	}
	if version != app.Version {
		t.Fatalf("version = %q", version)
	}
	if _, err := checkHealth(server.URL, 0, false); err != nil {
		t.Fatalf("checkHealth without PID: %v", err)
	}
	if _, err := checkHealth(server.URL, 4321, false); err == nil {
		t.Fatal("expected process mismatch")
	}
}

func TestCheckHealthRejectsBadResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "status", status: http.StatusServiceUnavailable, body: `{"version":"x"}`},
		{name: "malformed", status: http.StatusOK, body: `{`},
		{name: "missing version", status: http.StatusOK, body: `{}`},
		{name: "wrong identity", status: http.StatusOK, body: `{"name":"ARTEM Flow","version":"0.0.6-control-lab"}`},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			if _, err := checkHealth(server.URL, 0, false); err == nil {
				t.Fatal("expected healthcheck error")
			}
		})
	}
}

func TestStrictHealthRejectsCommittedDataplaneWithoutRuntimeEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"committed","dataplane_adapters":2,"live_active":false}`, app.Version)))
	}))
	defer server.Close()
	if _, err := checkHealth(server.URL, 1234, true); err == nil {
		t.Fatal("strict health accepted a committed dataplane without runtime evidence")
	}
}

func TestStrictHealthRejectsDataplaneJournalFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"journal-error","dataplane_error":"dataplane journal unavailable"}`, app.Version)))
	}))
	defer server.Close()
	if _, err := checkHealth(server.URL, 1234, true); err == nil {
		t.Fatal("strict health accepted an unreadable dataplane journal")
	}
}
