package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArtixSx/razvilka/internal/app"
)

func TestCheckHealthDistinguishesRealRestoreBusyFromFailure(t *testing.T) {
	a := &app.App{}
	owner, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer owner()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	for _, strict := range []bool{false, true} {
		version, err := checkHealth(server.URL+"/api/v1/status", 0, strict)
		if !errors.Is(err, errHealthBusy) || version != "" {
			t.Fatal("busy was called healthy or failed", version, err)
		}
	}
	if _, err := checkHealth(server.URL+"/api/v1/status", 999999, false); errors.Is(err, errHealthBusy) || err == nil {
		t.Fatal("wrong PID accepted")
	}
	a.Operations.Fence()
	if _, err := checkHealth(server.URL+"/api/v1/status", 0, false); errors.Is(err, errHealthBusy) || err == nil {
		t.Fatal("recovery required mistaken for temporary busy")
	}
}

func TestCheckHealthRejectsUntrustedConflict(t *testing.T) {
	for _, body := range []string{`{}`, `{"name":"RAZVILKA","code":"RESTORE_OPERATION_BUSY"}`, fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"RESTORE_OPERATION_BUSY","not_started":true,"recovery_required":true}`, app.Version)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(409); fmt.Fprint(w, body) }))
		_, err := checkHealth(server.URL, 1234, false)
		server.Close()
		if errors.Is(err, errHealthBusy) || err == nil {
			t.Fatal("invalid busy accepted", err)
		}
	}
}

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
