package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckHealth(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"RAZVILKA","version":"0.0.8-security-gate","process_id":1234}`))
	}))
	defer server.Close()

	version, err := checkHealth(server.URL, 1234)
	if err != nil {
		t.Fatalf("checkHealth: %v", err)
	}
	if version != "0.0.8-security-gate" {
		t.Fatalf("version = %q", version)
	}
	if _, err := checkHealth(server.URL, 0); err != nil {
		t.Fatalf("checkHealth without PID: %v", err)
	}
	if _, err := checkHealth(server.URL, 4321); err == nil {
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
			if _, err := checkHealth(server.URL, 0); err == nil {
				t.Fatal("expected healthcheck error")
			}
		})
	}
}
