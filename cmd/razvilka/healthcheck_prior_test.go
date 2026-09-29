package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// G01: the installer relaxes the final route check only for an identified
// previous process whose committed routes are not live. Every other outcome
// keeps the strict check, including busy and interrupted observations.
func TestPriorRouteClassificationIsTyped(t *testing.T) {
	const other = "0.18.15" // the previous release, not this binary's version
	status := func(extra string) string {
		return fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"committed","dataplane_adapters":2,"dataplane_error":""%s}`, other, extra)
	}
	for _, tc := range []struct {
		name  string
		code  int
		body  string
		want  int
		label string
	}{
		{"live routes", 200, status(`,"live_active":true`), priorRoutesConfirmed, "confirmed"},
		{"known degradation", 200, status(`,"live_active":false`), priorRoutesDegraded, "degraded"},
		{"recovery awaits review", 200, status(`,"live_active":false,"node_recovery":{"state":"requires-review"}`), priorRoutesDegraded, "degraded"},
		{"busy", 409, fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"RESTORE_OPERATION_BUSY","not_started":true}`, other), priorRoutesBusy, "busy"},
		{"fenced journal", 503, fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"DATAPLANE_RECOVERY_REQUIRED","not_started":true,"recovery_required":true}`, other), priorRoutesFenced, "fenced"},
		{"wrong process", 200, `{"name":"RAZVILKA","version":"0.18.15","process_id":999,"dataplane_state":"committed","dataplane_adapters":2,"live_active":false}`, priorRoutesUnknown, "unknown"},
		{"not RAZVILKA", 200, `{"name":"other","version":"1","process_id":1234,"dataplane_state":"committed","dataplane_adapters":2,"live_active":false}`, priorRoutesUnknown, "unknown"},
		{"no version", 200, `{"name":"RAZVILKA","version":"","process_id":1234,"dataplane_state":"committed","dataplane_adapters":2,"live_active":false}`, priorRoutesUnknown, "unknown"},
		{"journal error", 200, status(`,"live_active":false,"dataplane_error":"journal"`), priorRoutesUnknown, "unknown"},
		{"server error", 500, `{}`, priorRoutesUnknown, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			code, label, _ := classifyPriorRoutes(ctx, server.URL, 1234, time.Millisecond)
			if code != tc.want || label != tc.label {
				t.Fatalf("got %d %s, want %d %s", code, label, tc.want, tc.label)
			}
		})
	}
	unreachable := httptest.NewServer(http.NotFoundHandler())
	unreachable.Close()
	if code, _, _ := classifyPriorRoutes(context.Background(), unreachable.URL, 1234, time.Millisecond); code != priorRoutesUnknown {
		t.Fatalf("no response classified as %d", code)
	}
}
