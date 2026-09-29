package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
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

// A cut request right after start proves nothing: the bounded wait retries
// it instead of rolling back an upgrade whose panel then answers correctly.
func TestWaitForHealthRetriesTransportFailureBeforeFirstAnswer(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"rolled-back","dataplane_adapters":2,"live_active":false}`, app.Version)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	version, err := waitForHealth(ctx, server.URL, 1234, false, time.Millisecond)
	if err != nil || version != app.Version || requests.Load() != 2 {
		t.Fatalf("transient transport failure rolled back a healthy panel: version=%q requests=%d err=%v", version, requests.Load(), err)
	}
	// Identity failures after a transport failure still fail immediately.
	requests.Store(0)
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		fmt.Fprint(w, `{"name":"RAZVILKA","version":"different","process_id":1234}`)
	}))
	defer wrong.Close()
	if _, err := waitForHealth(ctx, wrong.URL, 1234, false, time.Millisecond); err == nil || requests.Load() != 2 || ctx.Err() != nil {
		t.Fatalf("identity mismatch retried: requests=%d err=%v", requests.Load(), err)
	}
}
