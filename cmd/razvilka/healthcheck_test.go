package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestWaitForHealthObservesPendingBusyAndFreshRuntime(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch requests.Add(1) {
		case 1:
			fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"committed","dataplane_adapters":1,"live_active":false,"node_recovery":{"state":"idle"}}`, app.Version)
		case 2:
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"RESTORE_OPERATION_BUSY","not_started":true,"node_recovery":{"state":"revalidating"}}`, app.Version)
		case 3:
			// The last execution can fail while an older committed route still
			// exists. Its adapter count must still require real live evidence.
			fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"rolled-back","dataplane_adapters":1,"live_active":false,"node_recovery":{"state":"network-stale"}}`, app.Version)
		default:
			fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"committed","dataplane_adapters":1,"live_active":true,"node_recovery":{"state":"recovered"}}`, app.Version)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	version, err := waitForHealth(ctx, server.URL, 1234, true, time.Millisecond)
	if err != nil || version != app.Version || requests.Load() != 4 {
		t.Fatalf("readiness accepted before fresh runtime: version=%q, requests=%d, err=%v", version, requests.Load(), err)
	}
}

func TestWaitForHealthCancellationPreservesBusyOrPendingFailure(t *testing.T) {
	for _, busy := range []bool{false, true} {
		t.Run(fmt.Sprint("busy=", busy), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			watchdog := time.AfterFunc(10*time.Second, cancel)
			defer watchdog.Stop()
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 2 {
					// The next request proves that the previous identity/busy
					// response was fully parsed; slow startup cannot skip it.
					cancel()
				}
				if busy {
					w.WriteHeader(http.StatusConflict)
					fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"RESTORE_OPERATION_BUSY","not_started":true}`, app.Version)
				} else {
					fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"committed","dataplane_adapters":1,"live_active":false}`, app.Version)
				}
			}))
			defer server.Close()
			version, err := waitForHealth(ctx, server.URL, 1234, true, time.Millisecond)
			if err == nil || version != "" || errors.Is(err, errHealthBusy) != busy || requests.Load() != 2 {
				t.Fatalf("deadline lost refusal/busy fence: version=%q, requests=%d, err=%v", version, requests.Load(), err)
			}
			if !busy && !errors.Is(err, errHealthPending) {
				t.Fatalf("pending runtime should fail, permitting rollback: %v", err)
			}
		})
	}
}

func TestWaitForHealthRejectsAuthorityAndJournalFailuresImmediately(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"different process", fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":4321}`, app.Version), 200},
		{"different version", `{"name":"RAZVILKA","version":"different","process_id":1234}`, 200},
		{"malformed response", `{`, 200},
		{"untrusted conflict", fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"OTHER_BUSY","not_started":true}`, app.Version), 409},
		{"journal failure", fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"journal-error"}`, app.Version), 200},
		{"private recovery fence", fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"RESTORE_OPERATION_BUSY","not_started":true,"recovery_required":true}`, app.Version), 409},
		{"node requires review", fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"rolled-back","dataplane_adapters":1,"live_active":false,"node_recovery":{"state":"requires-review"}}`, app.Version), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 {
					w.WriteHeader(http.StatusConflict)
					fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"RESTORE_OPERATION_BUSY","not_started":true}`, app.Version)
					return
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			version, err := waitForHealth(ctx, server.URL, 1234, true, time.Millisecond)
			if err == nil || errors.Is(err, errHealthBusy) || errors.Is(err, errHealthPending) || version != "" || requests.Load() != 2 || ctx.Err() != nil {
				t.Fatalf("hard failure retried or mistaken for private busy: version=%q requests=%d err=%v", version, requests.Load(), err)
			}
		})
	}
}

func TestWaitForHealthCancellationBoundsInFlightRequestAndPreservesPrivateBusy(t *testing.T) {
	for _, stallBody := range []bool{false, true} {
		t.Run(fmt.Sprint("body=", stallBody), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			watchdog := time.AfterFunc(10*time.Second, cancel)
			defer watchdog.Stop()
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					w.WriteHeader(http.StatusConflict)
					fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"RESTORE_OPERATION_BUSY","not_started":true}`, app.Version)
					return
				}
				if stallBody {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"name":"RAZVILKA",`)
					w.(http.Flusher).Flush()
				}
				// Cancel only after the in-flight second request (and optional
				// partial body) exists, not after an assumed startup duration.
				cancel()
				<-r.Context().Done()
			}))
			defer server.Close()
			version, err := waitForHealth(ctx, server.URL, 1234, true, time.Millisecond)
			if !errors.Is(err, errHealthBusy) || version != "" || requests.Load() != 2 {
				t.Fatalf("in-flight deadline lost private busy fence: version=%q requests=%d err=%v", version, requests.Load(), err)
			}
		})
	}
}

func TestCheckHealthWaitRequiresFiniteBoundAndKeepsDefaultBusyBehavior(t *testing.T) {
	for _, invalid := range []time.Duration{-1, maxHealthWait + 1} {
		if _, err := checkHealthWithWait("invalid URL", 1234, true, invalid); err == nil {
			t.Fatalf("accepted invalid wait %s", invalid)
		}
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, `{"name":"RAZVILKA","version":%q,"process_id":1234,"code":"RESTORE_OPERATION_BUSY","not_started":true}`, app.Version)
	}))
	defer server.Close()
	if _, err := checkHealthWithWait(server.URL, 1234, true, 0); !errors.Is(err, errHealthBusy) || requests.Load() != 1 {
		t.Fatalf("default supervision must remain a single busy check: requests=%d err=%v", requests.Load(), err)
	}
}

func TestCheckHealthWithWaitDeadlineRejectsUnresponsiveServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	// No assertion depends on a request starting before this short deadline.
	// The overall wait must own cancellation, rather than the client's 4s limit.
	version, err := checkHealthWithWait(server.URL, 1234, true, 25*time.Millisecond)
	if version != "" || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errHealthBusy) {
		t.Fatalf("unresponsive server escaped readiness deadline: version=%q err=%v", version, err)
	}
}

func TestStrictHealthRequiresCompleteBoundedSingleStatus(t *testing.T) {
	valid := fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234,"dataplane_state":"never-applied","dataplane_adapters":0,"live_active":false}`, app.Version)
	for _, tc := range []struct{ name, body string }{
		{"no dataplane fields", fmt.Sprintf(`{"name":"RAZVILKA","version":%q,"process_id":1234}`, app.Version)},
		{"missing adapter count", strings.Replace(valid, `,"dataplane_adapters":0`, "", 1)},
		{"negative adapter count", strings.Replace(valid, `"dataplane_adapters":0`, `"dataplane_adapters":-1`, 1)},
		{"missing live evidence", strings.Replace(valid, `,"live_active":false`, "", 1)},
		{"missing state", strings.Replace(valid, `,"dataplane_state":"never-applied"`, "", 1)},
		{"trailing object", valid + `{}`},
		{"trailing garbage", valid + `bad`},
		{"oversized suffix", valid + strings.Repeat(" ", 64<<10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			if version, err := checkHealth(server.URL, 1234, true); err == nil || version != "" || errors.Is(err, errHealthPending) {
				t.Fatalf("incomplete/unbounded status accepted or retried: version=%q err=%v", version, err)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, valid)
	}))
	defer server.Close()
	if version, err := checkHealth(server.URL, 1234, true); err != nil || version != app.Version {
		t.Fatalf("fresh installation without applied adapters refused: version=%q err=%v", version, err)
	}
}
