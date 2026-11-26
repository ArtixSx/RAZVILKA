package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This executes the real worker, HTTP middleware and stores. The deliberately
// blocked checker models outstanding work; it is not native router evidence.
func TestAutonomyProgressRemainsReadableUntilCancelledCheckerJoins(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		name := "cancel"
		if fenced {
			name = "cancel-with-recovery"
		}
		t.Run(name, func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			a.Security = panelTestApp(t).Security
			before := a.Store.Get()
			instance := strings.Repeat("a", 32)
			old := time.Now().Add(-3 * time.Minute).UTC()
			if !a.publishPanelSnapshot(context.Background(), instance, old) {
				t.Fatal("could not publish the saved settings")
			}
			a.panelSnapshots.autonomy.Store(&panelAutonomyPublication{
				InstanceID: instance, Revision: 7, ObservedAt: old,
				Data: json.RawMessage(`{"policy":{"revision":1},"services":{}}`),
			})
			entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var resumeOnce sync.Once
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, _ dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				close(entered)
				<-resume // Cancellation alone cannot certify joined cleanup.
				return dataplane.NodeCheckResult{}, ctx.Err()
			})
			ctx, cancel := context.WithCancel(context.Background())
			go func() { defer close(done); a.autonomyRound(ctx, time.Now()) }()
			t.Cleanup(func() {
				cancel()
				resumeOnce.Do(func() { close(resume) })
				awaitOperation(t, done)
			})
			awaitOperation(t, entered)
			first := a.Operations.Snapshot()
			if first.State != "busy" || first.Progress == nil || first.Progress.Kind != "autonomy" || first.Progress.Phase != "checking" || first.Progress.ServiceID != "my-independent-site" || first.Progress.DeadlineAt == nil {
				t.Fatalf("real worker did not publish its admitted phase: %+v", first)
			}
			if delta := first.Progress.DeadlineAt.Sub(first.Progress.StartedAt); delta <= 0 || delta > defaultDataplaneApplyTimeout {
				t.Fatalf("progress lost the actual admitted deadline: %s", delta)
			}
			server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer server.Close()
			client := &http.Client{Timeout: 2 * time.Second}
			request := func(method, path string, auth bool) (int, []byte) {
				t.Helper()
				r, err := http.NewRequest(method, server.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if auth {
					r.Header.Set("Authorization", "Bearer "+panelTestToken)
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				return response.StatusCode, body
			}

			// The worker's state mutex can be held by journal I/O. Progress HTTP
			// must not take it, refresh the expired image or grant new admission.
			a.autonomy.mu.Lock()
			func() {
				defer a.autonomy.mu.Unlock()
				for _, path := range []string{"/api/v1/panel/availability", panelSnapshotPath} {
					code, body := request(http.MethodGet, path, true)
					var response struct {
						Dataplane string                 `json:"dataplane"`
						Admission operationgate.Snapshot `json:"admission"`
					}
					if code != http.StatusOK || json.Unmarshal(body, &response) != nil || response.Dataplane != "not-checked" || response.Admission.Progress == nil || response.Admission.Progress.ID != first.Progress.ID || response.Admission.Progress.Phase != "checking" {
						t.Fatalf("busy progress unavailable through %s: %d %s", path, code, body)
					}
				}
				code, body := request(http.MethodGet, panelAutonomyPath, true)
				var saved panelAutonomyResponse
				if code != http.StatusOK || json.Unmarshal(body, &saved) != nil || saved.State != "expired" || len(saved.Data) != 0 || saved.Revision != 7 || saved.ObservedAt == nil || !saved.ObservedAt.Equal(old) {
					t.Fatalf("progress renewed old service evidence: %d %s", code, body)
				}
				code, body = request(http.MethodGet, "/api/v1/panel/availability", false)
				if code != http.StatusUnauthorized || strings.Contains(string(body), "progress") {
					t.Fatalf("anonymous progress disclosure: %d %s", code, body)
				}
				code, body = request(http.MethodHead, "/api/v1/panel/availability", true)
				if code != http.StatusOK || len(body) != 0 {
					t.Fatalf("invalid HEAD: %d %s", code, body)
				}
			}()
			if code, body := request(http.MethodGet, "/api/v1/status", true); code != http.StatusConflict || !strings.Contains(string(body), "RESTORE_OPERATION_BUSY") {
				t.Fatalf("live status escaped original admission: %d %s", code, body)
			}

			cancel()
			wantState := "busy"
			if fenced {
				a.Operations.FenceJournal()
				wantState = "recovery-required"
			}
			code, body := request(http.MethodGet, "/api/v1/panel/availability", true)
			var cancelled struct{ Admission operationgate.Snapshot }
			if code != http.StatusOK || json.Unmarshal(body, &cancelled) != nil || cancelled.Admission.State != wantState || cancelled.Admission.Progress == nil || cancelled.Admission.Progress.ID != first.Progress.ID {
				t.Fatalf("unjoined cancellation hid the holder: %d %s", code, body)
			}
			if release, err := a.Operations.Exclusive(context.Background()); err == nil {
				release()
				t.Fatal("progress observation released the worker")
			}
			resumeOnce.Do(func() { close(resume) })
			awaitOperation(t, done)
			last := a.Operations.Snapshot()
			if last.Progress != nil || last.Active != 0 || last.Exclusive || last.Fenced != fenced {
				t.Fatalf("finished holder leaked progress or cleared recovery: %+v", last)
			}
			if !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 {
				t.Fatal("read-only progress/cancel changed the applied configuration")
			}
		})
	}
}

func TestAutonomyProgressCleanupRetainsOriginalPrivateOwner(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	var join func()
	defer func() {
		if join != nil {
			join()
		}
	}()
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, _ dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		var err error
		join, err = a.privateRestoreAdmission(ctx)
		if err != nil {
			return dataplane.NodeCheckResult{}, err
		}
		return dataplane.NodeCheckResult{}, errors.New("modeled checker retains cleanup")
	})
	a.autonomyRound(context.Background(), time.Now())
	state := a.Operations.Snapshot()
	if join == nil || state.State != "busy" || state.Progress == nil || state.Progress.Phase != "cleanup" || len(adapter.calls) != 0 {
		t.Fatalf("round return hid original private cleanup: %+v", state)
	}
	join()
	if last := a.Operations.Snapshot(); last.Progress != nil || last.State != "idle" {
		t.Fatalf("joined holder did not clear presentation: %+v", last)
	}
}
