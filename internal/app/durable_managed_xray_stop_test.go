package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/security"
)

func keyedStopHTTP(t *testing.T, server *httptest.Server, action, confirm, key string, revision uint64, authenticated bool) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"action": action, "confirm": confirm, "expected_revision": revision, "idempotency_key": key})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/service-control/runtime", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+panelTestToken)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}

func TestDurableManagedXrayStopHTTPFenceKeepsAuthConfirmationAndIdempotentACK(t *testing.T) {
	a, _, adapter, before := serviceRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	a.Security, _ = security.NewGate(panelTestToken)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	status, raw := keyedStopHTTP(t, server, "stop", "STOP_OWNED_ROUTES", "keyed-stop-before-fence", before.Revision, true)
	var initial struct{ Job nodeCheckJob }
	if status != http.StatusAccepted || json.Unmarshal(raw, &initial) != nil {
		t.Fatalf("initial HTTP acceptance: %d %s", status, raw)
	}
	accepted := durableJobAt(t, a, initial.Job.ID)
	a.Operations.FenceJournal()
	for _, test := range []struct {
		name, action, confirm, key string
		revision                   uint64
		authenticated              bool
		status                     int
	}{
		{"anonymous", "stop", "STOP_OWNED_ROUTES", "keyed-stop-anonymous-1", before.Revision, false, http.StatusUnauthorized},
		{"confirmation", "stop", "wrong", "keyed-stop-confirmation", before.Revision, true, http.StatusBadRequest},
		{"unknown-stop", "stop", "STOP_OWNED_ROUTES", "keyed-stop-unknown-owner", before.Revision + 1, true, http.StatusServiceUnavailable},
		{"resume", "resume", "RESUME_OWNED_ROUTES", "keyed-resume-after-fence", before.Revision, true, http.StatusServiceUnavailable},
		{"key-conflict", "resume", "RESUME_OWNED_ROUTES", "keyed-stop-before-fence", before.Revision, true, http.StatusConflict},
		{"lost-response", "stop", "STOP_OWNED_ROUTES", "keyed-stop-before-fence", before.Revision, true, http.StatusAccepted},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, raw := keyedStopHTTP(t, server, test.action, test.confirm, test.key, test.revision, test.authenticated)
			if status != test.status {
				t.Fatalf("status %d, wanted %d: %s", status, test.status, raw)
			}
			if status == http.StatusAccepted {
				var response struct{ Job nodeCheckJob }
				if json.Unmarshal(raw, &response) != nil || response.Job.ID != accepted.ID {
					t.Fatal("fenced ACK duplicated original job")
				}
			}
		})
	}
	if len(a.reconciler.doc.Jobs) != 1 || len(adapter.calls) != 0 || !reflect.DeepEqual(a.Store.Get(), before) || !a.Operations.Snapshot().Fenced {
		t.Fatal("fenced request changed the job, runtime, Store or fence")
	}
}

// These deliberately incomplete views exercise refusal only. No native
// material, private App operation, completion or cleanup grant is fabricated.
func TestDurableManagedXrayStopRefusesForeignAndIncompletePendingOwners(t *testing.T) {
	for _, name := range []string{"no-runtime", "incomplete-pending", "copied-runtime", "foreign-app", "foreign-manager", "missing-policy", "busy-runtime"} {
		t.Run(name, func(t *testing.T) {
			a, _, adapter, before := serviceRuntimeFixture(t)
			initReconcilerFixture(t, a, time.Now())
			release, err := a.Operations.Exclusive(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			var fakeReleases atomic.Int32
			policy := &managedListPolicyOwner{app: a, manager: a.Dataplane}
			policy.self = policy
			r := &ManagedXraySelectedTCPListRuntime{app: a, manager: a.Dataplane, policy: policy}
			r.self = r
			e := &managedXraySelectedTCPListExecution{runtime: r, pendingStop: true, pendingContext: context.Background(),
				pendingCloseOperation: func() { fakeReleases.Add(1) }, pendingRelease: func() { fakeReleases.Add(1) }}
			e.self = e
			r.pending = e
			a.managedXraySelectedTCPList = r
			switch name {
			case "no-runtime":
				a.managedXraySelectedTCPList = nil
			case "copied-runtime":
				r.self = &ManagedXraySelectedTCPListRuntime{}
			case "foreign-app":
				r.app = &App{}
			case "foreign-manager":
				r.manager = dataplane.New(t.TempDir())
			case "missing-policy":
				r.policy = nil
			case "busy-runtime":
				r.mu.Lock()
				defer r.mu.Unlock()
			}
			a.Operations.FenceJournal()
			request := serviceControlJobRequest{Kind: "stop", ExpectedRevision: &before.Revision, IdempotencyKey: "foreign-pending-stop-key"}
			joined := make(chan error, 1)
			go func() {
				_, err := a.enqueueDurableServiceJob(context.Background(), request)
				joined <- err
			}()
			select {
			case err := <-joined:
				if !errors.Is(err, operationgate.ErrRecovery) {
					t.Fatal("foreign or incomplete owner queued Stop", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("pending comparison waited on the busy runtime")
			}
			if _, err := a.runDurableRuntimeJob(context.Background(), request); !errors.Is(err, operationgate.ErrRecovery) {
				t.Fatal("executor borrowed a foreign or incomplete cleanup", err)
			}
			if len(a.reconciler.doc.Jobs) != 0 || len(adapter.calls) != 0 || fakeReleases.Load() != 0 || !reflect.DeepEqual(a.Store.Get(), before) {
				t.Fatal("refusal performed effects or released another owner")
			}
			if gate := a.Operations.Snapshot(); !gate.Fenced || gate.Active != 1 {
				t.Fatal("refusal changed the original held gate", gate)
			}
		})
	}
}

func TestDurableManagedXrayStopRechecksFenceAfterAcceptanceAndHonorsCancel(t *testing.T) {
	a, _, adapter, before := serviceRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	job := durableRuntimeAccept(t, a, "stop", "keyed-stop-executor-recheck", before.Revision)
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	a.Operations.FenceJournal()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.runDurableRuntimeJob(canceled, job.Request); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled Stop entered original cleanup dispatch", err)
	}
	if !a.runDurableServiceJob(context.Background(), time.Now()) {
		t.Fatal("accepted job did not settle")
	}
	got := durableJobAt(t, a, job.ID)
	if got.State != "failed" || got.Reason != "cleanup-unverified" || got.CleanupOutcome != "unverified" {
		t.Fatal("unknown fence was reported as completed", got)
	}
	if len(adapter.calls) != 0 || !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("generic Stop ran through a new fence")
	}
	if gate := a.Operations.Snapshot(); !gate.Fenced || gate.Active != 1 {
		t.Fatal("worker released the unrelated owner", gate)
	}
	if retry := durableRuntimeAccept(t, a, "stop", "keyed-stop-executor-recheck", before.Revision); retry.ID != job.ID || retry.State != "failed" || retry.Attempts != 1 {
		t.Fatal("failed original key was replayed instead of acknowledged", retry)
	}
	if _, err := a.enqueueDurableServiceJob(context.Background(), serviceControlJobRequest{Kind: "stop", ExpectedRevision: &before.Revision, IdempotencyKey: "keyed-stop-new-unknown-owner"}); !errors.Is(err, operationgate.ErrRecovery) {
		t.Fatal("a new key created cleanup authority", err)
	}
}

func TestDurableManagedXrayStopStorageBlockCannotBeBypassedByACK(t *testing.T) {
	a, _, _, before := serviceRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	job := durableRuntimeAccept(t, a, "stop", "keyed-stop-storage-block", before.Revision)
	a.Operations.FenceJournal()
	a.reconciler.blocked = true
	for i, request := range []serviceControlJobRequest{job.Request, {Kind: "stop", ExpectedRevision: &before.Revision}} {
		request.IdempotencyKey = "keyed-stop-storage-block"
		if i != 0 {
			request.IdempotencyKey = fmt.Sprintf("keyed-stop-storage-block-%d", i)
		}
		if _, err := a.enqueueDurableServiceJob(context.Background(), request); !errors.Is(err, restorejournal.ErrRecovery) {
			t.Fatal("unreliable durable storage accepted a Stop or ACK", err)
		}
	}
	if a.runDurableServiceJob(context.Background(), time.Now()) || durableJobAt(t, a, job.ID).State != "queued" || !a.Operations.Snapshot().Fenced {
		t.Fatal("storage block admitted an executor or changed the fence")
	}
}
