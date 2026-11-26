package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
)

func TestDurableStopJoinsFirstAutonomyCheckAndPersistsWithoutAppliedPlan(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	store, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	a.Store, a.autonomy = store, autonomyState{}
	p := saveAutonomyFixturePolicy(t, a)
	p.SourceIDs = []string{"manual"}
	p.Application.Mode, p.Components.Mode = "off", "off"
	if w := controlRequest(a, http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := store.UpdateService("my-independent-site", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(context.Background(), "my-independent-site"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	initReconcilerFixture(t, a, now)
	a.wakeAutonomy()
	if view := a.serviceControlView(context.Background()); view["runtime_state"] != "preparing" || view["can_stop"] != true || view["running"] != false {
		t.Fatalf("no Stop action while Auto is preparing: %v", view)
	}
	entered, canceled, releaseCheck, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseCheck) })
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-releaseCheck
		return d10Result(req, "sing-box", true), nil // Late PASS from the canceled generation.
	})
	go func() { a.reconcileRound(testCtx, time.Now()); close(finished) }()
	awaitOperation(t, entered)
	before := a.Store.Get()
	stop := durableRuntimeAccept(t, a, "stop", "stop-first-autonomy-check", before.Revision)
	awaitOperation(t, canceled)
	if a.Store.Get().ServiceControl.Stopped {
		t.Fatal("Stop completed before the previous check joined")
	}
	releaseOnce.Do(func() { close(releaseCheck) })
	awaitOperation(t, finished)
	a.reconcileRound(testCtx, time.Now())
	after := a.Store.Get()
	if got := durableJobAt(t, a, stop.ID); got.State != "completed" || !after.ServiceControl.Stopped || after.AppliedRevision != before.AppliedRevision || len(adapter.calls) != 0 {
		t.Fatalf("Stop did not persist the empty applied state: job=%+v stopped=%v appliedEpoch=%d calls=%v", got, after.ServiceControl.Stopped, after.AppliedRevision, adapter.calls)
	}
	store, err = config.LoadExisting(configPath)
	if err != nil || !store.Get().ServiceControl.Stopped {
		t.Fatalf("Stop lost on reload: %v", err)
	}
	a.autonomyRound(testCtx, time.Now().Add(time.Hour))
	if len(adapter.calls) != 0 || len(a.Store.Get().AppliedServices) != 0 {
		t.Fatal("scheduler resumed a stopped cold search")
	}
	if view := a.serviceControlView(context.Background()); view["resume_available"] != true {
		t.Fatal("inactive Stop cannot be resumed")
	}
	if w := runtimeRequest(a, "resume"); w.Code != http.StatusOK || a.Store.Get().ServiceControl.Stopped || !strings.Contains(w.Body.String(), `"live_applied":false`) {
		t.Fatalf("Resume changed the network before a fresh verification: %d %s", w.Code, w.Body.String())
	}
}

func durableRuntimeAccept(t *testing.T, a *App, action, key string, revision uint64) durableServiceJob {
	t.Helper()
	confirm := "STOP_OWNED_ROUTES"
	if action == "resume" {
		confirm = "RESUME_OWNED_ROUTES"
	}
	w := controlRequest(a, "POST", "/api/v1/service-control/runtime", map[string]any{"action": action, "confirm": confirm, "expected_revision": revision, "idempotency_key": key})
	var response struct {
		Job        nodeCheckJob
		Persistent bool
	}
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &response) != nil || !response.Persistent {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	return durableJobAt(t, a, response.Job.ID)
}

func TestDurableRuntimeStopAcceptedDuringCheckJoinsCleanupAndHasPriority(t *testing.T) {
	a, _, adapter, cfg := serviceRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	a.StartNodeChecks(context.Background())
	t.Cleanup(func() { _ = a.WaitNodeChecks(context.Background()) })
	entered, canceled, cleanup, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-cleanup
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	check, err := a.enqueueDurableServiceJob(context.Background(), serviceControlJobRequest{Kind: "check", ServiceIDs: []string{"telegram"}, ExpectedRevision: &cfg.Revision, IdempotencyKey: "durable-runtime-check-1"})
	if err != nil {
		t.Fatal(err)
	}
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(finished) }()
	awaitOperation(t, entered)
	defer func() {
		select {
		case <-finished:
		default:
			close(cleanup)
			<-finished
		}
	}()
	stop := durableRuntimeAccept(t, a, "stop", "durable-runtime-stop-1", cfg.Revision)
	awaitOperation(t, canceled)
	if retry := durableRuntimeAccept(t, a, "stop", "durable-runtime-stop-1", cfg.Revision); retry.ID != stop.ID {
		t.Fatal("lost response duplicated action")
	}
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("Stop stole cleanup admission")
	}
	if len(adapter.calls) != 0 || a.Store.Get().ServiceControl.Stopped {
		t.Fatal("Stop ran before cleanup")
	}
	close(cleanup)
	awaitOperation(t, finished)
	if !durableJobAt(t, a, check.ID).terminal() {
		t.Fatal("previous worker not joined")
	}
	a.reconciler.doc.ManualUntil = time.Now().Add(time.Minute)
	a.reconciler.durableBurst = 3
	a.reconcileRound(context.Background(), time.Now())
	if got := durableJobAt(t, a, stop.ID); got.State != "completed" || !a.Store.Get().ServiceControl.Stopped {
		t.Fatal("Stop lost priority", got)
	}
	if !reflect.DeepEqual(a.Store.Get().Services, cfg.Services) {
		t.Fatal("Stop consumed pending edits")
	}
	if len(adapter.calls) != 2 {
		t.Fatal("unexpected adapters", adapter.calls)
	}
}

func TestDurableRuntimeRestartBeforeAndAfterCommitNeverReplaysChangedRevision(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			a, _, adapter, cfg := serviceRuntimeFixture(t)
			initReconcilerFixture(t, a, time.Now())
			job := durableRuntimeAccept(t, a, "stop", "runtime-restart-request", cfg.Revision)
			a.reconciler.doc.Jobs[0].State = "running"
			a.reconciler.doc.Jobs[0].Attempts = 1
			if err := a.persistReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			if committed {
				outcome, err := a.runDurableRuntimeJob(context.Background(), job.Request)
				if err != nil || outcome.Code != "" {
					t.Fatal(outcome, err)
				}
			}
			calls := len(adapter.calls)
			b := &App{Store: a.Store, Dataplane: a.Dataplane, Catalog: a.Catalog, Nodes: a.Nodes, FreshProfile: a.FreshProfile}
			b.reconciler.started, b.reconciler.path = true, a.Store.AutomationStatePath()
			if err := b.loadReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			b.runDurableServiceJob(context.Background(), time.Now().Add(time.Minute))
			got := durableJobAt(t, b, job.ID)
			if committed {
				if got.State != "failed" || got.RuntimeCode != "SERVICE_CONTROL_CHANGED" || len(adapter.calls) != calls {
					t.Fatal("ambiguous commit was replayed", got)
				}
			} else if got.State != "completed" || !b.Store.Get().ServiceControl.Stopped {
				t.Fatal("unstarted Stop not recovered", got)
			}
		})
	}
}

func TestDurableRuntimeCancelOldIDAndAcceptedResumeIgnoreBrowserLifetime(t *testing.T) {
	a, _, _, cfg := serviceRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	job := durableRuntimeAccept(t, a, "stop", "runtime-close-browser-1", cfg.Revision)
	// A completed HTTP context is no longer involved when the worker dispatches.
	a.runDurableServiceJob(context.Background(), time.Now())
	if durableJobAt(t, a, job.ID).State != "completed" {
		t.Fatal("Stop failed")
	}
	resume := durableRuntimeAccept(t, a, "resume", "runtime-close-browser-2", a.Store.Get().Revision)
	if ok, err := a.cancelDurableServiceJob(context.Background(), job.ID); !ok || err != nil {
		t.Fatal(err)
	}
	if durableJobAt(t, a, resume.ID).CancelRequested {
		t.Fatal("old cancel affected resume")
	}
	a.runDurableServiceJob(context.Background(), time.Now())
	if got := durableJobAt(t, a, resume.ID); got.State != "completed" || a.Store.Get().ServiceControl.Stopped {
		t.Fatal("Resume failed", got)
	}
	if !reflect.DeepEqual(cfg.Services, a.Store.Get().Services) || !reflect.DeepEqual(cfg.AppliedServices, a.Store.Get().AppliedServices) {
		t.Fatal("Resume widened scope or consumed edits")
	}
}

func TestDurableRuntimeRejectsInvalidAndUnsavedIntentsWithoutPreempting(t *testing.T) {
	a, request := durableFixture(t)
	var cancels atomic.Int32
	a.reconciler.cancel = func() { cancels.Add(1) }
	for _, body := range []map[string]any{
		{"action": "stop", "confirm": "wrong", "idempotency_key": "valid-request-token", "expected_revision": *request.ExpectedRevision},
		{"action": "stop", "confirm": "STOP_OWNED_ROUTES", "idempotency_key": "short", "expected_revision": *request.ExpectedRevision},
	} {
		w := controlRequest(a, "POST", "/api/v1/service-control/runtime", body)
		if w.Code != 400 || cancels.Load() != 0 {
			t.Fatal("invalid request preempted", w.Code)
		}
	}
	request.Kind, request.ServiceIDs = "stop", nil
	w := controlRequest(a, "POST", "/api/v1/service-control/jobs", request)
	if w.Code != 400 {
		t.Fatal("confirmation bypassed via jobs")
	}
	if err := os.WriteFile(a.Store.AutomationStatePath(), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.enqueueDurableServiceJob(context.Background(), request); err == nil || cancels.Load() != 0 {
		t.Fatal("unsaved Stop preempted current work")
	}
}

func TestDurableRuntimeFailurePublishesBoundedReasonAndJoinsRollback(t *testing.T) {
	a, _, adapter, cfg := serviceRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	adapter.after = func(phase string) error {
		if phase == "deactivate" {
			return errors.New("private endpoint must never enter durable job")
		}
		return nil
	}
	job := durableRuntimeAccept(t, a, "stop", "runtime-failure-request", cfg.Revision)
	a.runDurableServiceJob(context.Background(), time.Now())
	got := durableJobAt(t, a, job.ID)
	if got.State != "failed" || got.RuntimeCode != "SERVICE_RUNTIME_FAILED" || !reflect.DeepEqual(cfg, a.Store.Get()) || !strings.Contains(strings.Join(adapter.calls, ","), "rollback") {
		t.Fatal(got)
	}
	raw, _ := os.ReadFile(a.Store.AutomationStatePath())
	if strings.Contains(string(raw), "private endpoint") || a.Operations.Snapshot().Active != 0 {
		t.Fatal("private error persisted or lease leaked")
	}
}

func TestDurableRuntimeRealHTTPAcceptsStopDuringBusyButRequiresAuthentication(t *testing.T) {
	a, _, _, cfg := serviceRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	a.Security, _ = security.NewGate(panelTestToken)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	client := &http.Client{Timeout: 2 * time.Second}
	body := fmt.Sprintf(`{"action":"stop","confirm":"STOP_OWNED_ROUTES","expected_revision":%d,"idempotency_key":"real-http-runtime-stop"}`, cfg.Revision)
	var response struct{ Job nodeCheckJob }
	for _, authenticated := range []bool{false, true} {
		request, _ := http.NewRequest("POST", server.URL+"/api/v1/service-control/runtime", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if authenticated {
			request.Header.Set("Authorization", "Bearer "+panelTestToken)
		}
		got, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(got.Body)
		got.Body.Close()
		if !authenticated {
			if got.StatusCode != 401 || len(a.reconciler.doc.Jobs) != 0 {
				t.Fatal("anonymous Stop accepted")
			}
		} else if got.StatusCode != 202 || json.Unmarshal(raw, &response) != nil {
			t.Fatal(got.StatusCode, string(raw))
		}
	}
	if a.Operations.Snapshot().Active != 1 || a.Store.Get().ServiceControl.Stopped {
		t.Fatal("admission stolen")
	}
	// No live HTTP request remains. The durable intent has its own lifetime.
	release()
	a.runDurableServiceJob(context.Background(), time.Now())
	if got := durableJobAt(t, a, response.Job.ID); got.State != "completed" {
		t.Fatal(got)
	}
}

func TestDurableRuntimeStopHasReservedQueueSlotAndHonorsRecoveryFence(t *testing.T) {
	a, request := durableFixture(t)
	base, err := a.enqueueDurableServiceJob(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 15; i++ {
		j := base
		j.ID += uint64(i)
		j.KeyHash = applyReviewHash(fmt.Sprintf("key-%d", i))
		j.RequestHash = applyReviewHash(fmt.Sprintf("intent-%d", i))
		a.reconciler.doc.Jobs = append(a.reconciler.doc.Jobs, j)
	}
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	request.Kind = "stop"
	request.ServiceIDs = nil
	request.IdempotencyKey = "reserved-runtime-stop"
	if _, err := a.enqueueDurableServiceJob(context.Background(), request); err != nil {
		t.Fatal("Stop slot was consumed by checks", err)
	}
	b, request := durableFixture(t)
	request.Kind = "stop"
	request.ServiceIDs = nil
	b.Operations.Fence()
	if _, err := b.enqueueDurableServiceJob(context.Background(), request); !errors.Is(err, operationgate.ErrRecovery) || len(b.reconciler.doc.Jobs) != 0 {
		t.Fatal("fence bypassed", err)
	}
}
