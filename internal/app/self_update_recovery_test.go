package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func startupUpdateFixture(t *testing.T, a *App, confirmedHelper bool) (context.Context, context.CancelFunc, *selfUpdateNodeRecovery, func(string) error) {
	t.Helper()
	u := updatecheck.NewUpdater(Version, t.TempDir(), updatecheck.Deployment{})
	if err := os.MkdirAll(u.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	writeState := func(state string) error {
		root, err := ownedfs.Open(u.Directory)
		if err != nil {
			return err
		}
		defer root.Close()
		data, err := json.Marshal(map[string]any{"owner": "razvilka-self-update-v1", "job": map[string]any{
			"id": strings.Repeat("a", 32), "state": state, "helper_pid": 0, "updated_at": time.Now().UTC(),
		}})
		if err != nil {
			return err
		}
		return root.WriteAtomic("current.json", data, 0600)
	}
	if err := writeState("restarting"); err != nil {
		t.Fatal(err)
	}
	a.SelfUpdate = u
	ctx, cancel := context.WithCancel(context.Background())
	a.StartSelfUpdate(ctx)
	t.Cleanup(func() {
		cancel()
		wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := a.WaitSelfUpdate(wait); err != nil {
			t.Error(err)
		}
	})
	handoff := a.nodeRecovery.update
	if handoff == nil {
		t.Fatal("persisted restarting update did not acquire startup lease")
	}
	if confirmedHelper {
		// Model only a confirmed private helper process. Job state, identity,
		// terminal transitions and corruption still come from the real journal.
		// No route/proof/adapter is stubbed by this process-observation seam.
		handoff.helperPID = 1234
		handoff.current = func() updatecheck.Job {
			job := u.Snapshot()
			if job.HelperPID == 0 {
				job.HelperPID = 1234
			}
			return job
		}
	}
	return ctx, cancel, handoff, writeState
}

func waitStartupRecovery(t *testing.T, handoff *selfUpdateNodeRecovery) {
	t.Helper()
	select {
	case <-handoff.done:
	case <-time.After(5 * time.Second):
		t.Fatal("startup node recovery did not finish")
	}
}

func assertStartupWritersBlocked(t *testing.T, a *App) {
	t.Helper()
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatalf("startup worker lost gate: %v", err)
	}
	called := false
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true }))
	for _, path := range []string{"/api/v1/services/telegram", "/api/v1/auth/password"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPut, path, nil))
		if called || w.Code != http.StatusConflict {
			t.Fatalf("write crossed startup lease: %s %d", path, w.Code)
		}
	}
}

func TestSelfUpdateStartupRecoversExactAppliedNodesBeforeReleasingWriters(t *testing.T) {
	a, id, adapter, checker, beforePlan := nodeRecoveryFixture(t)
	beforeConfig := a.Store.Get()
	ctx, _, handoff, writeState := startupUpdateFixture(t, a, true)
	entered, proceed := make(chan struct{}), make(chan struct{})
	checker.hook = func(ctx context.Context, _ dataplane.NodeCheckRequest) {
		close(entered)
		select {
		case <-proceed:
		case <-ctx.Done():
		}
	}
	a.StartSelfUpdateNodeRecovery(ctx)
	a.StartSelfUpdateNodeRecovery(ctx) // Listener handoff is one-shot.
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("startup recovery remained deadlocked behind its own lease")
	}
	assertStartupWritersBlocked(t, a)
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	var status struct {
		Name     string             `json:"name"`
		Version  string             `json:"version"`
		PID      int                `json:"process_id"`
		Live     bool               `json:"live_active"`
		Recovery nodeRecoveryStatus `json:"node_recovery"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Name != "RAZVILKA" || status.Version != Version || status.PID != os.Getpid() || status.Live || status.Recovery.State != "revalidating" {
		t.Fatalf("installer status was blocked or prematurely healthy: HTTP%d %+v", w.Code, status)
	}
	close(proceed)
	waitStartupRecovery(t, handoff)
	current, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || current.PlanID == beforePlan.PlanID || current.NetworkProfileID != recoveryProfile || a.nodeRecoverySnapshot().State != "recovered" {
		t.Fatalf("applied route was not revalidated: %v %+v", err, a.nodeRecoverySnapshot())
	}
	if !reflect.DeepEqual(beforePlan.Routes, current.Routes) || !reflect.DeepEqual(beforeConfig, a.Store.Get()) || len(checker.requests) != 1 || checker.requests[0].NodeID != id {
		t.Fatal("startup recovery changed scope/drafts or selected a different node")
	}
	if strings.Join(adapter.calls, ",") != "snapshot,stage,validate,canary,activate,health,commit" {
		t.Fatalf("recovery skipped guarded runtime transaction: %v", adapter.calls)
	}
	// Use the same injected network observer as exact checks. Public /status
	// uses the actual host's passive observer, which is unavailable on Windows.
	if err := a.Dataplane.CheckCommittedNodeHealth(ctx, current); err != nil {
		t.Fatalf("new committed runtime lacks exact health: %v", err)
	}
	assertStartupWritersBlocked(t, a) // Worker completion is not installer completion.
	if err := writeState("completed"); err != nil {
		t.Fatal(err)
	}
	wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := a.WaitSelfUpdate(wait); err != nil {
		t.Fatal("completed/reaped helper did not release handoff", err)
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("completed update retained gate", err)
	} else {
		release()
	}
}

func TestSelfUpdateStartupRecoveryRefusesMissingHelperAndRevokedJob(t *testing.T) {
	for _, mode := range []string{"missing-helper", "requires-review", "corrupt-journal", "after-check", "after-activate"} {
		t.Run(mode, func(t *testing.T) {
			a, _, adapter, checker, before := nodeRecoveryFixture(t)
			beforeConfig := a.Store.Get()
			ctx, _, handoff, writeState := startupUpdateFixture(t, a, mode != "missing-helper")
			if mode == "requires-review" {
				if err := writeState("requires-review"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "corrupt-journal" {
				if err := os.WriteFile(filepath.Join(a.SelfUpdate.Directory, "current.json"), []byte(`{`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "after-check" {
				checker.hook = func(context.Context, dataplane.NodeCheckRequest) { _ = writeState("requires-review") }
			}
			if mode == "after-activate" {
				adapter.after = func(phase string) error {
					if phase == "activate" {
						return writeState("requires-review")
					}
					return nil
				}
			}
			a.StartSelfUpdateNodeRecovery(ctx)
			waitStartupRecovery(t, handoff)
			current, _, err := a.Dataplane.Committed()
			if err != nil || !sameNodeRecoveryPlan(current, before) || !reflect.DeepEqual(beforeConfig, a.Store.Get()) {
				t.Fatal("revoked handoff changed applied authority/configuration")
			}
			if mode == "after-activate" {
				if len(adapter.calls) == 0 || adapter.calls[len(adapter.calls)-1] != "rollback" || strings.Contains(strings.Join(adapter.calls, ","), "commit") {
					t.Fatalf("revoked transaction did not roll back: %v", adapter.calls)
				}
			} else if len(adapter.calls) != 0 {
				t.Fatalf("unconfirmed helper wrote runtime: %v", adapter.calls)
			}
			if mode != "after-check" && mode != "after-activate" && len(checker.requests) != 0 {
				t.Fatal("unconfirmed helper started a probe")
			}
			assertStartupWritersBlocked(t, a)
		})
	}
}

func TestSelfUpdateShutdownRetainsLeaseUntilRecoveryCleanupJoins(t *testing.T) {
	a, _, adapter, checker, previous := nodeRecoveryFixture(t)
	ctx, cancel, handoff, _ := startupUpdateFixture(t, a, true)
	entered, cleaning, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	}()
	checker.hook = func(ctx context.Context, _ dataplane.NodeCheckRequest) {
		close(entered)
		<-ctx.Done()
		close(cleaning)
		<-finish // Existing checker owns bounded cleanup after request cancellation.
	}
	a.StartSelfUpdateNodeRecovery(ctx)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("startup worker did not start")
	}
	cancel()
	<-cleaning
	short, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := a.WaitSelfUpdate(short)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("join escaped cleanup: %v", err)
	}
	assertStartupWritersBlocked(t, a)
	if !a.SelfUpdate.InstallationLocked() {
		t.Fatal("installation authority ended before cleanup")
	}
	close(finish)
	waitStartupRecovery(t, handoff)
	wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := a.WaitSelfUpdate(wait); err != nil {
		t.Fatal(err)
	}
	current, _, err := a.Dataplane.Committed()
	if err != nil || !sameNodeRecoveryPlan(current, previous) || len(adapter.calls) != 0 {
		t.Fatal("shutdown changed runtime")
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
}

func TestSelfUpdateShutdownBeforeListenerCannotStartLateRecovery(t *testing.T) {
	a, _, adapter, checker, _ := nodeRecoveryFixture(t)
	ctx, cancel, handoff, _ := startupUpdateFixture(t, a, true)
	cancel()
	wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := a.WaitSelfUpdate(wait); err != nil {
		t.Fatal(err)
	}
	a.StartSelfUpdateNodeRecovery(ctx)
	waitStartupRecovery(t, handoff)
	if len(checker.requests) != 0 || len(adapter.calls) != 0 {
		t.Fatal("late listener callback revived startup authority")
	}
}
