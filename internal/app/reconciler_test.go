package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func initReconcilerFixture(t *testing.T, a *App, now time.Time) {
	t.Helper()
	r := &a.reconciler
	r.started = true
	r.path = a.Store.AutomationStatePath()
	if err := a.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"node-recovery", "legacy-routes", "feeds"} {
		r.doc.Operations = append(r.doc.Operations, automationOperation{Kind: kind, State: "completed", Reason: "scheduled", ConfigFingerprint: automationConfigFingerprint(a.Store.Get()), NextRun: now.Add(time.Hour)})
	}
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReconcilerUnattendedTwoNodeSwitchPersistsIntentBeforeProbe(t *testing.T) {
	a, current, _, adapter, previous := nodeAutofallbackFixture(t, 1)
	now := time.Now()
	initReconcilerFixture(t, a, now)
	checks := 0
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		data, err := os.ReadFile(a.Store.AutomationStatePath())
		if err != nil {
			t.Fatal(err)
		}
		var doc reconcilerDocument
		if json.Unmarshal(data, &doc) != nil {
			t.Fatal("invalid checkpoint")
		}
		found := false
		for _, op := range doc.Operations {
			if op.Kind == "node-fallback" && op.State == "running" && op.PolicyRevisions["telegram"] == 1 && op.NodeGeneration > 0 && op.NetworkFingerprint == recoveryProfile {
				found = true
			}
		}
		if !found {
			t.Fatal("probe started without durable current-generation intent")
		}
		return autofallbackResult(r, r.NodeID != current), nil
	})
	a.reconcileRound(context.Background(), now)
	a.reconcileRound(context.Background(), now.Add(time.Minute))
	status := fallbackEntry(t, a)
	if status.State != "switched" || status.NodeID == current || checks != 3 {
		t.Fatalf("unattended cycle failed: %+v checks=%d", status, checks)
	}
	plan, _, _ := a.Dataplane.Committed()
	if plan.Routes[0].Resolved != "sing-box:"+status.NodeID || !reflect.DeepEqual(plan.Routes[0].Sources, previous.Routes[0].Sources) || len(adapter.calls) == 0 {
		t.Fatal("scope or transaction lost")
	}
	data, _ := os.ReadFile(a.Store.AutomationStatePath())
	for _, secret := range []string{"vless://", "private.example", "123e4567", "reserve0.example"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("private material in automation journal")
		}
	}
	var doc reconcilerDocument
	_ = json.Unmarshal(data, &doc)
	if validateReconcilerDocument(doc) != nil || len(doc.Fallback["telegram"].SwitchAttempts) != 1 {
		t.Fatal("switch attempt not durably budgeted")
	}
}

func TestReconcilerRestartRetainsRateLimitButRevokesCachedHealth(t *testing.T) {
	a, _, _, _, _ := nodeAutofallbackFixture(t, 1)
	p := applyFixturePolicy(t, a)
	p.MaxSwitchesPerHour = 1
	now := time.Now()
	initReconcilerFixture(t, a, now)
	if err := a.reserveFallbackSwitch(context.Background(), p, now); err != nil {
		t.Fatal(err)
	}
	c := a.reconciler.doc.Fallback["telegram"]
	c.Status.Healthy = true
	c.Status.Failures = 2
	c.Status.State = "healthy"
	c.LastSwitched = now
	a.reconciler.doc.Fallback["telegram"] = c
	a.reconciler.doc.Operations[0].State = "running"
	a.reconciler.doc.Operations[0].Attempts = 2
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := &App{Store: a.Store}
	b.reconciler.started = true
	b.reconciler.path = a.Store.AutomationStatePath()
	if err := b.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.reserveFallbackSwitch(context.Background(), p, now.Add(time.Minute)); err == nil {
		t.Fatal("reboot erased hourly switch budget")
	}
	entry := b.nodeAutofallback.entries["telegram"]
	if entry.status.Healthy || entry.status.Failures != 0 || !entry.lastSwitched.Equal(now) {
		t.Fatal("cached proof survived reboot or cooldown vanished")
	}
	if b.reconciler.doc.Operations[0].State != "interrupted" {
		t.Fatal("unfinished task replayed as success")
	}
}

func TestReconcilerExternalJournalChangeBlocksAutomaticMutation(t *testing.T) {
	a, _, _, adapter, _ := nodeAutofallbackFixture(t, 1)
	now := time.Now()
	initReconcilerFixture(t, a, now)
	changed := []byte(`{"foreign":true}`)
	if err := os.WriteFile(a.Store.AutomationStatePath(), changed, 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		called = true
		return autofallbackResult(r, true), nil
	})
	a.reconcileRound(context.Background(), now)
	if !a.reconciler.blocked || called || len(adapter.calls) != 0 {
		t.Fatal("uncertain journal admitted automatic work")
	}
	data, _ := os.ReadFile(a.Store.AutomationStatePath())
	if string(data) != string(changed) {
		t.Fatal("foreign journal overwritten")
	}
}

func TestReconcilerManualCancellationKeepsLeaseUntilCleanup(t *testing.T) {
	a, _, _, adapter, _ := nodeAutofallbackFixture(t, 1)
	now := time.Now()
	initReconcilerFixture(t, a, now)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	cleanup := make(chan struct{})
	finished := make(chan struct{})
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-cleanup
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	go func() { a.reconcileRound(context.Background(), now); close(finished) }()
	awaitOperation(t, entered)
	a.interruptAutomation(httptest.NewRequest("PUT", "/api/v1/service-policies/telegram", nil))
	awaitOperation(t, canceled)
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("cancel released worker admission before cleanup")
	}
	close(cleanup)
	awaitOperation(t, finished)
	if len(adapter.calls) != 0 {
		t.Fatal("canceled intent applied")
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("cleanup retained gate")
	} else {
		release()
	}
	a.reconciler.mu.Lock()
	defer a.reconciler.mu.Unlock()
	if !a.reconciler.doc.ManualUntil.After(now) {
		t.Fatal("manual priority was not retained")
	}
	for _, op := range a.reconciler.doc.Operations {
		if op.Kind == "node-fallback" && (op.State != "backoff" || op.Attempts != 1 || !op.NextRun.After(now)) {
			t.Fatal("canceled task has no bounded backoff")
		}
	}
}

func TestReconcilerCorruptStartupIsBlockedAndShutdownJoins(t *testing.T) {
	a, _, _, _, _ := nodeAutofallbackFixture(t, 1)
	bad := []byte(`{"schema":99,"owner":"foreign"}`)
	if err := os.WriteFile(a.Store.AutomationStatePath(), bad, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	a.StartServiceReconciler(ctx)
	stop()
	joined, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.WaitServiceReconciler(joined); err != nil {
		t.Fatal(err)
	}
	if a.reconcilerSnapshot()["state"] != "blocked" {
		t.Fatal("invalid journal accepted")
	}
	data, _ := os.ReadFile(a.Store.AutomationStatePath())
	if string(data) != string(bad) {
		t.Fatal("corrupt journal was erased")
	}
}

func TestReconcilerWaitStopsItsOwnedLoopAndInvalidJournalNeverEntersDTO(t *testing.T) {
	a, _, _, _, _ := nodeAutofallbackFixture(t, 1)
	private := `{"schema":99,"owner":"foreign","operations":[{"reason":"private-token-must-not-enter-UI"}]}`
	if err := os.WriteFile(a.Store.AutomationStatePath(), []byte(private), 0600); err != nil {
		t.Fatal(err)
	}
	a.StartServiceReconciler(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.WaitServiceReconciler(ctx); err != nil {
		t.Fatal(err)
	}
	view, _ := json.Marshal(a.reconcilerSnapshot())
	if strings.Contains(string(view), "private-token") {
		t.Fatal("invalid private journal leaked through metadata DTO")
	}
}
