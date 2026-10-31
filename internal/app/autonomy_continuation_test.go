package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func singleAutonomyCandidatePerRound(t *testing.T, a *App) {
	t.Helper()
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.CandidatesPerRound = 1
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

// Real worker, durable cursor and Apply owner; only network/OS effects use the
// integration fixtures. This checks scheduling, not native router performance.
func TestAutonomyColdSearchContinuesAfterBoundedProgress(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	singleAutonomyCandidatePerRound(t, a)
	before := a.Store.Get()
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		if req.NodeID == ids[0] {
			return autonomyTerminalNodeFailure(req, "transport"), nil
		}
		return d10Result(req, "sing-box", true), nil
	})
	started := time.Now()
	a.autonomyRound(context.Background(), started)
	finished := time.Now()
	r := autonomyTestState(a)
	if r.State != "searching" || r.Search == nil || r.Search.Cursor != 1 || r.Search.Exhausted || r.Search.Halted || !reflect.DeepEqual(checked, ids[:1]) || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("bounded first round did not preserve an unapplied continuation", r, checked, adapter.calls)
	}
	if r.NextCheck.Before(started.Add(5*time.Second)) || r.NextCheck.After(finished.Add(5*time.Second)) {
		t.Fatalf("unfinished cold search waits %v; want the next 5-second coordinator tick", r.NextCheck.Sub(finished))
	}
	data, err := os.ReadFile(a.autonomy.path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := decodeAutonomy(data)
	if err != nil || !doc.Runtime["my-independent-site"].NextCheck.Equal(r.NextCheck) {
		t.Fatal("continuation was not saved with the consumed cursor", err)
	}
	a.autonomyRound(context.Background(), time.Now())
	if !reflect.DeepEqual(checked, ids[:1]) {
		t.Fatal("continuation retried immediately without yielding", checked)
	}
	// Advance the scheduler clock without sleeping or manufacturing fresh proof.
	a.autonomyRound(context.Background(), r.NextCheck)
	next := autonomyTestState(a)
	if !reflect.DeepEqual(checked, ids) || next.State != "applied" || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] || !slices.Contains(adapter.calls, "commit") {
		t.Fatal("continuation did not recheck and apply the first usable remaining peer", next, checked, adapter.calls)
	}
	if next.NextCheck.Before(r.NextCheck.Add(time.Duration(a.autonomyPolicy().CheckSeconds) * time.Second)) {
		t.Fatal("applied route inherited the cold-search cadence", next.NextCheck)
	}
}

func TestReconcilerPersistsColdSearchContinuationWithoutFeedInterval(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	singleAutonomyCandidatePerRound(t, a)
	now := time.Now()
	initReconcilerFixture(t, a, now)
	for _, kind := range []string{"node-fallback", "service-checks"} {
		a.reconciler.doc.Operations = append(a.reconciler.doc.Operations, automationOperation{Kind: kind, State: "completed", Reason: "scheduled", ConfigFingerprint: automationConfigFingerprint(a.Store.Get()), NextRun: now.Add(time.Hour)})
	}
	for i := range a.reconciler.doc.Operations {
		if a.reconciler.doc.Operations[i].Kind == "feeds" {
			a.reconciler.doc.Operations[i].NextRun = now
		}
	}
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return autonomyTerminalNodeFailure(req, "transport"), nil
	})
	a.reconcileRound(context.Background(), now)
	finished := time.Now()
	if r := autonomyTestState(a); r.State != "searching" || r.Search == nil || r.Search.Cursor != 1 || !reflect.DeepEqual(checked, ids[:1]) || len(adapter.calls) != 0 {
		t.Fatal("feeds did not run exactly one bounded cold-search round", r, checked, adapter.calls)
	}
	data, err := os.ReadFile(a.reconciler.path)
	if err != nil {
		t.Fatal(err)
	}
	var doc reconcilerDocument
	if json.Unmarshal(data, &doc) != nil || validateReconcilerDocument(doc) != nil || len(doc.Operations) != 5 {
		t.Fatal("continuation changed the durable operation set")
	}
	for _, op := range doc.Operations {
		if op.Kind == "feeds" {
			if op.State != "completed" || op.NextRun.Before(now.Add(5*time.Second)) || op.NextRun.After(finished.Add(5*time.Second)) {
				t.Fatalf("feeds added its ordinary interval to continuation: state=%s delay=%v", op.State, op.NextRun.Sub(finished))
			}
		} else if !op.NextRun.Equal(now.Add(time.Hour)) || op.ID != 0 {
			t.Fatal("continuation made unrelated maintenance due", op)
		}
	}
	a.reconcileRound(context.Background(), time.Now())
	if !reflect.DeepEqual(checked, ids[:1]) {
		t.Fatal("durable continuation spun immediately", checked)
	}
}

func TestAutonomyColdContinuationSharesSlotsBetweenServices(t *testing.T) {
	a, ids, adapter := serviceRefusalFixture(t, 2)
	singleAutonomyCandidatePerRound(t, a)
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(context.Background(), "telegram"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a.autonomy.mu.Lock()
	for id, service := range a.autonomy.doc.Services {
		r := a.autonomy.doc.Runtime[id]
		r.State, r.NextCheck = "searching", now.Add(-time.Second)
		r.Search = &autonomy.Traversal{Version: autonomyTraversalVersion(a.autonomy.doc.Policy, service, "sing-box", recoveryProfile), Ordered: slices.Clone(ids)}
		a.autonomy.doc.Runtime[id] = r
	}
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	var services []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		services = append(services, req.Service.ID)
		return autonomyTerminalNodeFailure(req, "transport"), nil
	})
	for round := range 4 {
		a.autonomyRound(context.Background(), now.Add(time.Duration(round)*10*time.Second))
	}
	if !reflect.DeepEqual(services, []string{"my-independent-site", "telegram", "my-independent-site", "telegram"}) || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("one cold continuation displaced the other or changed a route", services, adapter.calls)
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	for id, r := range a.autonomy.doc.Runtime {
		if r.State != "searching" || r.Search == nil || r.Search.Cursor != 2 || r.Search.Exhausted || r.Search.Halted {
			t.Fatal("a cold service lost bounded durable progress", id, r)
		}
	}
}

func TestAutonomyColdContinuationHonorsChangedIntent(t *testing.T) {
	for _, change := range []string{"policy-disabled", "protocol-revoked", "service-disabled", "manual", "safe-mode", "stopped"} {
		t.Run(change, func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			singleAutonomyCandidatePerRound(t, a)
			checks := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks++
				return autonomyTerminalNodeFailure(req, "transport"), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			r := autonomyTestState(a)
			if r.State != "searching" || r.Search == nil || r.Search.Cursor != 1 || checks != 1 {
				t.Fatal("missing first bounded round", r, checks)
			}
			switch change {
			case "policy-disabled", "protocol-revoked":
				p := a.autonomyPolicy()
				if change == "policy-disabled" {
					p.Enabled = false
				} else {
					p.Protocols = []string{"hysteria2"}
				}
				w := httptest.NewRecorder()
				a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
				if w.Code != 200 {
					t.Fatalf("policy change: %d %s", w.Code, w.Body.String())
				}
			case "service-disabled":
				draft := a.Store.Get().Services["my-independent-site"]
				draft.Enabled = false
				if err := a.Store.UpdateService("my-independent-site", draft); err != nil {
					t.Fatal(err)
				}
			case "manual":
				mode := "manual"
				if err := a.Store.UpdateServiceControl(&mode, nil, a.Store.Get().Revision); err != nil {
					t.Fatal(err)
				}
			case "safe-mode":
				if err := a.Store.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
			case "stopped":
				if _, err := a.Store.ApplyAutonomyRouteWithRollback("telegram", "sing-box", []string{"192.168.1.2/32"}, a.Store.Get().Revision); err != nil {
					t.Fatal(err)
				}
				if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": "sing-box"}, a.Store.Get().Revision); err != nil {
					t.Fatal(err)
				}
			}
			before := a.Store.Get()
			if change != "protocol-revoked" && !a.nextAutonomySearchCheck(time.Now()).IsZero() {
				t.Fatal("revoked intent kept an early coordinator wake")
			}
			// A changed allowed protocol can cause one due re-evaluation, but
			// cannot probe the old pool or keep its old continuation alive.
			a.autonomyRound(context.Background(), r.NextCheck)
			if checks != 1 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || !a.nextAutonomySearchCheck(time.Now()).IsZero() {
				t.Fatal("old continuation outlived changed intent", autonomyTestState(a), checks, adapter.calls)
			}
		})
	}
}

func TestAutonomyColdContinuationDoesNotAccelerateTimeoutRotation(t *testing.T) {
	for _, progressBeforeTimeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout-only", true: "progress-then-timeout"}[progressBeforeTimeout], func(t *testing.T) {
			a, _, adapter := serviceRefusalFixture(t, 1)
			checks := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks++
				if progressBeforeTimeout && checks == 1 {
					return autonomyTerminalNodeFailure(req, "transport"), nil
				}
				return autonomyExactServiceTimeout(req), nil
			})
			now := time.Now()
			a.autonomyRound(context.Background(), now)
			r := autonomyTestState(a)
			wantCursor := 0
			if progressBeforeTimeout {
				wantCursor = 1
			}
			if r.State != "searching" || r.Search == nil || r.Search.Cursor != wantCursor || checks != wantCursor+1 || len(adapter.calls) != 0 || !r.NextCheck.Equal(now.Add(time.Duration(a.autonomyPolicy().CheckSeconds)*time.Second)) {
				t.Fatal("timeout gained a fast retry or lost its pending peer", r, checks, adapter.calls)
			}
			if next := a.nextAutonomySearchCheck(time.Now()); !next.Equal(r.NextCheck) {
				t.Fatal("coordinator shortened the timeout's saved interval", next, r.NextCheck)
			}
		})
	}
}
