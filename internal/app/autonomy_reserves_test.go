package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// Real consent/config/node stores and transaction manager. Only host checks,
// network probes and the OS adapter are simulated; this is not HIL evidence.
func autonomyThreeReserveFixture(t *testing.T) (*App, []string, *nodeApplyAdapter) {
	t.Helper()
	a, _, adapter := autonomousIntegrationFixture(t)
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174002@third.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		ids = append(ids, node.ID)
	}
	slices.Sort(ids)
	a.nodeReviews.options = func() []routecatalog.Option {
		out := []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box", Installed: true, Configured: true, Selectable: true}}
		for _, id := range ids {
			out = append(out, routecatalog.Option{ID: "sing-box:" + id, Installed: true, Configured: true, Selectable: true, Services: []string{"my-independent-site", "telegram"}})
		}
		return out
	}
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.CandidatesPerRound = 3
	err = a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(request, true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if autonomyTestState(a).State != "applied" || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[0] {
		t.Fatal("initial A assignment failed")
	}
	adapter.calls = nil
	return a, ids, adapter
}

func autonomyConfirmFailure(t *testing.T, a *App, ctx context.Context) {
	t.Helper()
	autonomyTestDue(a, false)
	a.autonomyRound(ctx, time.Now())
	if state := autonomyTestState(a); state.Failures != 1 {
		t.Fatalf("first failure was not confirmed once: %+v", state)
	}
	autonomyTestDue(a, true)
	a.autonomyRound(ctx, time.Now())
}

func TestAutonomyReserveTargetDoesNotCountAnotherKeyForSameServer(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(request, true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	before := a.Store.Get()
	if autonomyTestState(a).State != "applied" {
		t.Fatal("primary was not applied")
	}
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174009@reserve.example:8443?security=tls#Another", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Nodes) != len(ids)+1 {
		t.Fatal("duplicate-server fixture missing")
	}
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.ReserveTarget = 3
	a.autonomy.doc.Policy.CandidatesPerRound = 3
	err = a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	adapter.calls = nil
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "healthy" || len(r.Reserves) != 2 || !strings.Contains(r.Message, "ещё не заполнен") {
		t.Fatal("duplicate server filled reserve target", r)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(adapter.calls, []string{"health"}) {
		t.Fatal("diversity replaced healthy route", adapter.calls)
	}
}

func TestAutonomyReservesDefiniteFailureContinuesToFreshPeer(t *testing.T) {
	a, ids, adapter := autonomyThreeReserveFixture(t)
	before := a.Store.Get()
	beforeSwitches := len(autonomyTestState(a).Switches)
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, request.NodeID)
		return autofallbackResult(request, request.NodeID == ids[2]), nil
	})
	autonomyConfirmFailure(t, a, context.Background())
	state := autonomyTestState(a)
	after := a.Store.Get()
	if state.State != "applied" || selectedRoute(after.AppliedServices["my-independent-site"]) != "sing-box:"+ids[2] {
		t.Fatalf("C was not applied after definite failure of B: %+v, checked=%v", state, checked)
	}
	if !reflect.DeepEqual(checked, []string{ids[0], ids[0], ids[1], ids[2]}) {
		t.Fatalf("not an ordered fresh bounded check of A/B/C: %v", checked)
	}
	if len(state.Switches) != beforeSwitches+1 || slices.Contains(state.Reserves, ids[1]) {
		t.Fatal("failed isolated B consumed a switch or remained a ready reserve")
	}
	if !reflect.DeepEqual(before.Services["youtube"], after.Services["youtube"]) || !reflect.DeepEqual(before.AppliedServices["telegram"], after.AppliedServices["telegram"]) || !reflect.DeepEqual(before.AppliedServices["my-independent-site"].Sources, after.AppliedServices["my-independent-site"].Sources) {
		t.Fatal("another service, unapplied draft or client scope changed")
	}
	if !reflect.DeepEqual(adapter.calls, []string{"snapshot", "stage", "validate", "canary", "activate", "health", "commit"}) {
		t.Fatal("C bypassed the guarded transaction", adapter.calls)
	}
}

func TestAutonomyReservesUncertainOrGlobalFailureStopsBeforeC(t *testing.T) {
	for _, scenario := range []string{"inconclusive", "cleanup", "cleanup-cancel", "network", "engine", "ownership", "permission", "expired", "refresh-inconclusive", "refresh-cleanup", "refresh-network"} {
		outcome := strings.TrimPrefix(scenario, "refresh-")
		t.Run(scenario, func(t *testing.T) {
			a, ids, adapter := autonomyThreeReserveFixture(t)
			if scenario != outcome {
				a.autonomy.mu.Lock()
				runtime := a.autonomy.doc.Runtime["my-independent-site"]
				runtime.ReserveCheckedAt = time.Time{}
				a.autonomy.doc.Runtime["my-independent-site"] = runtime
				err := a.persistAutonomyLocked(context.Background())
				a.autonomy.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			before := a.Store.Get()
			beforeSwitches := len(autonomyTestState(a).Switches)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, request.NodeID)
				result := autofallbackResult(request, request.NodeID == ids[2])
				if request.NodeID != ids[1] {
					return result, nil
				}
				switch outcome {
				case "inconclusive":
					result.Verdict = evidence.VerdictInconclusive
				case "cleanup", "cleanup-cancel":
					result.ErrorCode = "node-cleanup-failed"
					result.Stage = "cleanup"
					result.Verdict = evidence.VerdictInconclusive
					if outcome == "cleanup-cancel" {
						cancel()
					}
				case "network":
					return result, dataplane.ErrExactNodeNetworkChanged
				case "engine":
					return result, dataplane.ErrExactNodeRuntime
				case "ownership":
					return result, dataplane.ErrReviewChanged
				case "permission":
					a.autonomy.mu.Lock()
					a.autonomy.doc.Policy.Enabled = false
					err := a.persistAutonomyLocked(context.Background())
					a.autonomy.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				case "expired":
					result.FinishedAt = time.Now().Add(-2 * time.Hour)
					result.ExpiresAt = time.Now().Add(-time.Hour)
				}
				return result, nil
			})
			autonomyConfirmFailure(t, a, ctx)
			state := autonomyTestState(a)
			wantState := map[string]string{"inconclusive": "unconfirmed", "cleanup": "requires-review", "cleanup-cancel": "requires-review", "network": "network-unknown", "engine": "checker-unavailable", "ownership": "paused", "permission": "paused", "expired": "checker-unavailable"}[outcome]
			if state.State != wantState || !reflect.DeepEqual(checked, []string{ids[0], ids[0], ids[1]}) || len(adapter.calls) != 0 || len(state.Switches) != beforeSwitches || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatalf("continued after %s: state=%s checks=%v calls=%v", outcome, state.State, checked, adapter.calls)
			}
			if !slices.Contains(state.Reserves, ids[1]) {
				t.Fatal("unattributed failure removed B from reserves")
			}
		})
	}
}

func TestAutonomyReservesCandidateBudgetDefersCWithoutRetryingFailedB(t *testing.T) {
	a, ids, adapter := autonomyThreeReserveFixture(t)
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.CandidatesPerRound = 1
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	beforeSwitches := len(autonomyTestState(a).Switches)
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, request.NodeID)
		return autofallbackResult(request, request.NodeID == ids[2]), nil
	})
	autonomyConfirmFailure(t, a, context.Background())
	state := autonomyTestState(a)
	if state.State != "searching" || !reflect.DeepEqual(checked, []string{ids[0], ids[0], ids[1]}) || len(state.Switches) != beforeSwitches || len(adapter.calls) != 0 {
		t.Fatalf("candidate budget exceeded: %+v, checked=%v, calls=%v", state, checked, adapter.calls)
	}
	checked = nil
	autonomyTestDue(a, true)
	a.autonomyRound(context.Background(), time.Now())
	if autonomyTestState(a).State != "applied" || !reflect.DeepEqual(checked, []string{ids[0], ids[2]}) || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[2] {
		t.Fatalf("failed B displaced C again: state=%s checks=%v", autonomyTestState(a).State, checked)
	}
}

// F03's Apply-failure -> C case intentionally remains closed. A successful
// rollback alone cannot distinguish a bad B from a shared engine/service
// failure. These cases pin that boundary until dataplane adds attribution.
func TestAutonomyReservesApplyFailureStopsEvenAfterRollback(t *testing.T) {
	for _, outcome := range []string{"rolled-back", "rollback-failed", "network", "ownership", "global-engine"} {
		t.Run(outcome, func(t *testing.T) {
			a, ids, adapter := autonomyThreeReserveFixture(t)
			before := a.Store.Get()
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, request.NodeID)
				return autofallbackResult(request, request.NodeID != ids[0]), nil
			})
			adapter.after = func(phase string) error {
				if phase == "rollback" && outcome == "rollback-failed" {
					return errors.New("owned rollback did not finish")
				}
				if phase == "health" {
					switch outcome {
					case "network":
						return dataplane.ErrNetworkChanged
					case "ownership":
						return dataplane.ErrReviewChanged
					default:
						return errors.New("shared engine or candidate service failed")
					}
				}
				return nil
			}
			autonomyConfirmFailure(t, a, context.Background())
			state := autonomyTestState(a)
			want := map[string]string{"rolled-back": "apply-refused", "rollback-failed": "requires-review", "network": "network-unknown", "ownership": "paused", "global-engine": "apply-refused"}[outcome]
			if state.State != want || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(checked, []string{ids[0], ids[0], ids[1]}) || !slices.Contains(adapter.calls, "rollback") {
				t.Fatalf("unattributed Apply failure continued: state=%s checks=%v calls=%v", state.State, checked, adapter.calls)
			}
			if !slices.Contains(state.Reserves, ids[1]) {
				t.Fatal("unattributed Apply failure penalized B")
			}
			if outcome == "rollback-failed" {
				adapter.calls, checked = nil, nil
				autonomyTestDue(a, false)
				a.autonomyRound(context.Background(), time.Now())
				if autonomyTestState(a).State != "requires-review" || len(adapter.calls) != 0 || len(checked) != 0 {
					t.Fatal("incomplete rollback did not block the next round")
				}
			}
		})
	}
}

func TestAutonomyApplyFailureRetainsRealExecutionAndCause(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "incomplete"}[rollbackFails], func(t *testing.T) {
			a, ids, adapter := autonomyThreeReserveFixture(t)
			cause := errors.New("unattributed service failure")
			adapter.after = func(phase string) error {
				if phase == "health" {
					return cause
				}
				if phase == "rollback" && rollbackFails {
					return errors.New("cleanup failed")
				}
				return nil
			}
			a.autonomy.mu.Lock()
			policy, service := a.autonomy.doc.Policy, a.autonomy.doc.Services["my-independent-site"]
			a.autonomy.mu.Unlock()
			profile, err := stableNodeProfile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			err = a.applyAutonomyRoute(context.Background(), policy, service, a.Store.Get(), profile, "sing-box:"+ids[1])
			var failure *autonomyApplyFailure
			if !errors.As(err, &failure) || !errors.Is(err, cause) || failure.Execution.PlanID == "" || failure.Execution.FinishedAt == "" {
				t.Fatalf("lost cause or execution: %T %v", err, err)
			}
			want := "rolled-back"
			if rollbackFails {
				want = "rollback-failed"
			}
			status, statusErr := a.Dataplane.Status()
			if failure.Execution.State != want || statusErr != nil || status.Execution == nil || !reflect.DeepEqual(failure.Execution, *status.Execution) {
				t.Fatalf("not the actual completed transaction result: %+v, statusErr=%v", failure.Execution, statusErr)
			}
		})
	}
}
