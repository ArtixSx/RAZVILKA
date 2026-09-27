package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Host operations are simulated; config/consent stores and the transaction
// journal are real. The production receipt constructor is tested separately
// with the proxy's live health checks. This is not physical LAN evidence.
type candidateApplyAdapter struct {
	*nodeApplyAdapter
	health func(dataplane.Plan) error
	verify func() (bool, error)
}

func (a *candidateApplyAdapter) Health(_ context.Context, p dataplane.Plan, _ string) error {
	if err := a.phase("health"); err != nil {
		return err
	}
	if a.health != nil {
		return a.health(p)
	}
	return nil
}
func (a *candidateApplyAdapter) VerifyRollback(ctx context.Context, _ dataplane.Plan, _ string) (bool, error) {
	if err := a.phase("verify-rollback"); err != nil {
		return false, err
	}
	if a.verify != nil {
		return a.verify()
	}
	return true, ctx.Err()
}
func candidateFailureForTest(p dataplane.Plan, id string) *dataplane.CandidateServiceFailure {
	for _, route := range p.Routes {
		if route.ServiceID == "my-independent-site" && route.Resolved == "sing-box:"+id {
			data, _ := json.Marshal(route)
			digest := sha256.Sum256(data)
			return &dataplane.CandidateServiceFailure{PlanID: p.PlanID, Digest: p.Digest, Network: p.NetworkProfileID,
				ServiceID: route.ServiceID, Route: route.Resolved, RouteDigest: hex.EncodeToString(digest[:]), Code: "http-403", ObservedAt: time.Now().UTC()}
		}
	}
	return nil
}

func TestAutonomyCandidateApplyFailureVerifiedRollbackThenFreshC(t *testing.T) {
	a, ids, old := autonomyThreeReserveFixture(t)
	before := a.Store.Get()
	switches := len(autonomyTestState(a).Switches)
	adapter := &candidateApplyAdapter{nodeApplyAdapter: old}
	a.Dataplane.Adapters["sing-box"] = adapter
	adapter.health = func(p dataplane.Plan) error {
		if f := candidateFailureForTest(p, ids[1]); f != nil {
			return f
		}
		return nil
	}
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, request.NodeID)
		if request.NodeID == ids[2] && !slices.Contains(old.calls, "verify-rollback") {
			t.Fatal("C checked before rollback verification")
		}
		return autofallbackResult(request, request.NodeID != ids[0]), nil
	})
	autonomyConfirmFailure(t, a, context.Background())
	state, after := autonomyTestState(a), a.Store.Get()
	if state.State != "applied" || selectedRoute(after.AppliedServices["my-independent-site"]) != "sing-box:"+ids[2] ||
		!reflect.DeepEqual(checked, []string{ids[0], ids[0], ids[1], ids[2]}) || len(state.Switches) != switches+2 ||
		len(state.CandidateFailures) != 1 || state.CandidateFailures[0].NodeID != ids[1] || slices.Contains(state.Reserves, ids[1]) {
		t.Fatalf("B -> verified rollback -> C failed: state=%+v checked=%v calls=%v", state, checked, old.calls)
	}
	want := []string{"snapshot", "stage", "validate", "canary", "activate", "health", "rollback", "verify-rollback", "snapshot", "stage", "validate", "canary", "activate", "health", "commit"}
	if !reflect.DeepEqual(old.calls, want) {
		t.Fatalf("wrong transaction order: %v", old.calls)
	}
	if !reflect.DeepEqual(before.Services["youtube"], after.Services["youtube"]) || !reflect.DeepEqual(before.AppliedServices["telegram"], after.AppliedServices["telegram"]) ||
		!reflect.DeepEqual(before.AppliedServices["my-independent-site"].Sources, after.AppliedServices["my-independent-site"].Sources) {
		t.Fatal("foreign draft or device scope changed")
	}
	// Reopen the durable state; previous successes are discarded while this
	// short negative cooldown survives. Healthy C stays pinned; B is skipped.
	a.autonomy.mu.Lock()
	a.autonomy.loaded = false
	a.autonomy.mu.Unlock()
	if err := a.loadAutonomy(context.Background()); err != nil {
		t.Fatal(err)
	}
	checked = nil
	a.autonomyRound(context.Background(), time.Now())
	if autonomyTestState(a).State != "healthy" || slices.Contains(checked, ids[1]) {
		t.Fatalf("restart lost scoped cooldown: %v", checked)
	}
}

func TestAutonomyCandidateFailureCannotBypassStopConditions(t *testing.T) {
	for _, scenario := range []string{"unverified", "rollback-error", "other-service", "other-node", "other-plan", "other-scope", "expired", "429", "network-after-rollback", "cancel-after-rollback", "revoke-after-rollback", "budget"} {
		t.Run(scenario, func(t *testing.T) {
			a, ids, old := autonomyThreeReserveFixture(t)
			before := a.Store.Get()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapter := &candidateApplyAdapter{nodeApplyAdapter: old}
			a.Dataplane.Adapters["sing-box"] = adapter
			adapter.health = func(p dataplane.Plan) error {
				f := candidateFailureForTest(p, ids[1])
				if f == nil {
					return nil
				}
				switch scenario {
				case "other-service":
					f.ServiceID = "telegram"
				case "other-node":
					f.Route = "sing-box:" + ids[2]
				case "other-plan":
					f.PlanID += "x"
				case "other-scope":
					f.RouteDigest = "other"
				case "expired":
					f.ObservedAt = time.Now().Add(-3 * time.Minute)
				case "429":
					f.Code = "http-429"
				}
				return f
			}
			adapter.verify = func() (bool, error) {
				switch scenario {
				case "unverified":
					return false, nil
				case "rollback-error":
					return false, errors.New("owned readback failed")
				case "network-after-rollback":
					a.FreshProfile = func(context.Context) (string, error) { return "wan-other", nil }
				case "cancel-after-rollback":
					cancel()
				case "revoke-after-rollback":
					a.autonomy.mu.Lock()
					a.autonomy.doc.Policy.Enabled = false
					_ = a.persistAutonomyLocked(context.Background())
					a.autonomy.mu.Unlock()
				}
				return true, nil
			}
			if scenario == "budget" {
				a.autonomy.mu.Lock()
				a.autonomy.doc.Policy.MaxSwitchesPerHour = len(a.autonomy.doc.Runtime["my-independent-site"].Switches) + 1
				_ = a.persistAutonomyLocked(context.Background())
				a.autonomy.mu.Unlock()
			}
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, request.NodeID)
				return autofallbackResult(request, request.NodeID != ids[0]), nil
			})
			autonomyConfirmFailure(t, a, ctx)
			state := autonomyTestState(a)
			if state.State == "applied" || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("forbidden C changed configuration", state.State)
			}
			if scenario == "budget" {
				if state.State != "rate-limited" || len(state.CandidateFailures) != 1 {
					t.Fatal("attempt budget lost", state)
				}
			} else if len(state.CandidateFailures) != 0 || slices.Contains(checked, ids[2]) {
				t.Fatalf("uncertain B penalized or C checked: state=%+v checks=%v", state, checked)
			}
		})
	}
}
