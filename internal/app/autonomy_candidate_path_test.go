package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func candidatePathFailureForTest(p dataplane.Plan, id string) *dataplane.CandidatePathFailure {
	f := candidateFailureForTest(p, id)
	if f == nil {
		return nil
	}
	f.Code = "node-path-io"
	return (*dataplane.CandidatePathFailure)(f)
}

func TestAutonomyColdCandidatePathRollbackThenFreshPeerWithoutPenalty(t *testing.T) {
	a, ids, old := autonomousIntegrationFixture(t)
	before := a.Store.Get()
	adapter := &candidateApplyAdapter{nodeApplyAdapter: old}
	a.Dataplane.Adapters["sing-box"] = adapter
	adapter.health = func(p dataplane.Plan) error {
		if f := candidatePathFailureForTest(p, ids[0]); f != nil {
			return f
		}
		return nil
	}
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		if req.NodeID == ids[1] && !slices.Contains(old.calls, "verify-rollback") {
			t.Fatal("fresh peer check preceded verified rollback")
		}
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	after := a.Store.Get()
	if r.State != "applied" || r.Search == nil || r.Search.Halted || r.Search.Cursor != 2 || !reflect.DeepEqual(checked, ids) ||
		len(r.CandidateFailures) != 0 || len(r.Switches) != 2 || selectedRoute(after.AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] {
		t.Fatal("path-only failure did not continue through fresh check without penalty", r, checked, old.calls)
	}
	want := []string{"snapshot", "stage", "validate", "canary", "activate", "health", "rollback", "verify-rollback", "snapshot", "stage", "validate", "canary", "activate", "health", "commit"}
	if !reflect.DeepEqual(old.calls, want) || !reflect.DeepEqual(before.AppliedServices["telegram"], after.AppliedServices["telegram"]) {
		t.Fatal("path-only retry bypassed transaction or changed another service", old.calls)
	}
	d10Reopen(t, a)
	if r := autonomyTestState(a); len(r.CandidateFailures) != 0 || r.Search.Halted {
		t.Fatal("restart acquired transport reputation or lost confirmed continuation", r)
	}
}

func TestAutonomyCandidatePathCannotBypassRollbackAndConsentGates(t *testing.T) {
	for _, scenario := range []string{"generic-io", "tls", "dns", "unknown-cleanup", "unverified", "rollback-error", "other-service", "other-node", "other-plan", "other-scope", "expired", "wrong-code", "network-after-rollback", "cancel-after-rollback", "revoke-after-rollback", "config-after-rollback", "budget"} {
		t.Run(scenario, func(t *testing.T) {
			a, ids, old := autonomousIntegrationFixture(t)
			before := a.Store.Get()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapter := &candidateApplyAdapter{nodeApplyAdapter: old}
			a.Dataplane.Adapters["sing-box"] = adapter
			adapter.health = func(p dataplane.Plan) error {
				f := candidatePathFailureForTest(p, ids[0])
				if f == nil {
					return nil
				}
				switch scenario {
				case "generic-io":
					return errors.New("node service IP path unsupported or unavailable; reason=io")
				case "tls", "dns", "unknown-cleanup":
					return errors.New(scenario)
				case "other-service":
					f.ServiceID = "telegram"
				case "other-node":
					f.Route = "sing-box:" + ids[1]
				case "other-plan":
					f.PlanID += "x"
				case "other-scope":
					f.RouteDigest = "other"
				case "expired":
					f.ObservedAt = time.Now().Add(-3 * time.Minute)
				case "wrong-code":
					f.Code = "timeout"
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
					err := a.persistAutonomyLocked(context.Background())
					a.autonomy.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				case "config-after-rollback":
					if err := a.Store.SetSafeMode(true); err != nil {
						t.Fatal(err)
					}
				}
				return true, nil
			}
			if scenario == "budget" {
				a.autonomy.mu.Lock()
				a.autonomy.doc.Policy.MaxSwitchesPerHour = 1
				err := a.persistAutonomyLocked(context.Background())
				a.autonomy.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, req.NodeID)
				return d10Result(req, "sing-box", true), nil
			})
			a.autonomyRound(ctx, time.Now())
			r := autonomyTestState(a)
			if r.State == "applied" || r.Search == nil || len(r.CandidateFailures) != 0 || slices.Contains(old.calls, "commit") {
				t.Fatal("untrusted path receipt applied or penalized candidate", r, checked, old.calls)
			}
			if scenario == "budget" {
				if r.State != "rate-limited" || r.Search.Halted || len(r.Switches) != 1 {
					t.Fatal("verified path retry lost apply budget", r)
				}
			} else if !r.Search.Halted || !reflect.DeepEqual(checked, ids[:1]) {
				t.Fatal("untrusted failure cleared latch or checked another peer", r, checked)
			}
			if scenario != "config-after-rollback" && !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("refused retry changed configuration")
			}
		})
	}
}
