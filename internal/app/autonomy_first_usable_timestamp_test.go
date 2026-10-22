package app

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Real enrollment/config/node stores, search and transaction manager. Only the
// checker and OS adapter are modeled; this is not live router evidence.
func TestAutonomyFirstUsablePublishesOnlyAppliedExactCheckTimestamp(t *testing.T) {
	for _, rollbackFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh-first", true: "fresh-peer-after-verified-rollback"}[rollbackFirst], func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			if rollbackFirst {
				candidate := &candidateApplyAdapter{nodeApplyAdapter: adapter}
				candidate.health = func(p dataplane.Plan) error {
					if failure := candidateFailureForTest(p, ids[0]); failure != nil {
						return failure
					}
					return nil
				}
				a.Dataplane.Adapters["sing-box"] = candidate
			}
			proofs := map[string]dataplane.NodeCheckResult{}
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				proof := d10Result(req, "sing-box", true)
				proofs[req.NodeID] = proof
				return proof, nil
			})
			a.autonomyRound(context.Background(), time.Now())
			wantID := ids[0]
			if rollbackFirst {
				wantID = ids[1]
			}
			proof, checked := proofs[wantID]
			r := autonomyTestState(a)
			if r.State != "applied" || !checked || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+wantID || !slices.Contains(adapter.calls, "commit") || proof.FinishedAt.IsZero() || !r.CheckedAt.Equal(proof.FinishedAt) {
				t.Fatal("successful first apply did not publish the exact checked node time", r.State, r.CheckedAt, proof.FinishedAt, adapter.calls)
			}
			if rollbackFirst && (!slices.Contains(adapter.calls, "verify-rollback") || r.CheckedAt.Equal(proofs[ids[0]].FinishedAt)) {
				t.Fatal("applied peer inherited the rejected candidate timestamp")
			}
			snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, node := range snapshot.Nodes {
				if node.ID != wantID {
					continue
				}
				for _, record := range node.Health.History {
					if record.ProbeID == proof.ProbeID && record.ServiceID == "my-independent-site" && record.NetworkProfile == proof.NetworkProfile && record.RoutePathID == "sing-box:"+wantID && record.Verdict == "PASS" && record.TestLevel == "service" && record.CheckedAt.Equal(r.CheckedAt) {
						found = true
					}
				}
			}
			if !found {
				t.Fatal("published timestamp has no matching durable exact PASS")
			}
			data, err := os.ReadFile(a.autonomy.path)
			if err != nil {
				t.Fatal(err)
			}
			document, err := decodeAutonomy(data)
			if err != nil || document.Runtime["my-independent-site"].State != "applied" || !document.Runtime["my-independent-site"].CheckedAt.Equal(proof.FinishedAt) {
				t.Fatal("first apply timestamp was not persisted", err)
			}
			d10Reopen(t, a)
			if reloaded := autonomyTestState(a); reloaded.State != "pending" || !reloaded.CheckedAt.Equal(proof.FinishedAt) {
				t.Fatal("reload lost history or reused it as a live PASS", reloaded)
			}
		})
	}
}

func TestAutonomyFirstUsableFailureOrCancelDoesNotPublishPassTimestamp(t *testing.T) {
	for _, scenario := range []string{"check-failed", "check-canceled", "foreign-node", "foreign-route", "apply-health-failed", "apply-canceled"} {
		t.Run(scenario, func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			before := a.Store.Get()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				proof := d10Result(req, "sing-box", scenario != "check-failed")
				switch scenario {
				case "check-canceled":
					cancel() // Even a returned PASS is not a completed guarded check.
				case "foreign-node":
					proof.NodeID = ids[1]
				case "foreign-route":
					proof.RoutePathID = "xray:" + req.NodeID
				}
				return proof, nil
			})
			adapter.after = func(phase string) error {
				if phase == "health" {
					if scenario == "apply-health-failed" {
						return errors.New("modeled active route health failure")
					}
					if scenario == "apply-canceled" {
						cancel()
						return context.Canceled
					}
				}
				return nil
			}
			a.autonomyRound(ctx, time.Now())
			r := autonomyTestState(a)
			if r.State == "applied" || !r.CheckedAt.IsZero() || !reflect.DeepEqual(before, a.Store.Get()) || slices.Contains(adapter.calls, "commit") {
				t.Fatal("failed/canceled first apply published successful observation", scenario, r.State, r.CheckedAt, adapter.calls)
			}
			if scenario == "apply-health-failed" || scenario == "apply-canceled" {
				if !slices.Contains(adapter.calls, "rollback") {
					t.Fatal("modeled post-activation failure did not exercise rollback")
				}
				// Isolated PASS alone cannot supply the applied timestamp.
				snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				pass := false
				for _, node := range snapshot.Nodes {
					for _, record := range node.Health.History {
						pass = pass || record.ServiceID == "my-independent-site" && record.Verdict == "PASS"
					}
				}
				if !pass {
					t.Fatal("fixture did not reach a durable isolated PASS before failed Apply")
				}
			}
		})
	}
}
