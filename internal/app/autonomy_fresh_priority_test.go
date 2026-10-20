package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestAutonomyFreshProofPriorityStillChecksBeforeApply(t *testing.T) {
	for _, freshPass := range []bool{true, false} {
		t.Run(map[bool]string{true: "pass", false: "reject"}[freshPass], func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			now := time.Now()
			_, err := a.Nodes.RecordCheck(context.Background(), ids[1], nodestore.CheckRecord{ProbeID: "manual-fresh", ServiceID: "my-independent-site", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + ids[1], TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour)}, now)
			if err != nil {
				t.Fatal(err)
			}
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, q.NodeID)
				return d10Result(q, "sing-box", freshPass), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			if len(checked) == 0 || checked[0] != ids[1] {
				t.Fatalf("fresh proof did not prioritize fresh check: %v", checked)
			}
			if freshPass {
				if autonomyTestState(a).State != "applied" || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] || !slices.Contains(adapter.calls, "commit") {
					t.Fatal("fresh check was not applied", autonomyTestState(a), adapter.calls)
				}
			} else if slices.Contains(adapter.calls, "commit") {
				t.Fatal("historical PASS authorized Apply after fresh rejection")
			}
		})
	}
}
func TestAutonomyFreshProofPriorityPreservesPrefixAndRefusesForeignProof(t *testing.T) {
	for _, mode := range []string{"fresh", "stale", "service", "network", "engine", "disabled", "ineligible", "halted", "consumed", "cooldown", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			a, ids, _ := autonomousIntegrationFixture(t)
			now := time.Now()
			p := a.autonomyPolicy()
			s := a.autonomy.doc.Services["my-independent-site"]
			check := nodestore.CheckRecord{ProbeID: "priority-proof", ServiceID: s.ID, NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + ids[1], TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
			switch mode {
			case "stale":
				check.ExpiresAt = now.Add(-time.Second)
			case "service":
				check.ServiceID = "telegram"
			case "network":
				check.NetworkProfile = "wan-foreign"
			case "engine":
				check.RoutePathID = "xray:" + ids[1]
			}
			if _, err := a.Nodes.RecordCheck(context.Background(), ids[1], check, check.CheckedAt.Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if mode == "disabled" {
				if _, err := a.Nodes.SetDisabled(context.Background(), ids[1], true, now); err != nil {
					t.Fatal(err)
				}
			}
			prefix := "consumed-prefix"
			r := autonomy.Runtime{Search: &autonomy.Traversal{Ordered: []string{prefix, ids[0], ids[1]}, Cursor: 1, Halted: mode == "halted"}}
			eligible := slices.Clone(ids)
			if mode == "ineligible" {
				eligible = ids[:1]
			}
			if mode == "consumed" {
				r.Search.Ordered = []string{ids[1], ids[0]}
			}
			if mode == "cooldown" {
				r.CandidateFailures = []autonomy.CandidateFailure{{NodeID: ids[1]}}
			}
			if mode == "revoked" {
				p.SourceIDs = []string{"different-source"}
			}
			before := slices.Clone(r.Search.Ordered)
			a.prioritizeAutonomyFreshProofs(context.Background(), p, s, &r, "sing-box", "wan-0123456789ab", eligible, now)
			if r.Search.Cursor != 1 || r.Search.Ordered[0] != before[0] {
				t.Fatal("consumed prefix changed", r.Search)
			}
			if mode == "fresh" {
				if r.Search.Ordered[1] != ids[1] {
					t.Fatal("fresh proof not promoted")
				}
			} else if !reflect.DeepEqual(before, r.Search.Ordered) {
				t.Fatal("invalid proof changed priority", mode, r.Search)
			}
		})
	}
}
func TestAutonomyNewTraversalKeepsCallerOrder(t *testing.T) {
	r := autonomy.Runtime{}
	ids := []string{"z", "a"}
	prepareAutonomyTraversal(&r, "v", ids, time.Now())
	if !reflect.DeepEqual(r.Search.Ordered, ids) {
		t.Fatal(r.Search)
	}
}

func TestAutonomyFreshProofPriorityRuntimeContractAndOrigin(t *testing.T) {
	for _, mode := range []string{"current", "obsolete", "expired-origin"} {
		t.Run(mode, func(t *testing.T) {
			a, ids, _ := autonomousIntegrationFixture(t)
			now := time.Now()
			ctx := context.Background()
			snapshot, err := a.Nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174009@reality.example:443?security=reality&pbk=PUBLIC_KEY&sni=front.example", now, time.Minute, false)
			if err != nil {
				t.Fatal(err)
			}
			id := ""
			for _, n := range snapshot.Nodes {
				if !slices.Contains(ids, n.ID) {
					id = n.ID
				}
			}
			contract := "sing-box-reality-utls-chrome-v1"
			if mode == "obsolete" {
				contract = ""
			}
			_, err = a.Nodes.RecordCheck(ctx, id, nodestore.CheckRecord{ProbeID: "runtime-contract-priority", ServiceID: "my-independent-site", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now, ExpiresAt: now.Add(time.Hour), RuntimeContract: contract}, now)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "expired-origin" {
				now = now.Add(2 * time.Minute)
			}
			p := a.autonomyPolicy()
			service := a.autonomy.doc.Services["my-independent-site"]
			r := autonomy.Runtime{Search: &autonomy.Traversal{Ordered: []string{ids[0], id}}}
			a.prioritizeAutonomyFreshProofs(ctx, p, service, &r, "sing-box", "wan-0123456789ab", []string{ids[0], id}, now)
			if (r.Search.Ordered[0] == id) != (mode == "current") {
				t.Fatal("runtime or origin contract not respected", mode, r.Search)
			}
		})
	}
}
