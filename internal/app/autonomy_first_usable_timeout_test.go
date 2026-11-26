package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func autonomyExactServiceTimeout(req dataplane.NodeCheckRequest) dataplane.NodeCheckResult {
	now := time.Now().UTC()
	return dataplane.NodeCheckResult{SchemaVersion: 1, ProbeID: fmt.Sprintf("probe-timeout-%d", now.UnixNano()),
		NodeID: req.NodeID, ServiceID: req.Service.ID, NetworkProfile: req.NetworkProfile, RoutePathID: "sing-box:" + req.NodeID,
		StartedAt: now, FinishedAt: now, ExpiresAt: now.Add(time.Minute), Verdict: evidence.VerdictError,
		TestLevel: "service", Stage: "service", ErrorCode: "request-failed", ServiceErrorCategory: "service_timeout",
		DirectControl: "measured", EgressIP: "93.184.216.34", CleanupStatus: dataplane.NodeCleanupVerified}
}

func TestAutonomyServiceTimeoutFairnessSurvivesRestartAndReadinessPriority(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	before := a.Store.Get()
	now := time.Now()
	a.nodeReadiness.network = "wan-0123456789ab"
	a.nodeReadiness.entries = map[string]nodeReadinessEntry{ids[0]: {Engine: "sing-box", Ready: true, PassAt: now}}
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		if req.NodeID == ids[0] {
			return autonomyExactServiceTimeout(req), nil
		}
		// The first peer must be deferred durably before another peer is checked.
		raw, err := os.ReadFile(a.autonomy.path)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := decodeAutonomy(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := doc.Runtime["my-independent-site"]
		if r.Search.Cursor != 0 || !reflect.DeepEqual(r.Search.Ordered, []string{ids[1], ids[0]}) || len(adapter.calls) != 0 {
			t.Fatal("peer preceded durable deferral", r)
		}
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "searching" || r.Search == nil || r.Search.Cursor != 0 || r.Search.Exhausted || r.Search.Halted ||
		!reflect.DeepEqual(r.Search.Ordered, []string{ids[1], ids[0]}) ||
		len(checked) != 1 || len(adapter.calls) != 0 || len(r.Switches) != 0 || len(r.CandidateFailures) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || !r.CheckedAt.IsZero() {
		t.Fatal("timeout became failure, PASS or Apply", r, checked)
	}
	if !r.NextCheck.After(time.Now()) {
		t.Fatal("normal scheduling interval lost")
	}
	a.autonomyRound(context.Background(), time.Now())
	if len(checked) != 1 {
		t.Fatal("timeout immediately retried")
	}
	d10Reopen(t, a)
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	r = autonomyTestState(a)
	if r.State != "applied" || !reflect.DeepEqual(checked, ids) || r.Search.Cursor != 1 || len(r.CandidateFailures) != 0 || len(r.Switches) != 1 || !slices.Contains(adapter.calls, "commit") || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] {
		t.Fatal("healthy peer was starved by readiness priority", r, checked, adapter.calls)
	}
	snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range snapshot.Nodes {
		if node.ID != ids[0] {
			continue
		}
		count := 0
		for _, record := range node.Health.History {
			if record.ServiceID != "my-independent-site" {
				continue
			}
			count++
			if record.Verdict != "ERROR" || record.ErrorCode != "request-failed" || record.HTTPStatus != 0 {
				t.Fatal("timeout observation relabeled", record)
			}
		}
		if count != 1 {
			t.Fatal("timeout retried or its observation was lost", count)
		}
	}
}

func TestAutonomyServiceTimeoutRotationRefusesUncertainConditions(t *testing.T) {
	for _, mode := range []string{"legacy", "tls-transport", "cleanup-unknown", "cleanup-failed", "unmeasured", "no-egress", "http-response", "misroute", "foreign-node", "foreign-service", "foreign-route", "expired", "future", "old-check", "local-error", "resource", "cancel", "final-network", "single-pending"} {
		t.Run(mode, func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			if mode == "single-pending" {
				if _, err := a.Nodes.SetDisabled(context.Background(), ids[1], true, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			before := a.Store.Get()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks, probe := 0, ""
			if mode == "final-network" {
				a.FreshProfile = func(c context.Context) (string, error) {
					snap, err := a.Nodes.Snapshot(c, time.Now())
					if err != nil {
						return "", err
					}
					for _, node := range snap.Nodes {
						for _, record := range node.Health.History {
							if probe != "" && record.ProbeID == probe {
								return "wan-ffffffffffff", nil
							}
						}
					}
					return "wan-0123456789ab", nil
				}
			}
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks++
				r := autonomyExactServiceTimeout(req)
				probe = r.ProbeID
				switch mode {
				case "legacy":
					r.ServiceErrorCategory = ""
				case "tls-transport":
					r.ServiceErrorCategory = "service_transport"
				case "cleanup-unknown":
					r.CleanupStatus = dataplane.NodeCleanupNotObserved
				case "cleanup-failed":
					r.CleanupStatus, r.Stage, r.ErrorCode = dataplane.NodeCleanupFailed, "cleanup", "node-cleanup-failed"
				case "unmeasured":
					r.DirectControl = "not_run"
				case "no-egress":
					r.EgressIP = ""
				case "http-response":
					r.HTTPStatus = 500
				case "misroute":
					r.DirectLeak = true
				case "foreign-node":
					r.NodeID = ids[1]
				case "foreign-service":
					r.ServiceID = "telegram"
				case "foreign-route":
					r.RoutePathID = "xray:" + req.NodeID
				case "expired":
					r.FinishedAt, r.ExpiresAt = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
				case "future":
					r.FinishedAt = time.Now().Add(time.Minute)
				case "old-check":
					r.StartedAt = time.Now().Add(-time.Hour)
				case "local-error":
					return r, errors.New("local checker failure")
				case "resource":
					return r, dataplane.ErrNodeResourceDenied
				case "cancel":
					cancel()
				}
				return r, nil
			})
			a.autonomyRound(ctx, time.Now())
			r := autonomyTestState(a)
			if checks != 1 || r.Search == nil || r.Search.Cursor != 0 || r.Search.Ordered[0] != ids[0] || len(adapter.calls) != 0 || len(r.Switches) != 0 || len(r.CandidateFailures) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("uncertain condition rotated, consumed or applied", r, checks)
			}
			if mode == "single-pending" && (r.State != "unconfirmed" || !r.NextCheck.After(time.Now())) {
				t.Fatal("single pending candidate lost ordinary retry", r)
			}
		})
	}
}

func TestAutonomyServiceTimeoutAllPendingPeersGetBoundedRetryCycles(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return autonomyExactServiceTimeout(req), nil
	})
	for round := 0; round < 4; round++ {
		if round > 0 {
			d10Reopen(t, a)
			autonomyTestDue(a, false)
		}
		a.autonomyRound(context.Background(), time.Now())
		r := autonomyTestState(a)
		if len(checked) != round+1 || checked[round] != ids[round%len(ids)] || r.Search.Cursor != 0 || r.Search.Exhausted || r.Search.Halted || r.State != "searching" || len(r.Switches) != 0 || len(r.CandidateFailures) != 0 || len(adapter.calls) != 0 || !r.NextCheck.After(time.Now()) {
			t.Fatal("timeout cycle retried immediately, skipped a peer or consumed failure", round, checked, r)
		}
		a.autonomyRound(context.Background(), time.Now())
		if len(checked) != round+1 {
			t.Fatal("cycle reset bypassed the normal interval")
		}
	}
}

func TestAutonomyServiceTimeoutSchedulingPreservesPrefixAndPriority(t *testing.T) {
	_, ids, _ := autonomousIntegrationFixture(t)
	version := strings.Repeat("a", 64)
	third := "node-" + strings.Repeat("c", 64)
	r := autonomy.Runtime{Search: &autonomy.Traversal{Version: version, Ordered: []string{third, ids[0], ids[1]}, Cursor: 1}}
	previous := []string{ids[1], ids[0]}
	if count := orderAutonomyRecentUnconfirmed(r.Search, 1, previous, map[string]bool{ids[0]: true}); count != 0 || !reflect.DeepEqual(r.Search.Ordered, []string{third, ids[1], ids[0]}) {
		t.Fatal("source priority defeated deferral or changed consumed prefix", count, r.Search)
	}
	// Model the ranking owner promoting the same ready candidate again.
	r.Search.Ordered = []string{third, ids[0], ids[1]}
	if count := orderAutonomyRecentUnconfirmed(r.Search, 1, previous, map[string]bool{ids[0]: true, ids[1]: true}); count != 0 || !reflect.DeepEqual(r.Search.Ordered, []string{third, ids[1], ids[0]}) || r.Search.Cursor != 1 {
		t.Fatal("all-tried cycle lost the persisted rotation", r.Search)
	}
}
