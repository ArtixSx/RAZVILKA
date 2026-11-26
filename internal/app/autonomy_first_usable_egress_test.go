package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

// Model the two actual ExactNodeChecker terminal branches, without a service
// response or PASS evidence. Host checks/OS adapters remain test fixtures.
func autonomyTerminalNodeFailure(req dataplane.NodeCheckRequest, kind string) dataplane.NodeCheckResult {
	now := time.Now().UTC()
	r := dataplane.NodeCheckResult{SchemaVersion: 1, ProbeID: fmt.Sprintf("probe-terminal-%d", now.UnixNano()),
		NodeID: req.NodeID, ServiceID: req.Service.ID, NetworkProfile: req.NetworkProfile, RoutePathID: "sing-box:" + req.NodeID,
		StartedAt: now.Add(-time.Second), FinishedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		Available: false, Verdict: evidence.VerdictError, Stage: "egress", TestLevel: "protocol", ErrorCode: "node-egress-failed", DirectControl: "measured"}
	if kind == "transport" {
		r.Stage, r.TestLevel, r.ErrorCode, r.DirectControl = "transport", "transport", "node-transport-failed", "not_run"
	}
	return r
}

func TestAutonomyFirstUsableTerminalNodeFailureConsumesBeforeFreshPeer(t *testing.T) {
	for _, test := range []struct {
		kind   string
		budget int
	}{{"egress", 1}, {"egress", 2}, {"transport", 1}, {"transport", 2}} {
		t.Run(fmt.Sprintf("%s_budget_%d", test.kind, test.budget), func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			a.autonomy.mu.Lock()
			a.autonomy.doc.Policy.CandidatesPerRound = test.budget
			err := a.persistAutonomyLocked(context.Background())
			a.autonomy.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			before := a.Store.Get()
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, req.NodeID)
				if req.NodeID == ids[0] {
					return autonomyTerminalNodeFailure(req, test.kind), nil
				}
				data, err := os.ReadFile(a.autonomy.path)
				if err != nil {
					t.Fatal(err)
				}
				d, err := decodeAutonomy(data)
				if err != nil {
					t.Fatal(err)
				}
				r := d.Runtime["my-independent-site"]
				if req.NodeID != ids[1] || r.Search == nil || r.Search.Cursor != 1 || r.Search.Halted || len(r.Switches) != 0 || len(r.CandidateFailures) != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(a.Store.Get(), before) {
					t.Fatal("fresh C check preceded durable B consumption or followed a B Apply/penalty")
				}
				return d10Result(req, "sing-box", true), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			if test.budget == 1 {
				r := autonomyTestState(a)
				if r.Search == nil || r.Search.Cursor != 1 || r.Search.Halted || r.Search.Exhausted || !reflect.DeepEqual(checked, ids[:1]) || len(adapter.calls) != 0 || len(r.Switches) != 0 || len(r.CandidateFailures) != 0 || !reflect.DeepEqual(a.Store.Get(), before) {
					t.Fatal("failed B did not leave durable bounded progress without an Apply")
				}
				d10Reopen(t, a)
				autonomyTestDue(a, false)
				a.autonomyRound(context.Background(), time.Now())
			}
			r := autonomyTestState(a)
			if r.State != "applied" || r.Search == nil || r.Search.Cursor != 2 || r.Search.Halted || !reflect.DeepEqual(checked, ids) || len(r.Switches) != 1 || len(r.CandidateFailures) != 0 || !slices.Contains(adapter.calls, "commit") || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] {
				t.Fatal("fresh C was not applied once after measured B failure", r.State, checked, adapter.calls)
			}
			snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for _, node := range snapshot.Nodes {
				if node.ID == ids[0] {
					level, code := "protocol", "node-egress-failed"
					if test.kind == "transport" {
						level, code = "transport", "node-transport-failed"
					}
					checks := 0
					for _, record := range node.Health.History {
						if record.ServiceID != "my-independent-site" {
							continue
						}
						checks++
						if record.Verdict != "ERROR" || record.TestLevel != level || record.Stage != test.kind || record.ErrorCode != code || record.HTTPStatus != 0 {
							t.Fatal("B was relabeled as service evidence")
						}
					}
					if checks != 1 {
						t.Fatal("B was rechecked after restart")
					}
				}
			}
		})
	}
}

func TestAutonomyFirstUsableUncertainProxyFailureStopsBeforePeer(t *testing.T) {
	for _, scenario := range []string{"global-control", "unmeasured-control", "generic-error", "local-config", "dns", "transport-control", "transport-level", "transport-error", "http-response", "egress-present", "direct-leak", "busy", "runtime", "local-error", "cleanup", "cleanup-cancel", "network", "review", "cancel", "deadline", "unsupported-local", "expired", "future", "foreign-node", "foreign-route", "foreign-service", "foreign-network", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			before := a.Store.Get()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, req.NodeID)
				if req.NodeID != ids[0] {
					t.Fatal("C checked after uncertain/local B failure")
				}
				r := autonomyTerminalNodeFailure(req, "egress")
				switch scenario {
				case "global-control":
					r.DirectControl, r.TestLevel, r.Verdict, r.ErrorCode = "unavailable", "egress", evidence.VerdictInconclusive, "node-egress-control-unavailable"
				case "unmeasured-control":
					r.DirectControl = "not_run"
				case "generic-error":
					r.ErrorCode = ""
				case "local-config":
					r.Stage, r.ErrorCode = "configuration", "node-config-invalid"
				case "dns":
					r.Stage, r.TestLevel, r.ErrorCode = "dns", "dns", "node-dns-failed"
				case "transport-control", "transport-level", "transport-error":
					r = autonomyTerminalNodeFailure(req, "transport")
					if scenario == "transport-control" {
						r.DirectControl = "measured"
					} else if scenario == "transport-level" {
						r.TestLevel = "protocol"
					} else {
						r.ErrorCode = "node-protocol-start-failed"
					}
				case "http-response":
					r.HTTPStatus = 200
				case "egress-present":
					r.EgressIP = "93.184.216.34"
				case "direct-leak":
					r.DirectLeak, r.TestLevel, r.Verdict, r.ErrorCode = true, "egress", evidence.VerdictMisrouted, "node-direct-leak"
				case "busy":
					return r, dataplane.ErrExactNodeBusy
				case "runtime":
					return r, dataplane.ErrExactNodeRuntime
				case "local-error":
					return r, errors.New("local checker failure")
				case "cleanup", "cleanup-cancel":
					r.Stage, r.ErrorCode = "cleanup", "node-cleanup-failed"
					if scenario == "cleanup-cancel" {
						cancel()
					}
					return r, errors.Join(dataplane.ErrExactNodeUnsupported, context.Canceled)
				case "network":
					return r, dataplane.ErrExactNodeNetworkChanged
				case "review":
					return r, dataplane.ErrReviewChanged
				case "cancel":
					cancel()
					return r, nil
				case "deadline":
					return r, context.DeadlineExceeded
				case "unsupported-local":
					return r, errors.Join(dataplane.ErrExactNodeUnsupported, dataplane.ErrExactNodeRuntime)
				case "expired":
					r.FinishedAt, r.ExpiresAt = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
				case "future":
					r.FinishedAt = time.Now().Add(time.Minute)
				case "foreign-node":
					r.NodeID = ids[1]
				case "foreign-route":
					r.RoutePathID = "xray:" + req.NodeID
				case "foreign-service":
					r.ServiceID = "telegram"
				case "foreign-network":
					r.NetworkProfile = "wan-ffffffffffff"
				case "empty":
					return dataplane.NodeCheckResult{}, nil
				}
				return r, nil
			})
			a.autonomyRound(ctx, time.Now())
			r := autonomyTestState(a)
			if !reflect.DeepEqual(checked, ids[:1]) || len(adapter.calls) != 0 || r.Search == nil || r.Search.Cursor != 0 || r.Search.Halted || len(r.Switches) != 0 || len(r.CandidateFailures) != 0 || r.State == "applied" || !reflect.DeepEqual(a.Store.Get(), before) {
				t.Fatal("uncertainty consumed B, penalized it or applied C", r.State, checked, adapter.calls)
			}
		})
	}
}
