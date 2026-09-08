package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func nodeAutofallbackFixture(t *testing.T, extras int) (*App, string, nodestore.NodeGroup, *nodeApplyAdapter, dataplane.Plan) {
	t.Helper()
	a, currentID, adapter, _, previous := nodeRecoveryFixture(t)
	profiles := []string{}
	for i := 0; i < extras; i++ {
		profiles = append(profiles, fmt.Sprintf("vless://123e4567-e89b-12d3-a456-426614174000@reserve%d.example:443?security=tls", i))
	}
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "reserve", Kind: "manual"}, strings.Join(profiles, "\n"), time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, node := range snapshot.Nodes {
		ids = append(ids, node.ID)
	}
	group, err := a.Nodes.CreateGroup(context.Background(), "Резерв", "fallback", ids, "", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + group.ID, Sources: previous.Routes[0].Sources})
	_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"})
	_ = a.Store.ApplyDraft()
	previous.Revision = a.Store.Get().AppliedRevision
	previous.Routes[0].Selected = "sing-box:" + group.ID
	if err := a.Dataplane.Record(previous); err != nil {
		t.Fatal(err)
	}
	// These desired changes must survive both successful and failed fallback.
	_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.99/32"}})
	_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "warp-wg"})
	return a, currentID, group, adapter, previous
}

func autofallbackResult(request dataplane.NodeCheckRequest, available bool) dataplane.NodeCheckResult {
	now := time.Now().UTC()
	verdict := evidence.VerdictError
	if available {
		verdict = evidence.VerdictPass
	}
	return dataplane.NodeCheckResult{ProbeID: fmt.Sprintf("probe-fallback-%d", now.UnixNano()), NodeID: request.NodeID, ServiceID: request.Service.ID,
		NetworkProfile: request.NetworkProfile, RoutePathID: "sing-box:" + request.NodeID, StartedAt: now.Add(-time.Second), FinishedAt: now,
		ExpiresAt: now.Add(30 * time.Minute), Stage: "service", TestLevel: "service", Verdict: verdict, Available: available, DirectControl: "measured", Message: "Проверка завершена."}
}

func fallbackEntry(t *testing.T, a *App) nodeAutofallbackService {
	t.Helper()
	statuses := a.nodeAutofallbackSnapshot()
	if len(statuses) != 1 {
		t.Fatalf("statuses: %+v", statuses)
	}
	return statuses[0]
}

func TestNodeAutofallbackTwoFailuresSwitchOnlyAppliedGroupAndPreserveDrafts(t *testing.T) {
	a, currentID, _, adapter, previous := nodeAutofallbackFixture(t, 1)
	before := a.Store.Get()
	var checked []string
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, request.NodeID)
		if release, err := a.Operations.Enter(ctx); !errors.Is(err, operationgate.ErrBusy) {
			if release != nil {
				release()
			}
			t.Fatal("worker has no exclusive admission")
		}
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/node-autofallback", nil))
		if w.Code != http.StatusOK {
			t.Fatal("status blocked during worker")
		}
		return autofallbackResult(request, request.NodeID != currentID), nil
	})
	now := time.Now()
	a.nodeAutofallbackRound(context.Background(), now)
	if status := fallbackEntry(t, a); status.Failures != 1 || status.State != "suspect" || status.Healthy || len(adapter.calls) != 0 || len(checked) != 1 {
		t.Fatalf("premature switch: %+v", status)
	}
	a.nodeAutofallbackRound(context.Background(), now.Add(time.Minute))
	status := fallbackEntry(t, a)
	if status.State != "switched" || !status.Healthy || status.NodeID == currentID || len(checked) != 3 {
		t.Fatalf("no verified switch: %+v checks=%v calls=%v", status, checked, adapter.calls)
	}
	current, _, _ := a.Dataplane.Committed()
	expected := append([]dataplane.Route(nil), previous.Routes...)
	expected[0].Resolved = "sing-box:" + status.NodeID
	if !reflect.DeepEqual(current.Routes, expected) || current.Revision != before.AppliedRevision || len(current.EngineDrafts) != 0 || !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("switch changed scope, revisions or desired drafts")
	}
	if strings.Join(adapter.calls, ",") != "snapshot,stage,validate,canary,activate,health,commit" {
		t.Fatalf("transaction bypassed: %v", adapter.calls)
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("worker retained gate")
	} else {
		release()
	}
}

func TestNodeAutofallbackUnknownReserveAndUncertainCurrentNeverApply(t *testing.T) {
	for _, uncertainCurrent := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertainCurrent), func(t *testing.T) {
			a, currentID, _, adapter, previous := nodeAutofallbackFixture(t, 1)
			var reserveCalls int
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				result := autofallbackResult(request, false)
				if request.NodeID != currentID {
					reserveCalls++
					result.Verdict = evidence.VerdictInconclusive
				}
				if uncertainCurrent {
					result.Verdict = evidence.VerdictInconclusive
				}
				return result, nil
			})
			now := time.Now()
			a.nodeAutofallbackRound(context.Background(), now)
			a.nodeAutofallbackRound(context.Background(), now.Add(time.Minute))
			status := fallbackEntry(t, a)
			if status.Healthy || len(adapter.calls) != 0 || uncertainCurrent && reserveCalls != 0 {
				t.Fatalf("unknown caused switch: %+v calls=%d", status, reserveCalls)
			}
			current, _, _ := a.Dataplane.Committed()
			if !sameNodeRecoveryPlan(previous, current) {
				t.Fatal("unknown reserve replaced plan")
			}
		})
	}
}

func TestNodeAutofallbackPlainNodesManualGroupsAndDraftGroupsRemainUntouched(t *testing.T) {
	for _, kind := range []string{"plain", "manual", "draft", "auto"} {
		t.Run(kind, func(t *testing.T) {
			a, currentID, group, adapter, previous := nodeAutofallbackFixture(t, 1)
			selected := "sing-box:" + currentID
			if kind == "manual" {
				group.Mode, group.PreferredNodeID = "manual", currentID
				if _, err := a.Nodes.UpdateGroup(context.Background(), group, time.Now()); err != nil {
					t.Fatal(err)
				}
				selected = "sing-box:" + group.ID
			} else if kind == "auto" {
				selected = "auto"
			}
			_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: selected, Sources: previous.Routes[0].Sources})
			_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"})
			_ = a.Store.ApplyDraft()
			previous.Revision, previous.Routes[0].Selected = a.Store.Get().AppliedRevision, selected
			_ = a.Dataplane.Record(previous)
			if kind == "draft" {
				_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + group.ID})
			}
			a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				t.Error("non-opted route checked")
				return dataplane.NodeCheckResult{}, nil
			})
			a.nodeAutofallbackRound(context.Background(), time.Now())
			if len(a.nodeAutofallbackSnapshot()) != 0 || len(adapter.calls) != 0 {
				t.Fatal("non-opted route enabled auto replacement")
			}
		})
	}
}

func TestNodeAutofallbackAuthorityChangesRevokeBeforeOrDuringApply(t *testing.T) {
	for _, phase := range []string{"config", "group", "network", "scope", "stage-scope", "stage-generation", "activate-scope"} {
		t.Run(phase, func(t *testing.T) {
			a, currentID, group, adapter, previous := nodeAutofallbackFixture(t, 1)
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				if request.NodeID != currentID {
					switch phase {
					case "config":
						_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"})
					case "group":
						group.Name = "changed"
						_, _ = a.Nodes.UpdateGroup(context.Background(), group, time.Now())
					case "network":
						a.FreshProfile = func(context.Context) (string, error) { return "wan-333333333333", nil }
					case "scope":
						a.Catalog.Services[0].Domains = []string{"new.example"}
					}
				}
				return autofallbackResult(request, request.NodeID != currentID), nil
			})
			adapter.after = func(name string) error {
				if phase == "stage-scope" && name == "stage" || phase == "activate-scope" && name == "activate" {
					a.Catalog.Services[0].Domains = []string{"new.example"}
				}
				if phase == "stage-generation" && name == "stage" {
					_, _ = a.Nodes.SetAlias(context.Background(), currentID, "changed", time.Now())
				}
				return nil
			}
			now := time.Now()
			a.nodeAutofallbackRound(context.Background(), now)
			a.nodeAutofallbackRound(context.Background(), now.Add(time.Minute))
			current, _, _ := a.Dataplane.Committed()
			if !sameNodeRecoveryPlan(previous, current) || fallbackEntry(t, a).Healthy {
				t.Fatal("changed authority promoted plan")
			}
			live := phase == "activate-scope"
			if live != slices.Contains(adapter.calls, "rollback") || !live && slices.Contains(adapter.calls, "activate") {
				t.Fatalf("wrong rollback boundary: %v", adapter.calls)
			}
		})
	}
}

func TestNodeAutofallbackRollbackFailureLatchesAndNeverClaimsHealthy(t *testing.T) {
	for _, rollbackFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(rollbackFailure), func(t *testing.T) {
			a, currentID, _, adapter, previous := nodeAutofallbackFixture(t, 1)
			var checks int
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks++
				return autofallbackResult(request, request.NodeID != currentID), nil
			})
			adapter.after = func(name string) error {
				if name == "health" || rollbackFailure && name == "rollback" {
					return errors.New("private-error-not-for-ui")
				}
				return nil
			}
			now := time.Now()
			a.nodeAutofallbackRound(context.Background(), now)
			a.nodeAutofallbackRound(context.Background(), now.Add(time.Minute))
			status := fallbackEntry(t, a)
			if status.Healthy || !slices.Contains(adapter.calls, "rollback") || strings.Contains(status.Message, "private-error") {
				t.Fatalf("bad rollback status: %+v", status)
			}
			current, _, _ := a.Dataplane.Committed()
			if !sameNodeRecoveryPlan(previous, current) {
				t.Fatal("failed replacement changed commit")
			}
			if rollbackFailure {
				if status.State != "requires-review" {
					t.Fatal("rollback failure not latched")
				}
				count := checks
				_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"})
				a.nodeAutofallbackRound(context.Background(), now.Add(10*time.Minute))
				if checks != count {
					t.Fatal("rollback failure retried automatically")
				}
			}
		})
	}
}

func TestNodeAutofallbackCandidateBudgetRotatesAndCooldownPreventsChurn(t *testing.T) {
	a, currentID, group, _, _ := nodeAutofallbackFixture(t, 5)
	candidates := []string{}
	for _, id := range group.NodeIDs {
		if id != currentID {
			candidates = append(candidates, id)
		}
	}
	working := candidates[4]
	var currentCalls, reserveCalls int
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if request.NodeID == currentID {
			currentCalls++
		} else {
			reserveCalls++
		}
		return autofallbackResult(request, request.NodeID == working), nil
	})
	now := time.Now()
	a.nodeAutofallbackRound(context.Background(), now)
	a.nodeAutofallbackRound(context.Background(), now.Add(time.Minute))
	if reserveCalls != 3 || fallbackEntry(t, a).State != "no-working-reserve" {
		t.Fatal("per-round alternate budget exceeded")
	}
	a.nodeAutofallbackRound(context.Background(), now.Add(4*time.Minute))
	if reserveCalls != 5 || fallbackEntry(t, a).State != "switched" {
		t.Fatal("alternate cursor never reached later nodes")
	}
	working = currentID
	a.nodeAutofallbackRound(context.Background(), now.Add(5*time.Minute))
	a.nodeAutofallbackRound(context.Background(), now.Add(6*time.Minute))
	status := fallbackEntry(t, a)
	if status.State != "cooldown" || status.Healthy || currentCalls != 3 {
		t.Fatalf("cooldown caused churn: %+v checks %d", status, currentCalls)
	}
}

func TestNodeAutofallbackOtherAppliedServiceMustKeepExactProof(t *testing.T) {
	for _, retainedHealthy := range []bool{false, true} {
		t.Run(fmt.Sprint(retainedHealthy), func(t *testing.T) {
			a, currentID, group, adapter, previous := nodeAutofallbackFixture(t, 1)
			_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + group.ID, Sources: previous.Routes[0].Sources})
			_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "sing-box:" + currentID, Sources: []string{"192.168.1.42/32"}})
			_ = a.Store.ApplyDraft()
			previous.Revision = a.Store.Get().AppliedRevision
			other := dataplane.Route{ServiceID: "youtube", ServiceName: "YouTube", Selected: "sing-box:" + currentID, Resolved: "sing-box:" + currentID, Domains: []string{"youtube.com"}, ProbeURL: "https://youtube.com/", Sources: []string{"192.168.1.42/32"}}
			previous.Routes = append(previous.Routes, other)
			_ = a.Dataplane.Record(previous)
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				ok := request.NodeID != currentID || request.Service.ID == "youtube" && retainedHealthy
				return autofallbackResult(request, ok), nil
			})
			now := time.Now()
			a.nodeAutofallbackRound(context.Background(), now)
			a.nodeAutofallbackRound(context.Background(), now.Add(time.Minute))
			current, _, _ := a.Dataplane.Committed()
			if retainedHealthy {
				if fallbackEntry(t, a).State != "switched" || len(current.Routes) != 2 || !reflect.DeepEqual(current.Routes[1], other) {
					t.Fatalf("retained scope changed: %+v", current.Routes)
				}
			} else if len(adapter.calls) != 0 || !sameNodeRecoveryPlan(previous, current) {
				t.Fatal("partial plan applied while retained service failed")
			}
		})
	}
}

func TestNodeAutofallbackMixedPlanRequiresReviewWithoutChecks(t *testing.T) {
	a, _, _, adapter, previous := nodeAutofallbackFixture(t, 1)
	previous.Adapters = append(previous.Adapters, "nfqws2")
	_ = a.Dataplane.Record(previous)
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Error("mixed plan probed")
		return dataplane.NodeCheckResult{}, nil
	})
	a.nodeAutofallbackRound(context.Background(), time.Now())
	status := fallbackEntry(t, a)
	if status.State != "requires-review" || status.Healthy || len(adapter.calls) != 0 {
		t.Fatalf("mixed plan allowed: %+v", status)
	}
}

func TestNodeAutofallbackShutdownJoinsExactCleanup(t *testing.T) {
	a, _, _, adapter, previous := nodeAutofallbackFixture(t, 1)
	entered, cleaning, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(cleaning)
		<-finish
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.StartNodeAutofallback(ctx)
	select {
	case <-entered:
	case <-time.After(4 * time.Second):
		t.Fatal("worker did not start")
	}
	cancel()
	<-cleaning
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := a.WaitNodeAutofallback(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shutdown skipped cleanup")
	}
	stop()
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("cleanup gate released early")
	}
	close(finish)
	wait, stopWait := context.WithTimeout(context.Background(), time.Second)
	defer stopWait()
	if err := a.WaitNodeAutofallback(wait); err != nil {
		t.Fatal(err)
	}
	current, _, _ := a.Dataplane.Committed()
	if !sameNodeRecoveryPlan(previous, current) || len(adapter.calls) != 0 || calls.Load() != 1 {
		t.Fatal("shutdown progressed replacement")
	}
	raw, _ := json.Marshal(a.nodeAutofallbackSnapshot())
	if strings.Contains(string(raw), "reserve0.example") || strings.Contains(string(raw), "123e4567") {
		t.Fatal("status leaked private node data")
	}
}

func TestNodeAutofallbackSameEpochRequiresLiveRuntimeAndRepairsTransactionally(t *testing.T) {
	for _, state := range []string{"healthy", "dead", "repair-fails"} {
		t.Run(state, func(t *testing.T) {
			a, id, _, adapter, previous := nodeAutofallbackFixture(t, 1)
			previous.NetworkProfileID = recoveryProfile
			if err := a.Dataplane.Record(previous); err != nil {
				t.Fatal(err)
			}
			before := a.Store.Get()
			live := state == "healthy"
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				if request.NodeID != id {
					t.Fatal("runtime loss must not switch a working node")
				}
				return autofallbackResult(request, true), nil
			})
			adapter.after = func(name string) error {
				if name == "activate" && state == "dead" {
					live = true
				}
				if name == "health" && !live {
					return errors.New("managed process stopped")
				}
				return nil
			}
			a.nodeAutofallbackRound(context.Background(), time.Now())
			status := fallbackEntry(t, a)
			current, _, _ := a.Dataplane.Committed()
			if !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(current.Routes, previous.Routes) || current.Revision != previous.Revision {
				t.Fatal("runtime repair changed applied authority or drafts")
			}
			switch state {
			case "healthy":
				if status.State != "healthy" || !status.Healthy || !reflect.DeepEqual(adapter.calls, []string{"health"}) || !sameNodeRecoveryPlan(current, previous) {
					t.Fatalf("live runtime was not checked read-only: %+v %v", status, adapter.calls)
				}
			case "dead":
				if status.State != "revalidated" || !status.Healthy || status.Trigger != "runtime-unhealthy" || strings.Join(adapter.calls, ",") != "health,snapshot,stage,validate,canary,activate,health,commit" {
					t.Fatalf("same epoch dead process did not repair through guarded apply: %+v %v", status, adapter.calls)
				}
			case "repair-fails":
				if status.Healthy || status.State != "rolled-back" || !slices.Contains(adapter.calls, "rollback") || !sameNodeRecoveryPlan(current, previous) {
					t.Fatalf("failed runtime repair claimed healthy: %+v %v", status, adapter.calls)
				}
			}
		})
	}
}

func expireFallbackOrigin(t *testing.T, a *App, source, hostname string) {
	t.Helper()
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@" + hostname + ":443?security=tls"
	if _, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: source, Kind: "manual"}, raw, time.Now(), time.Nanosecond, false); err != nil {
		t.Fatal(err)
	}
}

func TestNodeAutofallbackExpiredOriginReplacesOnlyWithFreshSameGroupReserve(t *testing.T) {
	for _, reserve := range []string{"fresh", "expired", "unknown", "disabled-current", "retained-expired"} {
		t.Run(reserve, func(t *testing.T) {
			a, id, group, adapter, previous := nodeAutofallbackFixture(t, 1)
			if reserve == "retained-expired" {
				_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + group.ID, Sources: previous.Routes[0].Sources})
				_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "sing-box:" + id, Sources: []string{"192.168.1.42/32"}})
				_ = a.Store.ApplyDraft()
				previous.Revision = a.Store.Get().AppliedRevision
				previous.Routes = append(previous.Routes, dataplane.Route{ServiceID: "youtube", ServiceName: "YouTube", Selected: "sing-box:" + id, Resolved: "sing-box:" + id, Domains: []string{"youtube.com"}, ProbeURL: "https://youtube.com/", Sources: []string{"192.168.1.42/32"}})
				_ = a.Dataplane.Record(previous)
			}
			expireFallbackOrigin(t, a, "manual", "private.example")
			if reserve == "expired" {
				expireFallbackOrigin(t, a, "reserve", "reserve0.example")
			} else if reserve == "disabled-current" {
				_, _ = a.Nodes.SetDisabled(context.Background(), id, true, time.Now())
			}
			before := a.Store.Get()
			nodesBefore, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			var calls int
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls++
				if request.NodeID == id || reserve == "expired" || reserve == "disabled-current" || reserve == "retained-expired" {
					t.Fatal("expired or unauthorized node was checked")
				}
				result := autofallbackResult(request, reserve == "fresh")
				if reserve == "unknown" {
					result.Verdict = evidence.VerdictInconclusive
				}
				return result, nil
			})
			a.nodeAutofallbackRound(context.Background(), time.Now())
			status := fallbackEntry(t, a)
			current, _, _ := a.Dataplane.Committed()
			nodesAfter, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("origin replacement modified user drafts")
			}
			for _, old := range nodesBefore.Nodes {
				for _, next := range nodesAfter.Nodes {
					if old.ID == next.ID && !reflect.DeepEqual(old.Origins, next.Origins) {
						t.Fatal("check renewed source freshness")
					}
				}
			}
			if reserve == "fresh" {
				if status.State != "switched" || !status.Healthy || status.Trigger != "origin-expired" || calls != 1 || status.NodeID == id || !slices.Contains(group.NodeIDs, status.NodeID) {
					t.Fatalf("expired current could not use proved same-group reserve: %+v calls=%d", status, calls)
				}
				expected := append([]dataplane.Route(nil), previous.Routes...)
				expected[0].Resolved = "sing-box:" + status.NodeID
				if !reflect.DeepEqual(current.Routes, expected) || current.Revision != previous.Revision {
					t.Fatal("expiry expanded service/client scope")
				}
			} else if status.Healthy || len(adapter.calls) != 0 || !sameNodeRecoveryPlan(current, previous) {
				t.Fatalf("unproved expiry replacement applied: %+v", status)
			}
		})
	}
}

func TestNodeAutofallbackCancelEndpointRetainsGateUntilCleanupAndDefersRetry(t *testing.T) {
	a, _, _, adapter, previous := nodeAutofallbackFixture(t, 1)
	entered, cleaning, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(cleaning)
		<-finish
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	go func() {
		defer close(done)
		a.nodeAutofallbackRound(context.Background(), time.Now())
	}()
	<-entered
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/node-autofallback", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("cancel blocked during exclusive work: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		Active      bool      `json:"active"`
		PausedUntil time.Time `json:"paused_until"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || !response.Active || response.PausedUntil.Before(time.Now().Add(59*time.Second)) {
		t.Fatalf("cancel envelope: %+v %v", response, err)
	}
	<-cleaning
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("cancellation released gate before exact cleanup joined")
	}
	close(finish)
	<-done
	a.nodeAutofallbackRound(context.Background(), time.Now().Add(30*time.Second))
	current, _, _ := a.Dataplane.Committed()
	status := fallbackEntry(t, a)
	if calls.Load() != 1 || len(adapter.calls) != 0 || status.Healthy || status.State != "canceled" || status.NextCheckAt.Before(response.PausedUntil) || !sameNodeRecoveryPlan(current, previous) {
		t.Fatalf("canceled work applied or retried early: %+v", status)
	}
	w = httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/node-autofallback", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Active {
		t.Fatal("completed cancellation still active")
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("canceled worker did not release admission")
	} else {
		release()
	}
}
