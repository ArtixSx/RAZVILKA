package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/sources"
)

const recoveryProfile = "wan-222222222222"

type recoveryChecker struct {
	requests []dataplane.NodeCheckRequest
	hook     func(context.Context, dataplane.NodeCheckRequest)
	fail     bool
	ttl      time.Duration
}

func (f *recoveryChecker) Recover(context.Context) error { return nil }
func (f *recoveryChecker) Check(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	// Retain only public tuple data, never the ephemeral outbound copy.
	copy := request
	copy.Outbound = nil
	f.requests = append(f.requests, copy)
	if f.hook != nil {
		f.hook(ctx, request)
	}
	if ctx.Err() != nil {
		return dataplane.NodeCheckResult{}, ctx.Err()
	}
	now := time.Now()
	ttl := f.ttl
	if ttl == 0 {
		ttl = time.Hour
	}
	result := dataplane.NodeCheckResult{ProbeID: fmt.Sprintf("probe-recovery-%d", len(f.requests)), NodeID: request.NodeID, ServiceID: request.Service.ID,
		NetworkProfile: request.NetworkProfile, RoutePathID: "sing-box:" + request.NodeID, TestLevel: "service", Verdict: evidence.VerdictPass,
		Stage: "service", Available: true, StartedAt: now.Add(-time.Second), FinishedAt: now, ExpiresAt: now.Add(ttl), HTTPStatus: 200}
	if f.fail {
		result.Available = false
		result.Verdict = evidence.VerdictError
	}
	return result, nil
}

func nodeRecoveryFixture(t *testing.T) (*App, string, *nodeApplyAdapter, *recoveryChecker, dataplane.Plan) {
	t.Helper()
	a, id, adapter := nodeApplyFixture(t)
	review := reviewedNode(t, a, id)
	w := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", context.Background())
	if w.Code != 200 {
		t.Fatalf("initial apply: %d %s", w.Code, w.Body.String())
	}
	plan, exists, err := a.Dataplane.Committed()
	if err != nil || !exists {
		t.Fatal("no committed fixture")
	}
	adapter.calls = nil
	a.FreshProfile = func(context.Context) (string, error) { return recoveryProfile, nil }
	a.Dataplane.FreshProfile = a.FreshProfile
	checker := &recoveryChecker{}
	a.NodeChecker = checker
	return a, id, adapter, checker, plan
}

func TestAppliedNodeRecoveryNewEpochPreservesAllDrafts(t *testing.T) {
	a, id, adapter, checker, previous := nodeRecoveryFixture(t)
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.77/32"}}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a.EngineConfigs = engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	if _, err := a.EngineConfigs.Stage("nfqws2", "user-list", "unapplied.example\n"); err != nil {
		t.Fatal(err)
	}
	beforeConfig := a.Store.Get()
	beforeDraft, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list")
	if err != nil {
		t.Fatal(err)
	}
	a.nodeRecoveryRound(context.Background(), time.Now())
	status := a.nodeRecoverySnapshot()
	if status.State != "recovered" {
		t.Fatalf("status=%+v calls=%v", status, adapter.calls)
	}
	current, _, err := a.Dataplane.Committed()
	if err != nil || current.PlanID == previous.PlanID || current.Digest == previous.Digest || current.NetworkProfileID != recoveryProfile || current.Revision != beforeConfig.AppliedRevision || len(current.EngineDrafts) != 0 || len(current.RetiringAdapters) != 0 {
		t.Fatalf("not a fresh applied-only plan: %+v %v", current, err)
	}
	if !reflect.DeepEqual(previous.Routes, current.Routes) || !reflect.DeepEqual(beforeConfig, a.Store.Get()) {
		t.Fatal("revalidation changed applied targets or a draft")
	}
	afterDraft, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list")
	if err != nil || !reflect.DeepEqual(beforeDraft, afterDraft) {
		t.Fatal("engine draft changed")
	}
	if len(checker.requests) != 1 || checker.requests[0].NodeID != id || checker.requests[0].Service.ID != "telegram" || checker.requests[0].NetworkProfile != recoveryProfile {
		t.Fatal("checked different targets")
	}
	if strings.Join(adapter.calls, ",") != "snapshot,stage,validate,canary,activate,health,commit" {
		t.Fatalf("native pipeline bypassed: %v", adapter.calls)
	}
	a.nodeRecoveryRound(context.Background(), time.Now().Add(time.Minute))
	if len(checker.requests) != 1 {
		t.Fatal("same epoch caused unnecessary reapply")
	}
}

func TestAppliedNodeRecoveryRejectsUnreviewedTargetsBeforeChecks(t *testing.T) {
	for _, change := range []string{"mixed", "scope", "applied-revision", "missing-node", "disabled", "safe-mode", "no-capability"} {
		t.Run(change, func(t *testing.T) {
			a, id, adapter, checker, previous := nodeRecoveryFixture(t)
			switch change {
			case "mixed":
				previous.Routes = append(previous.Routes, dataplane.Route{ServiceID: "youtube", Selected: "direct", Resolved: "direct"})
				_ = a.Dataplane.Record(previous)
			case "scope":
				a.Catalog.Services[0].Domains = []string{"new.example"}
			case "applied-revision":
				_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct"})
				_ = a.Store.ApplyDraft()
			case "missing-node":
				_, _ = a.Nodes.Delete(context.Background(), id, time.Now())
			case "disabled":
				_, _ = a.Nodes.SetDisabled(context.Background(), id, true, time.Now())
			case "safe-mode":
				_ = a.Store.SetSafeMode(true)
			case "no-capability":
				a.DataplaneHost = func() dataplane.HostState { return dataplane.HostState{} }
			}
			a.nodeRecoveryRound(context.Background(), time.Now())
			if a.nodeRecoverySnapshot().State != "requires-review" || len(adapter.calls) != 0 {
				t.Fatalf("refusal=%+v calls=%v", a.nodeRecoverySnapshot(), adapter.calls)
			}
			if change != "no-capability" && len(checker.requests) != 0 {
				t.Fatal("unreviewed target was probed")
			}
		})
	}
}

func TestAppliedNodeRecoveryConflictAndCancellationBoundaries(t *testing.T) {
	for _, phase := range []string{"before", "check", "generation", "revision", "network", "snapshot", "stage", "canary", "activate", "health", "scope-at-stage", "ttl"} {
		t.Run(phase, func(t *testing.T) {
			a, id, adapter, checker, previous := nodeRecoveryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "before" {
				cancel()
			}
			checker.hook = func(context.Context, dataplane.NodeCheckRequest) {
				switch phase {
				case "check":
					cancel()
				case "generation":
					_, _ = a.Nodes.SetAlias(context.Background(), id, "changed", time.Now())
				case "revision":
					_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "warp-wg"})
				case "network":
					a.FreshProfile = func(context.Context) (string, error) { return "wan-333333333333", nil }
				}
			}
			if phase == "ttl" {
				checker.ttl = 100 * time.Millisecond
			}
			adapter.after = func(name string) error {
				if name == phase {
					cancel()
				}
				if name == "stage" && phase == "scope-at-stage" {
					a.Catalog.Services[0].Domains = []string{"new.example"}
				}
				if name == "stage" && phase == "ttl" {
					time.Sleep(150 * time.Millisecond)
				}
				return nil
			}
			a.nodeRecoveryRound(ctx, time.Now())
			current, _, _ := a.Dataplane.Committed()
			if !sameNodeRecoveryPlan(current, previous) {
				t.Fatal("conflict promoted a new committed plan")
			}
			calls := strings.Join(adapter.calls, ",")
			live := phase == "activate" || phase == "health"
			if live != strings.Contains(calls, "rollback") {
				t.Fatalf("rollback boundary: %s calls=%v", phase, adapter.calls)
			}
			if !live && strings.Contains(calls, "activate") {
				t.Fatal("stale candidate activated")
			}
			if release, err := a.Operations.Exclusive(context.Background()); err != nil {
				t.Fatal("cleanup leaked operation ownership")
			} else {
				release()
			}
		})
	}
}

func TestAppliedNodeRecoveryChecksAllServicesBeforeActivating(t *testing.T) {
	a, id, adapter, checker, previous := nodeRecoveryFixture(t)
	if err := a.Store.UpdateService("telegram", a.Store.Get().AppliedServices["telegram"]); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "sing-box:" + id}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	previous.Revision = a.Store.Get().AppliedRevision
	previous.Routes = append(previous.Routes, dataplane.Route{ServiceID: "youtube", ServiceName: "YouTube", Selected: "sing-box:" + id, Resolved: "sing-box:" + id, Domains: []string{"youtube.com"}, ProbeURL: "https://youtube.com/"})
	if err := a.Dataplane.Record(previous); err != nil {
		t.Fatal(err)
	}
	checker.hook = func(_ context.Context, request dataplane.NodeCheckRequest) {
		checker.fail = request.Service.ID == "youtube"
	}
	a.nodeRecoveryRound(context.Background(), time.Now())
	if len(checker.requests) != 2 || len(adapter.calls) != 0 {
		t.Fatalf("partial activation: checks=%d calls=%v", len(checker.requests), adapter.calls)
	}
	current, _, _ := a.Dataplane.Committed()
	if !sameNodeRecoveryPlan(previous, current) {
		t.Fatal("partial service recovery replaced journal")
	}
}

func TestAppliedNodeRecoveryGroupAndAutoPinCommittedNode(t *testing.T) {
	for _, selector := range []string{"group", "auto"} {
		t.Run(selector, func(t *testing.T) {
			a, id, adapter, checker, previous := nodeRecoveryFixture(t)
			snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "other", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@other.example:443?security=tls", time.Now(), time.Hour, false)
			if err != nil {
				t.Fatal(err)
			}
			ids := []string{}
			for _, node := range snapshot.Nodes {
				ids = append(ids, node.ID)
			}
			route := "auto"
			if selector == "group" {
				group, err := a.Nodes.CreateGroup(context.Background(), "applied", "fallback", ids, "", time.Minute, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				route = "sing-box:" + group.ID
			}
			_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: route, Sources: previous.Routes[0].Sources})
			_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"})
			_ = a.Store.ApplyDraft()
			previous.Revision = a.Store.Get().AppliedRevision
			previous.Routes[0].Selected = route
			_ = a.Dataplane.Record(previous)
			checker.fail = true
			a.nodeRecoveryRound(context.Background(), time.Now())
			if len(checker.requests) != 1 || checker.requests[0].NodeID != id || len(adapter.calls) != 0 {
				t.Fatal("recovery selected a different node")
			}
		})
	}
}

func TestAppliedNodeRecoveryBusyAndBoundedRetries(t *testing.T) {
	a, _, adapter, checker, _ := nodeRecoveryFixture(t)
	release, err := a.Operations.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a.nodeRecoveryRound(context.Background(), time.Now())
	if len(checker.requests) != 0 {
		t.Fatal("background took ownership from active operation")
	}
	release()
	checker.fail = true
	start := time.Now()
	for index := 0; index < 6; index++ {
		a.nodeRecoveryRound(context.Background(), start.Add(time.Duration(index)*10*time.Minute))
	}
	if len(checker.requests) != maxNodeRecoveryAttempts || len(adapter.calls) != 0 || a.nodeRecoverySnapshot().State != "requires-review" {
		t.Fatalf("unbounded retry: %+v checks=%d", a.nodeRecoverySnapshot(), len(checker.requests))
	}
	a.FreshProfile = func(context.Context) (string, error) { return "", errors.New("private-network-error") }
	a.nodeRecoveryRound(context.Background(), start.Add(time.Hour))
	a.FreshProfile = func(context.Context) (string, error) { return recoveryProfile, nil }
	a.nodeRecoveryRound(context.Background(), start.Add(2*time.Hour))
	if len(checker.requests) != maxNodeRecoveryAttempts {
		t.Fatal("unknown observation reset retry bound")
	}
}

func TestAppliedNodeRecoveryBusyStatusIsSanitized(t *testing.T) {
	a, _, _, checker, _ := nodeRecoveryFixture(t)
	checker.hook = func(context.Context, dataplane.NodeCheckRequest) {
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"state":"revalidating"`) || strings.Contains(w.Body.String(), "private.example") {
			t.Fatalf("busy status=%d %s", w.Code, w.Body.String())
		}
	}
	a.nodeRecoveryRound(context.Background(), time.Now())
	encoded, err := json.Marshal(a.nodeRecoverySnapshot())
	if err != nil || strings.Contains(string(encoded), "private.example") {
		t.Fatal("public status contains node material")
	}
}

func TestAppliedNodeRecoverySchedulerStopsWithOwnershipReleased(t *testing.T) {
	a, _, _, _, _ := nodeRecoveryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	a.StartNodeRecovery(ctx)
	cancel()
	waitCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := a.WaitNodeRecovery(waitCtx); err != nil {
		t.Fatal(err)
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	if _, err := os.Stat(filepath.Join(a.Dataplane.StateRoot, "latest-committed-plan.json")); err != nil {
		t.Fatal(err)
	}
}

func TestAppliedNodeRecoveryShutdownJoinsInFlightCleanup(t *testing.T) {
	a, _, adapter, checker, previous := nodeRecoveryFixture(t)
	entered, cleaning, finishCleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
	checker.hook = func(ctx context.Context, _ dataplane.NodeCheckRequest) {
		close(entered)
		<-ctx.Done()
		close(cleaning)
		<-finishCleanup // Models the exact checker's bounded WithoutCancel cleanup.
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.StartNodeRecovery(ctx)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not start")
	}
	cancel()
	<-cleaning
	short, stopShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := a.WaitNodeRecovery(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown returned before cleanup: %v", err)
	}
	stopShort()
	if release, err := a.Operations.Exclusive(context.Background()); err == nil {
		release()
		t.Fatal("cleanup lost exclusive ownership")
	}
	close(finishCleanup)
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := a.WaitNodeRecovery(wait); err != nil {
		t.Fatal(err)
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("joined worker kept ownership")
	} else {
		release()
	}
	current, _, _ := a.Dataplane.Committed()
	if !sameNodeRecoveryPlan(current, previous) || len(adapter.calls) != 0 {
		t.Fatal("shutdown changed working runtime")
	}
}

type recoverySourceTransport struct{}

func (recoverySourceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("enriched.example\n")), Request: request}, nil
}

func TestAppliedNodeRecoverySourceReceiptDoesNotReplaceExactScopeAuthority(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("previously_used_expired_%t", expired), func(t *testing.T) {
			a, _, adapter, checker, previous := nodeRecoveryFixture(t)
			cache := t.TempDir()
			source := sources.Source{ID: "telegram-enrichment", Name: "Telegram enrichment", Kind: "domains", Format: "lines", URL: "https://source.example/list", Enabled: true, MinEntries: 1, Services: []string{"telegram"}, TTLHours: 1, TrustTier: "community"}
			registry := sources.Registry{Schema: 2, Sources: []sources.Source{source}}
			manager := sources.NewManager(registry, cache)
			if expired {
				manager.SetHTTPClient(&http.Client{Transport: recoverySourceTransport{}})
				if err := manager.Refresh(context.Background(), source.ID); err != nil {
					t.Fatal(err)
				}
				domains, _ := manager.EntriesForService("telegram")
				if !reflect.DeepEqual(domains, []string{"enriched.example"}) {
					t.Fatal("source did not enrich the original applied scope")
				}
				previous.Routes[0].Domains = append(previous.Routes[0].Domains, domains...)
				if err := a.Dataplane.Record(previous); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(cache, source.ID+".cache.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var receipt map[string]any
				if err := json.Unmarshal(data, &receipt); err != nil {
					t.Fatal(err)
				}
				fetched := time.Now().UTC().Add(-2 * time.Hour)
				receipt["fetched_at"], receipt["expires_at"] = fetched, fetched.Add(time.Hour)
				data, _ = json.Marshal(receipt)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				manager = sources.NewManager(registry, cache)
				if manager.List()[0].CacheStatus != "stale" {
					t.Fatal("fixture is not an expired, otherwise valid receipt")
				}
			}
			a.Sources = manager
			if manager.AutomaticUseReady([]string{"telegram"}) {
				t.Fatal("fixture must reproduce the general AUTO gate refusal")
			}
			a.nodeRecoveryRound(context.Background(), time.Now())
			if expired {
				if a.nodeRecoverySnapshot().State != "requires-review" || len(checker.requests) != 0 || len(adapter.calls) != 0 {
					t.Fatal("expired enrichment silently dropped applied targets")
				}
				return
			}
			if a.nodeRecoverySnapshot().State != "recovered" || len(checker.requests) != 1 {
				t.Fatalf("never-downloaded source blocked identical applied scope: %+v", a.nodeRecoverySnapshot())
			}
			current, _, _ := a.Dataplane.Committed()
			if !reflect.DeepEqual(current.Routes, previous.Routes) {
				t.Fatal("source receipt refusal bypass changed targets")
			}
		})
	}
}
