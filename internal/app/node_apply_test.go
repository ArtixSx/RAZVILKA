package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type nodeApplyAdapter struct {
	calls []string
	after func(string) error
}

func (a *nodeApplyAdapter) ID() string { return "sing-box" }
func (a *nodeApplyAdapter) phase(name string) error {
	a.calls = append(a.calls, name)
	if a.after != nil {
		return a.after(name)
	}
	return nil
}
func (a *nodeApplyAdapter) Snapshot(context.Context, dataplane.Plan, string) error {
	return a.phase("snapshot")
}
func (a *nodeApplyAdapter) Stage(context.Context, dataplane.Plan, string) error {
	return a.phase("stage")
}
func (a *nodeApplyAdapter) Validate(context.Context, dataplane.Plan, string) error {
	return a.phase("validate")
}
func (a *nodeApplyAdapter) Canary(context.Context, dataplane.RoutePlan, string) error {
	return a.phase("canary")
}
func (a *nodeApplyAdapter) Activate(context.Context, dataplane.Plan, string) error {
	return a.phase("activate")
}
func (a *nodeApplyAdapter) Health(context.Context, dataplane.Plan, string) error {
	return a.phase("health")
}
func (a *nodeApplyAdapter) Commit(context.Context, dataplane.Plan, string) error {
	return a.phase("commit")
}
func (a *nodeApplyAdapter) Rollback(ctx context.Context, _ dataplane.Plan, _ string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return a.phase("rollback")
}

func nodeApplyFixture(t *testing.T) (*App, string, *nodeApplyAdapter) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nodes"), 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(filepath.Join(root, "nodes"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	snapshot, err := nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Nodes[0].ID
	_, err = nodes.RecordCheck(context.Background(), id, nodestore.CheckRecord{ProbeID: "probe-nb1", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Hour)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.2/32"}}); err != nil {
		t.Fatal(err)
	}
	if err = store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.3/32"}}); err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "usque"}); err != nil {
		t.Fatal(err)
	}
	a := &App{Nodes: nodes, Store: store, FreshProfile: stableNodeProfile, Dataplane: dataplane.New(filepath.Join(root, "dataplane")), Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}, ProbeURL: "https://telegram.org/"}, {ID: "youtube", Name: "YouTube", Domains: []string{"youtube.com"}, ProbeURL: "https://youtube.com/"}}}}
	a.Dataplane.FreshProfile = stableNodeProfile
	a.DataplaneHost = func() dataplane.HostState { return dataplane.HostState{IPCommand: true, TUN: true, SingBox: true} }
	a.nodeReviews.options = func() []routecatalog.Option {
		return []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box:" + id, Installed: true, Configured: true, Selectable: true, Services: []string{"telegram"}}}
	}
	adapter := &nodeApplyAdapter{}
	if err = a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	return a, id, adapter
}

func nodeRouteRequest(a *App, id, action string, body any, owner string, ctx context.Context) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+id+"/"+action, strings.NewReader(string(data))).WithContext(ctx)
	r.Header.Set("Authorization", owner)
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
	return w
}

func reviewedNode(t *testing.T, a *App, id string) nodeRouteReview {
	return reviewedNodeScope(t, a, id, nil)
}

func reviewedNodeScope(t *testing.T, a *App, id string, scope *nodeScopeSelection) nodeRouteReview {
	t.Helper()
	body := map[string]any{"service_id": "telegram"}
	if scope != nil {
		body["scope"] = scope
	}
	w := nodeRouteRequest(a, id, "preview", body, "owner-a", context.Background())
	var response struct {
		Ready       bool            `json:"ready"`
		Review      nodeRouteReview `json:"review"`
		Transaction dataplane.Plan  `json:"transaction"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || !response.Ready || response.Review.Token == "" {
		t.Fatalf("preview=%d %s", w.Code, w.Body.String())
	}
	if len(response.Transaction.Routes) != 1 || response.Transaction.Routes[0].ServiceID != "telegram" || len(response.Transaction.EngineDrafts) != 0 {
		t.Fatalf("preview included unrelated drafts: %+v", response.Transaction)
	}
	for _, secret := range []string{"private.example", "123e4567", "vless://"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("preview leaked secret")
		}
	}
	return response.Review
}

func TestNodeExplicitScopePreviewAndAtomicCommit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selection *nodeScopeSelection
		want      []string
		deferred  bool
	}{
		{"omitted", nil, []string{"192.168.1.2/32"}, true},
		{"applied", &nodeScopeSelection{Mode: "applied"}, []string{"192.168.1.2/32"}, true},
		{"draft", &nodeScopeSelection{Mode: "draft"}, []string{"192.168.1.3/32"}, false},
		{"all", &nodeScopeSelection{Mode: "all"}, nil, false},
		{"selected", &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.40", "192.168.1.40/32", "192.168.2.18/24"}}, []string{"192.168.1.40/32", "192.168.2.0/24"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, id, adapter := nodeApplyFixture(t)
			before := a.Store.Get()
			body := map[string]any{"service_id": "telegram", "expected_revision": before.Revision}
			if tc.selection != nil {
				body["scope"] = tc.selection
			}
			w := nodeRouteRequest(a, id, "preview", body, "owner-a", context.Background())
			var preview struct {
				Ready               bool            `json:"ready"`
				Review              nodeRouteReview `json:"review"`
				Transaction         dataplane.Plan  `json:"transaction"`
				Applied             nodeScopeView   `json:"applied_scope"`
				Draft               nodeScopeView   `json:"draft_scope"`
				Effective           nodeScopeView   `json:"effective_scope"`
				AppliedScopePresent bool            `json:"applied_scope_present"`
				ScopeChanged        bool            `json:"scope_changed"`
				DraftPending        bool            `json:"draft_scope_pending"`
				DraftDeferred       bool            `json:"draft_scope_deferred"`
				ScopeNotice         string          `json:"scope_notice"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &preview) != nil || !preview.Ready {
				t.Fatalf("preview=%d %s", w.Code, w.Body.String())
			}
			if !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 {
				t.Fatal("preview mutated draft or runtime")
			}
			if !stringSlicesEqual(preview.Applied.Sources, before.AppliedServices["telegram"].Sources) || !stringSlicesEqual(preview.Draft.Sources, before.Services["telegram"].Sources) || !stringSlicesEqual(preview.Effective.Sources, tc.want) || preview.Effective.SourceCount != len(tc.want) || preview.Effective.Summary == "" || preview.ScopeNotice == "" || !preview.AppliedScopePresent || !preview.DraftPending || preview.DraftDeferred != tc.deferred || preview.ScopeChanged != !stringSlicesEqual(tc.want, before.AppliedServices["telegram"].Sources) {
				t.Fatalf("misleading scope preview: %s", w.Body.String())
			}
			if len(preview.Transaction.Routes) != 1 || !stringSlicesEqual(preview.Transaction.Routes[0].Sources, tc.want) {
				t.Fatal("preview plan differs from displayed effective sources")
			}
			w = nodeRouteRequest(a, id, "apply", nodeApplyBody(preview.Review), "owner-a", context.Background())
			if w.Code != 200 {
				t.Fatalf("apply=%d %s", w.Code, w.Body.String())
			}
			after := a.Store.Get()
			wantDesired := tc.want
			if tc.deferred {
				wantDesired = before.Services["telegram"].Sources
			}
			if !stringSlicesEqual(after.AppliedServices["telegram"].Sources, tc.want) || !stringSlicesEqual(after.Services["telegram"].Sources, wantDesired) || !reflect.DeepEqual(after.Services["youtube"], before.Services["youtube"]) || !reflect.DeepEqual(after.AppliedServices["youtube"], before.AppliedServices["youtube"]) || after.Revision != before.Revision+1 {
				t.Fatal("atomic scope commit changed a different choice or unrelated draft")
			}
		})
	}
}

func TestNodeScopePreviewRejectsInvalidAndStaleSelectionWithoutMutation(t *testing.T) {
	for _, scope := range []*nodeScopeSelection{
		{}, {Mode: "selected"}, {Mode: "selected", Sources: []string{" "}},
		{Mode: "selected", Sources: []string{"127.0.0.1"}},
		{Mode: "selected", Sources: []string{"::1/128"}},
		{Mode: "selected", Sources: []string{"not-an-address"}},
		{Mode: "selected", Sources: make([]string, maxNodeScopeSources+1)},
		{Mode: "all", Sources: []string{"192.168.1.40"}},
		{Mode: "applied", Sources: []string{"192.168.1.40"}},
		{Mode: "draft", Sources: []string{"192.168.1.40"}},
	} {
		a, id, adapter := nodeApplyFixture(t)
		before := a.Store.Get()
		w := nodeRouteRequest(a, id, "preview", map[string]any{"service_id": "telegram", "scope": scope}, "owner-a", context.Background())
		if w.Code != 400 || !strings.Contains(w.Body.String(), "NODE_SCOPE_INVALID") || !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 || len(a.nodeReviews.reviews) != 0 {
			t.Fatalf("invalid scope was not rejected cleanly: %d %s", w.Code, w.Body.String())
		}
	}
	a, id, adapter := nodeApplyFixture(t)
	before := a.Store.Get()
	w := nodeRouteRequest(a, id, "preview", map[string]any{"service_id": "telegram", "scope": nodeScopeSelection{Mode: "applied"}, "expected_revision": before.Revision - 1}, "owner-a", context.Background())
	if w.Code != 409 || !strings.Contains(w.Body.String(), "NODE_REVIEW_CHANGED") || !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 || len(a.nodeReviews.reviews) != 0 {
		t.Fatal("stale displayed scope generated an applicable review")
	}
}

func TestNodeScopeIsBoundToReviewDigestAndNewServiceIsExplicitlyIdentified(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	first := reviewedNodeScope(t, a, id, &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.40"}})
	second := reviewedNodeScope(t, a, id, &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.41"}})
	if first.Digest == second.Digest {
		t.Fatal("different device scopes produced identical reviewed plans")
	}
	stored := a.nodeReviews.reviews[first.Token]
	stored.scopeSources = []string{"192.168.1.42/32"}
	a.nodeReviews.reviews[first.Token] = stored
	before := a.Store.Get()
	w := nodeRouteRequest(a, id, "apply", nodeApplyBody(first), "owner-a", context.Background())
	if w.Code != 409 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("scope changed after review without invalidating digest")
	}
	if err := a.Store.DeleteService("telegram"); err != nil {
		t.Fatal(err)
	}
	w = nodeRouteRequest(a, id, "preview", map[string]any{"service_id": "telegram", "scope": nodeScopeSelection{Mode: "all"}}, "owner-a", context.Background())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"applied_scope_present":false`) || !strings.Contains(w.Body.String(), `"mode":"all","sources":[],"source_count":0`) {
		t.Fatalf("new service scope is ambiguous: %d %s", w.Code, w.Body.String())
	}
}

func nodeApplyBody(review nodeRouteReview) map[string]any {
	return map[string]any{"service_id": review.ServiceID, "review_token": review.Token, "reviewed_digest": review.Digest, "revision": review.Revision, "generation": review.Generation, "confirm": "APPLY_NODE_ROUTE"}
}

func TestNodeReviewedApplyCommitsOnlySelectedRoute(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	before := a.Store.Get()
	review := reviewedNode(t, a, id)
	if !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 {
		t.Fatal("preview changed state")
	}
	w := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", context.Background())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"live_applied":true`) {
		t.Fatalf("apply=%d %s", w.Code, w.Body.String())
	}
	after := a.Store.Get()
	if !after.AppliedServices["telegram"].Enabled || after.AppliedServices["telegram"].Route != "sing-box:"+id || !reflect.DeepEqual(after.AppliedServices["telegram"].Sources, before.AppliedServices["telegram"].Sources) || !reflect.DeepEqual(after.Services["telegram"].Sources, before.Services["telegram"].Sources) || !reflect.DeepEqual(after.Services["youtube"], before.Services["youtube"]) || after.AppliedServices["youtube"].Enabled {
		t.Fatalf("targeted commit crossed ownership: %+v", after)
	}
	if after.Revision != review.Revision+1 || after.AppliedRevision != after.Revision || strings.Contains(strings.Join(adapter.calls, ","), "rollback") {
		t.Fatalf("post-commit guard rejected own revision: %+v calls=%v", after, adapter.calls)
	}
	calls := len(adapter.calls)
	w = nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", context.Background())
	if w.Code != 409 || len(adapter.calls) != calls {
		t.Fatal("review replay changed runtime")
	}
}

func TestNodeReviewConflictGatesBeforeRuntime(t *testing.T) {
	for _, kind := range []string{"digest", "revision", "generation", "session", "service", "config-changed", "node-changed", "network", "expired", "safe-mode"} {
		t.Run(kind, func(t *testing.T) {
			a, id, adapter := nodeApplyFixture(t)
			review := reviewedNodeScope(t, a, id, &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.40"}})
			body := nodeApplyBody(review)
			owner := "owner-a"
			switch kind {
			case "digest":
				body["reviewed_digest"] = "wrong"
			case "revision":
				body["revision"] = review.Revision + 1
			case "generation":
				body["generation"] = review.Generation + 1
			case "session":
				owner = "owner-b"
			case "service":
				body["service_id"] = "youtube"
			case "config-changed":
				_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"})
			case "node-changed":
				_, _ = a.Nodes.SetAlias(context.Background(), id, "Изменено", time.Now())
			case "network":
				a.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
			case "expired":
				stored := a.nodeReviews.reviews[review.Token]
				stored.ExpiresAt = time.Now().Add(-time.Second)
				a.nodeReviews.reviews[review.Token] = stored
			case "safe-mode":
				_ = a.Store.SetSafeMode(true)
			}
			before := a.Store.Get()
			w := nodeRouteRequest(a, id, "apply", body, owner, context.Background())
			if w.Code != 409 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatalf("gate %s failed: %d %s calls=%v", kind, w.Code, w.Body.String(), adapter.calls)
			}
		})
	}
}

func TestNodeReviewExpiresOrCancelsDuringTransaction(t *testing.T) {
	for _, phase := range []string{"stage", "canary", "activate", "health"} {
		for _, cancelRequest := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "/proof-revoked", true: "/canceled"}[cancelRequest], func(t *testing.T) {
				a, id, adapter := nodeApplyFixture(t)
				review := reviewedNode(t, a, id)
				before := a.Store.Get()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				adapter.after = func(current string) error {
					if current == phase {
						if cancelRequest {
							cancel()
						} else {
							_, err := a.Nodes.SetDisabled(context.Background(), id, true, time.Now())
							if err != nil {
								t.Fatal(err)
							}
						}
					}
					return nil
				}
				w := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", ctx)
				live := phase == "activate" || phase == "health"
				if w.Code != 409 || strings.Contains(strings.Join(adapter.calls, ","), "rollback") != live || !reflect.DeepEqual(before, a.Store.Get()) {
					t.Fatalf("late guard failed: %d %s calls=%v", w.Code, w.Body.String(), adapter.calls)
				}
			})
		}
	}
}

func TestNodeApplyCommitFailureRollsBack(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	review := reviewedNode(t, a, id)
	before := a.Store.Get()
	adapter.after = func(phase string) error {
		if phase == "commit" {
			return errors.New("commit failed")
		}
		return nil
	}
	w := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", context.Background())
	if w.Code != 409 || !strings.Contains(strings.Join(adapter.calls, ","), "rollback") || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatalf("failed apply changed config: %d %s", w.Code, w.Body.String())
	}
}

func TestNodeApplyNetworkChangeAfterConfigCommitRestoresOwnConfig(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	review := reviewedNodeScope(t, a, id, &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.40"}})
	before := a.Store.Get()
	a.Dataplane.FreshProfile = func(context.Context) (string, error) {
		if a.Store.Get().Revision != before.Revision {
			return "wan-ffffffffffff", nil
		}
		return stableNodeProfile(context.Background())
	}
	w := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", context.Background())
	if w.Code != http.StatusConflict || !strings.Contains(strings.Join(adapter.calls, ","), "rollback") || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatalf("late network change retained the targeted commit: %d %s calls=%v", w.Code, w.Body.String(), adapter.calls)
	}
}
