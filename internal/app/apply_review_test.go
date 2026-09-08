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
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func genericReviewFixture(t *testing.T) *App {
	t.Helper()
	root := t.TempDir()
	// TempDir's numbered child follows the runner umask. Engine staging is
	// private state and must have its own explicit 0700 directory on Unix.
	stageRoot := filepath.Join(root, "staging")
	backupRoot := filepath.Join(root, "backups")
	for _, path := range []string{stageRoot, backupRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.40/32"}}); err != nil {
		t.Fatal(err)
	}
	return &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}}}}, EngineConfigs: engineconfig.New(stageRoot, backupRoot), DataplaneHost: func() dataplane.HostState { return dataplane.HostState{} }}
}

func genericReviewed(t *testing.T, a *App, query string) applyReview {
	t.Helper()
	w := httptest.NewRecorder()
	a.plan(w, httptest.NewRequest(http.MethodGet, "/api/v1/plan"+query, nil))
	var body struct {
		Review applyReview `json:"review"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body.Review.Digest) != 64 {
		t.Fatalf("plan: %d %s", w.Code, w.Body.String())
	}
	return body.Review
}

func genericApply(a *App, query string, review any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(review)
	w := httptest.NewRecorder()
	a.apply(w, httptest.NewRequest(http.MethodPost, "/api/v1/apply"+query, strings.NewReader(string(data))))
	return w
}

func TestGenericApplyReviewRejectsChangedRevisionContentAndScopeWithoutMutation(t *testing.T) {
	for _, change := range []string{"revision", "content", "scope", "catalog", "correct", "legacy"} {
		t.Run(change, func(t *testing.T) {
			a := genericReviewFixture(t)
			query := "?scope=services"
			if change == "content" {
				query = "?scope=engine&engine=sing-box"
				if _, err := a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"info"}}`); err != nil {
					t.Fatal(err)
				}
			}
			review := genericReviewed(t, a, query)
			switch change {
			case "revision":
				_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct"})
			case "content":
				_, _ = a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"debug"}}`)
			case "scope":
				query = "?scope=devices"
			case "catalog":
				a.Catalog.Services[0].Domains = []string{"different.example"}
			}
			before := a.Store.Get()
			var body any = review
			if change == "legacy" {
				body = map[string]any{}
			}
			w := genericApply(a, query, body)
			if change == "correct" || change == "legacy" {
				if w.Code != 200 || !a.Store.Get().AppliedServices["telegram"].Enabled || len(a.Store.Get().AppliedServices["telegram"].Sources) != 0 {
					t.Fatalf("reviewed service scope failed: %d %s", w.Code, w.Body.String())
				}
			} else if w.Code != 409 || !strings.Contains(w.Body.String(), "APPLY_REVIEW_CHANGED") || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatalf("stale review accepted: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestGenericApplyReviewRejectsPartialAndMalformedBodies(t *testing.T) {
	a := genericReviewFixture(t)
	before := a.Store.Get()
	for _, body := range []string{`{"expected_revision":1}`, `{"reviewed_digest":"` + strings.Repeat("0", 64) + `"}`, `{"expected_revision":1,"reviewed_digest":"bad"}`, `{} {}`, `[1]`, strings.Repeat(" ", 4100) + `{}`} {
		w := httptest.NewRecorder()
		a.apply(w, httptest.NewRequest(http.MethodPost, "/api/v1/apply?scope=services", strings.NewReader(body)))
		if w.Code != 400 || !reflect.DeepEqual(before, a.Store.Get()) {
			t.Fatalf("malformed review mutated intent: %d", w.Code)
		}
	}
}

func TestGenericApplyExcludesEditorWritesUntilRequestCleanup(t *testing.T) {
	a := genericReviewFixture(t)
	if _, err := a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"info"}}`); err != nil {
		t.Fatal(err)
	}
	review := genericReviewed(t, a, "?scope=services")
	data, _ := json.Marshal(review)
	body := newPausedBody(strings.NewReader(string(data)))
	var release sync.Once
	defer release.Do(func() { close(body.resume) })
	handler := a.Handler(http.NotFoundHandler())
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/apply?scope=services", body))
	}()
	awaitOperation(t, body.entered)
	for _, path := range []string{"/api/v1/engine-configs/sing-box/file?file=main", "/api/v1/services/telegram"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"content":"changed","enabled":false,"route":"direct"}`)))
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"not_started":true`) {
			t.Fatalf("concurrent editor entered Apply: %d %s", response.Code, response.Body.String())
		}
	}
	view, err := a.EngineConfigs.ReadExpert("sing-box", "main")
	if err != nil || view.Source != "staged" || view.Content != `{"log":{"level":"info"}}` {
		t.Fatal("blocked editor changed saved draft")
	}
	release.Do(func() { close(body.resume) })
	awaitOperation(t, done)
	if w.Code != http.StatusOK {
		t.Fatalf("apply failed: %d %s", w.Code, w.Body.String())
	}
	last, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("apply leaked admission")
	}
	last()
}

func TestGenericReviewGuardsNonNodeTransactionPhasesAndOwnDraftCommit(t *testing.T) {
	for _, change := range []string{"stage-content", "stage-discard", "canary-config", "health-config", "commit-content", "own-commit", "none"} {
		t.Run(change, func(t *testing.T) {
			a := genericReviewFixture(t)
			a.Dataplane = dataplane.New(t.TempDir())
			if _, err := a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"info"}}`); err != nil {
				t.Fatal(err)
			}
			plan, err := dataplane.Build(dataplane.Input{Revision: a.Store.Get().Revision, Routes: []dataplane.Route{{ServiceID: "telegram", ServiceName: "Telegram", Selected: "sing-box", Resolved: "sing-box", Domains: []string{"telegram.org"}}}, EngineConfigDrafts: []string{"sing-box/main"}, Engines: []dataplane.Engine{{ID: "sing-box", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: dataplane.HostState{TUN: true, IPCommand: true, SingBox: true}})
			if err != nil || !plan.Ready {
				t.Fatalf("fixture: %v %+v", err, plan.Blockers)
			}
			binding, err := a.bindApplyReview(context.Background(), a.Store.Get(), plan, changeScopeServices, "")
			if err != nil {
				t.Fatal(err)
			}
			adapter := &nodeApplyAdapter{after: func(phase string) error {
				switch {
				case change == "stage-content" && phase == "stage", change == "commit-content" && phase == "commit":
					_, err := a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"debug"}}`)
					return err
				case change == "stage-discard" && phase == "stage", change == "own-commit" && phase == "commit":
					return a.EngineConfigs.Discard("sing-box", "main")
				case change == "canary-config" && phase == "canary", change == "health-config" && phase == "health":
					return a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct"})
				}
				return nil
			}}
			if err := a.Dataplane.Register(adapter); err != nil {
				t.Fatal(err)
			}
			ctx := dataplane.WithReviewGuard(context.Background(), func(ctx context.Context) error { return binding.guard(a, ctx) })
			execution, err := a.Dataplane.Apply(ctx, plan, func() (func() error, error) { return binding.commit(a, ctx, changeScopeServices) })
			if change == "none" || change == "own-commit" {
				if err != nil || execution.State != "committed" {
					t.Fatalf("valid own transaction refused: %v %s", err, execution.State)
				}
			} else {
				if !errors.Is(err, dataplane.ErrReviewChanged) || execution.State == "committed" {
					t.Fatalf("changed authority accepted: %v %s", err, execution.State)
				}
				if strings.HasPrefix(change, "stage") || change == "canary-config" {
					if slices.Contains(adapter.calls, "activate") || slices.Contains(adapter.calls, "rollback") {
						t.Fatal("preactivation refusal touched live runtime")
					}
				} else if !slices.Contains(adapter.calls, "rollback") {
					t.Fatal("postactivation refusal did not rollback")
				}
			}
		})
	}
}
