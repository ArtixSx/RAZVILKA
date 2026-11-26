package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

const autonomyXHTTPURI = "vless://123e4567-e89b-12d3-a456-426614174001@xhttp.example:443?security=tls&sni=xhttp.example&type=xhttp&path=%2Ftransport&mode=packet-up"

func TestAutonomySearchEngineHonorsOrderAndAvailableAlternative(t *testing.T) {
	a := &App{}
	p := autonomy.Default()
	cfg := config.Config{}
	spec := autonomy.Service{ExpectedRoute: "auto"}
	installed := []routecatalog.Option{{ID: "xray", Installed: true}}
	a.nodeReviews.options = func() []routecatalog.Option { return installed }
	if got := a.autonomySearchEngine(cfg, p, spec); got != "xray" {
		t.Fatalf("installed alternate engine was skipped: %s", got)
	}
	installed = append(installed, routecatalog.Option{ID: "sing-box", Installed: true})
	if got := a.autonomySearchEngine(cfg, p, spec); got != "sing-box" {
		t.Fatalf("default engine order was ignored: %s", got)
	}
	p.PreferredRoutes = []string{"xray", "sing-box"}
	if got := a.autonomySearchEngine(cfg, p, spec); got != "xray" {
		t.Fatalf("operator's engine order was ignored: %s", got)
	}
	spec.ExpectedRoute = "sing-box"
	if got := a.autonomySearchEngine(cfg, p, spec); got != "sing-box" {
		t.Fatalf("explicit engine was replaced: %s", got)
	}
}

func TestAutonomySwitchesSearchToApprovedEngineWithChecker(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	options := a.nodeReviews.options
	a.nodeReviews.options = func() []routecatalog.Option {
		return append(options(), routecatalog.Option{ID: "xray", Installed: true, Configured: true, Selectable: true})
	}
	p := a.autonomyPolicy()
	p.PreferredRoutes = []string{"xray", "sing-box"}
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var checked []string
	a.NodeCheckers = nil // Xray is installed, but only Sing-box can be checked.
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, request.NodeID)
		return d10Result(request, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if runtime := autonomyTestState(a); runtime.State != "applied" || !slices.Equal(checked, ids[:1]) || !slices.Contains(adapter.calls, "commit") {
		t.Fatal("an installed engine without a checker stopped the approved search", runtime.State, checked, adapter.calls)
	}
	if applied := selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]); applied != "sing-box:"+ids[0] {
		t.Fatal("the applied path did not use its actual checker", applied)
	}
}

func TestAutonomyTriesSameProfileAfterEngineAdmissionRefusal(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		err    error
		code   string
		expire bool
	}{
		{name: "runtime", err: dataplane.ErrExactNodeRuntime},
		{name: "unsupported", err: dataplane.ErrExactNodeUnsupported},
		{name: "cleanup", err: dataplane.ErrExactNodeUnsupported, code: "node-cleanup-failed"},
		{name: "expired-origin", err: dataplane.ErrExactNodeUnsupported, expire: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			options := a.nodeReviews.options
			a.nodeReviews.options = func() []routecatalog.Option {
				return append(options(), routecatalog.Option{ID: "xray", Installed: true, Configured: true, Selectable: true})
			}
			p := a.autonomyPolicy()
			p.PreferredRoutes = []string{"xray", "sing-box"}
			p.CandidatesPerRound = 1
			w := httptest.NewRecorder()
			a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
			if w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
			a.NodeHistoryWriteGuard = func(context.Context, int) error { return nil }
			var checks []string
			a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks = append(checks, "xray:"+request.NodeID)
				if scenario.expire {
					data := `{"outbounds":[` + string(request.Outbound) + `]}`
					if _, err := a.Nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, data, time.Now(), time.Nanosecond, false); err != nil {
						t.Fatal("could not expire fixture origin", err)
					}
				}
				return dataplane.NodeCheckResult{ErrorCode: scenario.code}, scenario.err
			})}
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks = append(checks, "sing-box:"+request.NodeID)
				return d10Result(request, "sing-box", true), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			r := autonomyTestState(a)
			if scenario.expire {
				if !slices.Equal(checks, []string{"xray:" + ids[0]}) || len(adapter.calls) != 0 || r.Search == nil || r.Search.Cursor != 1 {
					t.Fatal("expired origin allowed a second check or prevented progress", checks, adapter.calls, r.State)
				}
				return
			}
			if scenario.code != "" {
				if !slices.Equal(checks, []string{"xray:" + ids[0]}) || len(adapter.calls) != 0 || r.State != "requires-review" {
					t.Fatal("cleanup failure allowed an alternate check or application", checks, adapter.calls, r.State)
				}
				return
			}
			if !slices.Equal(checks, []string{"xray:" + ids[0], "sing-box:" + ids[0]}) || !slices.Contains(adapter.calls, "commit") || r.State != "applied" || r.Search == nil || r.Search.Cursor != 1 {
				t.Fatal("the same candidate was discarded before trying the compatible executor", checks, adapter.calls, r.State)
			}
			if route := selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]); route != "sing-box:"+ids[0] {
				t.Fatal("applied route was not bound to the alternate result", route)
			}
		})
	}
}

func autonomyXHTTPFixture(t *testing.T) (*App, *engineNodeFixture, *engineNodeFixture, string) {
	t.Helper()
	a, sing, xray, _ := engineNodeHTTPFixture(t)
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, autonomyXHTTPURI, time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, node := range snapshot.Nodes {
		if node.Transport == "xhttp" {
			id = node.ID
		}
	}
	if id == "" {
		t.Fatal("canonical XHTTP fixture missing")
	}
	a.nodeReviews.options = func() []routecatalog.Option {
		return []routecatalog.Option{{ID: "sing-box", Installed: true}, {ID: "xray", Installed: true}}
	}
	return a, sing, xray, id
}

func TestAutonomyAUTOUsesCompatibleConsentedInstalledEngine(t *testing.T) {
	a, _, _, id := autonomyXHTTPFixture(t)
	p := autonomy.Default()
	s := autonomy.Service{ID: "discord", ExpectedRoute: "auto"}
	if got, err := a.autonomyCandidateEngine(context.Background(), p, s, "sing-box", id); err != nil || got != "xray" {
		t.Fatalf("AUTO skipped canonical XHTTP: %s %v", got, err)
	}
	for _, explicit := range []string{"sing-box", "sing-box:node-example", "xray", "xray:node-example"} {
		s.ExpectedRoute = explicit
		engine := autonomyNodeEngine(explicit)
		if got, err := a.autonomyCandidateEngine(context.Background(), p, s, engine, id); err != nil || got != engine {
			t.Fatalf("explicit executor changed: %s -> %s %v", explicit, got, err)
		}
	}
	s.ExpectedRoute = "auto"
	p.PreferredRoutes = []string{"sing-box"}
	if _, err := a.autonomyCandidateEngine(context.Background(), p, s, "sing-box", id); !errors.Is(err, dataplane.ErrExactNodeUnsupported) {
		t.Fatal("Xray used without method consent", err)
	}
	p = autonomy.Default()
	a.nodeReviews.options = func() []routecatalog.Option { return []routecatalog.Option{{ID: "sing-box", Installed: true}} }
	if _, err := a.autonomyCandidateEngine(context.Background(), p, s, "sing-box", id); !errors.Is(err, dataplane.ErrExactNodeUnsupported) {
		t.Fatal("uninstalled Xray used", err)
	}
	if _, err := compatibleAutonomyEngine([]byte(`{"type":"vless","transport":{"type":"xhttp","mode":"unsupported"}}`), "sing-box"); !errors.Is(err, dataplane.ErrExactNodeUnsupported) {
		t.Fatal("malformed contract dispatched to another engine", err)
	}
}

func TestNodeHTTPDefaultUsesXHTTPExecutorButExplicitChoiceDoesNotChange(t *testing.T) {
	a, sing, xray, id := autonomyXHTTPFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	code, body := postEngineNode(t, server, id, "")
	if code != 200 || xray.calls != 1 || sing.calls != 0 || !strings.Contains(string(body), `"engine":"xray"`) || !strings.Contains(string(body), "xray:"+id) {
		t.Fatalf("omitted engine did not check canonical XHTTP: %d %s calls=%d/%d", code, body, sing.calls, xray.calls)
	}
	// Production Sing-box refuses XHTTP; that explicit refusal must survive.
	sing.err = dataplane.ErrExactNodeUnsupported
	code, _ = postEngineNode(t, server, id, "sing-box")
	if code != http.StatusConflict || sing.calls != 1 || xray.calls != 1 {
		t.Fatalf("explicit Sing-box choice silently fell back: %d calls=%d/%d", code, sing.calls, xray.calls)
	}
}
