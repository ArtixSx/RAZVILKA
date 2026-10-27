package app

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type readinessEngineChecker struct {
	readinessChecker
	engine string
}

func TestNodeReadinessSavedSourceRevocationDiscardsLateResult(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "deleted"}[remove], func(t *testing.T) {
			a, _, uris, _, _, start := readinessFixture(t)
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			feeds, err := providerfeed.Open(a.Nodes, root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = feeds.Close() })
			a.NodeFeeds = feeds
			request := providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.org/test"}, Enabled: true}
			source, err := feeds.Save(context.Background(), "", request)
			if err != nil {
				t.Fatal(err)
			}
			var raw string
			for _, uri := range uris {
				raw = uri
				break
			}
			if _, err = a.Nodes.Import(context.Background(), nodestore.Source{ID: source.SourceID, Kind: "subscription"}, raw, start, 24*time.Hour, false); err != nil {
				t.Fatal(err)
			}
			a.autonomy.doc.Policy.SourceIDs = []string{source.SourceID}
			calls := 0
			a.NodeChecker = connectivityJobChecker{run: func(ctx context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
				calls++
				if remove {
					err = feeds.Delete(context.Background(), source.SourceID, source.Revision)
				} else {
					request.Enabled, request.Revision = false, source.Revision
					_, err = feeds.Save(context.Background(), source.SourceID, request)
				}
				if err != nil {
					t.Fatal(err)
				}
				return readyConnectivity(r), nil
			}}
			a.nodeReadinessRound(context.Background(), start.Add(time.Minute))
			if calls != 1 {
				t.Fatalf("checks = %d", calls)
			}
			for _, e := range a.nodeReadiness.entries {
				if e.Ready || e.Failures != 0 || e.Transport != 0 {
					t.Fatalf("revoked source accepted or penalized: %+v", e)
				}
			}
			a.nodeReadinessRound(context.Background(), start.Add(20*time.Minute))
			if calls != 1 {
				t.Fatal("retained subscription nodes checked after source revocation")
			}
		})
	}
}

func (c *readinessEngineChecker) EngineID() string { return c.engine }
func (c *readinessEngineChecker) CheckConnectivity(ctx context.Context, request dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
	r, err := c.readinessChecker.CheckConnectivity(ctx, request)
	r.Engine = c.engine
	return r, err
}

func TestNodeReadinessUsesSelectedPermittedExecutor(t *testing.T) {
	for _, kind := range []string{"ordinary-auto", "ordinary-xray", "xhttp-auto", "xhttp-no-consent", "xhttp-xray"} {
		t.Run(kind, func(t *testing.T) {
			a, ids, _, _, _, start := readinessFixture(t)
			sing := &readinessEngineChecker{engine: "sing-box"}
			xray := &readinessEngineChecker{engine: "xray"}
			a.NodeChecker = sing
			a.NodeCheckers = map[string]dataplane.NodeChecker{"sing-box": sing, "xray": xray}
			a.nodeReviews.options = func() []routecatalog.Option {
				return []routecatalog.Option{{ID: "sing-box", Installed: true}, {ID: "xray", Installed: true}}
			}
			id := ids[0]
			if kind == "xhttp-auto" || kind == "xhttp-no-consent" || kind == "xhttp-xray" {
				for _, id := range ids {
					if _, err := a.Nodes.SetDisabled(context.Background(), id, true, time.Now()); err != nil {
						t.Fatal(err)
					}
				}
				id = importXHTTPNode(t, a)
			}
			if kind != "xhttp-no-consent" {
				a.autonomy.doc.Policy.PreferredRoutes = []string{"sing-box", "xray"}
			}
			if kind == "ordinary-xray" || kind == "xhttp-xray" {
				readinessWriteConfig(t, a, func(c *config.Config) {
					s := c.Services["my-independent-site"]
					s.Route = "xray:" + id
					c.Services["my-independent-site"] = s
				})
				s := a.autonomy.doc.Services["my-independent-site"]
				s.ExpectedRoute = "xray:" + id
				a.autonomy.doc.Services[s.ID] = s
			}
			a.nodeReadinessRound(context.Background(), start.Add(time.Minute))
			want := "xray"
			if kind == "ordinary-auto" {
				want = "sing-box"
			}
			if kind == "xhttp-no-consent" {
				if sing.count()+xray.count() != 0 {
					t.Fatal("Xray used without AUTO consent")
				}
				return
			}
			if e := readinessEntry(a, id); !e.Ready || e.Engine != want {
				t.Fatalf("selected executor/result mismatch: %+v want %s", e, want)
			}
			if want == "xray" && (xray.count() != 1 || sing.count() != 0) || want == "sing-box" && (sing.count() != 1 || xray.count() != 0) {
				t.Fatal("wrong executor invoked")
			}
		})
	}
}

func TestNodeReadinessRevocationCancelsAndDiscardsLateResult(t *testing.T) {
	for _, kind := range []string{"pause", "source-consent", "node-disabled", "node-deleted", "service-revoke"} {
		t.Run(kind, func(t *testing.T) {
			a, _, _, _, _, start := readinessFixture(t)
			called := 0
			a.NodeChecker = connectivityJobChecker{run: func(ctx context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
				called++
				switch kind {
				case "pause", "source-consent":
					p := autonomy.Clone(a.autonomy.doc.Policy)
					rev := p.Revision
					if kind == "pause" {
						p.Enabled = false
					} else {
						p.SourceIDs = nil
						p.PreferredRoutes = []string{"sing-box"}
					}
					w := httptest.NewRecorder()
					a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": rev, "policy": p, "confirm": "SAVE_AUTONOMY"}))
					if w.Code != 200 {
						t.Fatalf("policy save: %d", w.Code)
					}
					if ctx.Err() != context.Canceled {
						t.Fatal("permission writer did not cancel active checker context")
					}
				case "node-disabled":
					if _, err := a.Nodes.SetDisabled(context.Background(), r.NodeID, true, time.Now()); err != nil {
						t.Fatal(err)
					}
				case "node-deleted":
					if _, err := a.Nodes.Delete(context.Background(), r.NodeID, time.Now()); err != nil {
						t.Fatal(err)
					}
				case "service-revoke":
					w := httptest.NewRecorder()
					a.autonomyEnroll(w, autonomyRequest("POST", "/api/v1/autonomy/services", map[string]any{"service_id": "my-independent-site", "enabled": false, "use_defaults": true, "expected_revision": a.autonomy.doc.Policy.Revision, "confirm": "MANAGE_SERVICE"}))
					if w.Code != 200 {
						t.Fatalf("service revoke: %d %s", w.Code, w.Body.String())
					}
					if ctx.Err() != context.Canceled {
						t.Fatal("service permission writer did not cancel context")
					}
				}
				// A late success from an uncooperative checker must still be refused.
				return readyConnectivity(r), nil
			}}
			a.nodeReadinessRound(context.Background(), start.Add(time.Minute))
			if called != 1 {
				t.Fatal("fixture did not check")
			}
			for _, e := range a.nodeReadiness.entries {
				if e.Ready || e.Failures != 0 || e.Transport != 0 {
					t.Fatalf("revocation accepted/penalized node: %+v", e)
				}
			}
			for _, item := range a.nodeChecks.connectivity {
				if item.ConnectivityReady {
					t.Fatal("late PASS retained in connectivity cache")
				}
			}
		})
	}
}
