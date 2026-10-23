package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestAutonomyAPIDefaultRoutesAndSavedOptInSurviveReload(t *testing.T) {
	a := autonomyAPIFixture(t)
	read := func() autonomy.Policy {
		t.Helper()
		w := httptest.NewRecorder()
		a.autonomyAPI(w, autonomyRequest("GET", "/api/v1/autonomy", nil))
		var response struct {
			Policy autonomy.Policy `json:"policy"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil {
			t.Fatal("policy read failed", w.Code)
		}
		return response.Policy
	}
	if !slices.Equal(read().PreferredRoutes, []string{"nfqws2", "sing-box", "xray"}) {
		t.Fatal("API did not supply the initial wizard preference")
	}
	p := saveAutonomyFixturePolicy(t, a)
	for _, saved := range [][]string{{"warp-wg", "nfqws2", "usque", "xray"}, {}} {
		p.PreferredRoutes = saved
		w := httptest.NewRecorder()
		a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
		if w.Code != 200 {
			t.Fatal("explicit route preference was refused", w.Code)
		}
		d10Reopen(t, a)
		p = read()
		if !slices.Equal(p.PreferredRoutes, saved) {
			t.Fatal("reload replaced saved route preference")
		}
	}
}

func TestAutonomyDefaultReachesFirstUsableNodeAndWARPRequiresOptIn(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-default", true: "explicit-warp"}[optIn], func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			options := a.nodeReviews.options
			a.nodeReviews.options = func() []routecatalog.Option {
				return append(options(), routecatalog.Option{ID: "warp-wg", Installed: true, Configured: true, Running: true, Selectable: true, Ready: true})
			}
			a.autonomy.mu.Lock()
			a.autonomy.doc.Policy.PreferredRoutes = autonomy.Default().PreferredRoutes
			if optIn {
				a.autonomy.doc.Policy.PreferredRoutes = append([]string{"warp-wg"}, a.autonomy.doc.Policy.PreferredRoutes...)
			}
			err := a.persistAutonomyLocked(context.Background())
			a.autonomy.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			var probed, checked []string
			a.TestLab = testlab.NewRunner()
			a.RouteProber = autonomyResourceRouteProber(func(_ context.Context, service catalog.Service, route string) testlab.Result {
				probed = append(probed, route)
				return testlab.Result{ServiceID: service.ID, Route: route, Status: "not-ready", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
			})
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, req.NodeID)
				return d10Result(req, "sing-box", true), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			r := autonomyTestState(a)
			if r.State != "applied" || !slices.Equal(checked, ids[:1]) || !slices.Contains(adapter.calls, "commit") || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[0] {
				t.Fatal("first usable node was delayed or not applied", r.State, checked, adapter.calls)
			}
			if optIn && !slices.Equal(probed, []string{"warp-wg"}) || !optIn && len(probed) != 0 {
				t.Fatal("WARP preference did not follow explicit opt-in", probed)
			}
		})
	}
}
