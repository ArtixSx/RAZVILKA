package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/security"
)

func applyFixturePolicy(t *testing.T, a *App) config.ServicePolicy {
	t.Helper()
	if err := a.preserveLegacyServicePolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := a.Store.Get().ServicePolicies["telegram"]
	if p.Revision == 0 {
		t.Fatal("legacy fallback policy absent")
	}
	return p
}

func TestServicePolicyAPIReadOnlyScopeCASAndUnsupportedScenario(t *testing.T) {
	a, _, _, adapter, _ := nodeAutofallbackFixture(t, 1)
	before := a.Store.Get()
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/service-policies", nil))
	if w.Code != 200 || !reflect.DeepEqual(a.Store.Get(), before) || len(adapter.calls) != 0 || strings.Contains(w.Body.String(), "vless://") {
		t.Fatalf("policy GET mutation/private leak: %d", w.Code)
	}
	var response struct {
		Policies map[string]servicePolicyView `json:"policies"`
	}
	if json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatal("invalid response")
	}
	p := response.Policies["telegram"].Policy
	p.Mode = "auto"
	p.Enabled = true
	p.Scenario.RequireUDP = true
	body, _ := json.Marshal(map[string]any{"config_revision": before.Revision, "expected_revision": 0, "policy": p, "confirm": "SAVE_SERVICE_POLICY"})
	w = httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/service-policies/telegram", bytes.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "blocked-by-capability") || len(adapter.calls) != 0 {
		t.Fatalf("unsupported policy pretended runtime: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/service-policies/telegram", bytes.NewReader(body)))
	if w.Code != http.StatusConflict {
		t.Fatalf("stale revision accepted: %d", w.Code)
	}
}

func TestServicePolicyAuthenticationPrecedesManualCancellation(t *testing.T) {
	a, _, _, _, _ := nodeAutofallbackFixture(t, 1)
	var err error
	a.Security, err = security.NewGate(strings.Repeat("policy-auth-token", 3))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.reconciler.started = true
	a.reconciler.cancel = cancel
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "http://router.local/api/v1/service-policies/telegram", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://router.local")
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, request)
	if w.Code != http.StatusUnauthorized || ctx.Err() != nil {
		t.Fatal("unauthenticated request reached auto cancellation")
	}
}

func TestServicePolicyPausePinAndSourceRestrictionsPreventProbesAndSwitch(t *testing.T) {
	for _, kind := range []string{"pause", "pin", "source"} {
		t.Run(kind, func(t *testing.T) {
			a, current, _, adapter, _ := nodeAutofallbackFixture(t, 1)
			p := applyFixturePolicy(t, a)
			switch kind {
			case "pause":
				p.Mode = "paused"
			case "pin":
				p.PinnedNodeID = current
				p.PinFallback = false
			case "source":
				p.AllowedSourceIDs = []string{"manual"}
			}
			if _, err := a.Store.UpdateServicePolicy(p, a.Store.Get().Revision, p.Revision); err != nil {
				t.Fatal(err)
			}
			calls := []string{}
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls = append(calls, r.NodeID)
				return autofallbackResult(r, r.NodeID != current), nil
			})
			now := time.Now()
			a.nodeAutofallbackRound(context.Background(), now)
			a.nodeAutofallbackRound(context.Background(), now.Add(time.Minute))
			if len(adapter.calls) != 0 {
				t.Fatal("restricted candidate applied")
			}
			for _, id := range calls {
				if id != current {
					t.Fatal("forbidden reserve dialed")
				}
			}
			if kind == "pause" && len(calls) != 0 {
				t.Fatal("paused service checked")
			}
		})
	}
}

func TestServicePolicyMutationDuringProbeRevokesCommit(t *testing.T) {
	a, _, _, adapter, previous := nodeAutofallbackFixture(t, 1)
	p := applyFixturePolicy(t, a)
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		p.Mode = "paused"
		if _, err := a.Store.UpdateServicePolicy(p, a.Store.Get().Revision, p.Revision); err != nil {
			t.Fatal(err)
		}
		return autofallbackResult(r, true), nil
	})
	a.nodeAutofallbackRound(context.Background(), time.Now())
	committed, _, _ := a.Dataplane.Committed()
	if len(adapter.calls) != 0 || !sameNodeRecoveryPlan(previous, committed) {
		t.Fatal("stale policy committed")
	}
}

func TestServicePolicyMigrationDoesNotAdoptLaterFeedOrGroupGrowth(t *testing.T) {
	a, _, g, _, _ := nodeAutofallbackFixture(t, 1)
	p := applyFixturePolicy(t, a)
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "later-feed", Kind: "community"}, "vless://123e4567-e89b-12d3-a456-426614174000@later.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	newID := ""
	for _, n := range snapshot.Nodes {
		found := false
		for _, o := range n.Origins {
			found = found || o.SourceID == "later-feed"
		}
		if found {
			newID = n.ID
		}
	}
	g.NodeIDs = append(g.NodeIDs, newID)
	if _, err = a.Nodes.UpdateGroup(context.Background(), g, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = a.preserveLegacyServicePolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Store.Get().ServicePolicies["telegram"], p) || policyAllowsNode(p, snapshot, newID, time.Now()) {
		t.Fatal("new feed silently expanded permission")
	}
}
