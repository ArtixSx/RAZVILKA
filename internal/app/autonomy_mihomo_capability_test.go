package app

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestAutonomyMihomoNamesUnsupportedLifetimeWithoutProbingOrReplacing(t *testing.T) {
	for _, mode := range []string{"saved-selection", "applied-selection", "applied-with-auto-draft"} {
		t.Run(mode, func(t *testing.T) {
			a, ids, reserve := autonomousIntegrationFixture(t)
			const id = "my-independent-site"
			sources := []string{"192.168.1.50/32"}
			if mode == "saved-selection" {
				if err := a.Store.UpdateService(id, config.ServiceState{Enabled: true, Route: "mihomo:" + ids[0], Sources: sources}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, _, err := a.Store.ApplyMihomoNodeRouteScopeWithImage(id, ids[0], sources, a.Store.Get().Revision); err != nil {
					t.Fatal(err)
				}
				if mode == "applied-with-auto-draft" {
					if err := a.Store.UpdateService(id, config.ServiceState{Enabled: true, Route: "auto", Sources: sources}); err != nil {
						t.Fatal(err)
					}
				}
			}
			// Enrollment is valid user intent; it must not turn the manual
			// Mihomo lane into a supported automatic monitor or another engine.
			w := httptest.NewRecorder()
			a.autonomyEnroll(w, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", map[string]any{
				"service_id": id, "enabled": true, "use_defaults": true,
				"expected_revision": a.autonomyPolicy().Revision, "confirm": "MANAGE_SERVICE",
			}))
			if w.Code != http.StatusOK {
				t.Fatal("Mihomo service enrollment", w.Code, w.Body.String())
			}
			a.Components = components.New()
			if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
				t.Fatal(err)
			}
			originalAdapter := a.mihomoProbe.adapter
			before := a.Store.Get()
			beforeStatus, err := a.Dataplane.Status()
			if err != nil {
				t.Fatal(err)
			}
			nodesBefore, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			routeChecks, nodeChecks, networkChecks := 0, 0, 0
			a.TestLab = testlab.NewRunner()
			a.RouteProber = autonomyResourceRouteProber(func(ctx context.Context, service catalog.Service, route string) testlab.Result {
				routeChecks++
				result := confirmedRouteProber{}.Probe(ctx, service, route)
				result.RouteConfirmed = false // A finite probe is not the active route.
				return result
			})
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				nodeChecks++
				return autofallbackResult(request, true), nil
			})
			fresh := a.FreshProfile
			a.FreshProfile = func(ctx context.Context) (string, error) { networkChecks++; return fresh(ctx) }
			ctx, release, err := a.scopedRuntimeOperation(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			policy := a.autonomyPolicy()
			spec := a.autonomy.doc.Services[id]
			state := autonomyTestState(a)
			state.NextCheck = time.Now().Add(time.Minute)
			for round := 0; round < 2; round++ {
				result := a.runAutonomyService(ctx, policy, spec, state, time.Now())
				if result.State != "capability-refused" || !strings.Contains(result.Message, "Mihomo") || !strings.Contains(result.Message, "ручн") ||
					strings.Contains(result.Message, "повтор") || result.Failures != state.Failures || !result.CheckedAt.Equal(state.CheckedAt) ||
					!result.NextCheck.Equal(state.NextCheck) || !reflect.DeepEqual(result.Switches, state.Switches) {
					t.Fatalf("unsupported Mihomo was presented as a retryable failure or health: %+v", result)
				}
				state = result
			}
			if routeChecks != 0 || nodeChecks != 0 || networkChecks != 0 || len(reserve.calls) != 0 || len(a.TestLab.Current()) != 0 {
				t.Fatal("unsupported lifecycle consumed probes or attempted fallback", routeChecks, nodeChecks, networkChecks, reserve.calls)
			}
			afterStatus, err := a.Dataplane.Status()
			if err != nil || !reflect.DeepEqual(beforeStatus, afterStatus) || !reflect.DeepEqual(before, a.Store.Get()) ||
				a.mihomoProbe.adapter != originalAdapter || !a.mihomoProbeRegistered() || a.mihomoProbe.liveApply != nil || a.mihomoProbe.liveStop != nil {
				t.Fatal("diagnostic changed the saved route or original Mihomo owner", err)
			}
			nodesAfter, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil || nodesAfter.Generation != nodesBefore.Generation || !reflect.DeepEqual(nodesAfter.Nodes, nodesBefore.Nodes) {
				t.Fatal("diagnostic published node evidence", err)
			}
		})
	}
}

func TestNodeReadinessMihomoDoesNotDemandAnotherEngineOrRevokeEvidence(t *testing.T) {
	for _, mode := range []string{"saved-selection", "applied-with-auto-draft"} {
		t.Run(mode, func(t *testing.T) {
			a, ids, _, checker, _, now := readinessFixture(t)
			ctx := context.Background()
			a.nodeReadinessRound(ctx, now)
			if checker.count() != 1 {
				t.Fatal("fixture did not earn its existing connectivity evidence")
			}
			const id = "my-independent-site"
			sources := []string{"192.168.1.50/32"}
			if mode == "saved-selection" {
				if err := a.Store.UpdateService(id, config.ServiceState{Enabled: true, Route: "mihomo:" + ids[0], Sources: sources}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, _, err := a.Store.ApplyMihomoNodeRouteScopeWithImage(id, ids[0], sources, a.Store.Get().Revision); err != nil {
					t.Fatal(err)
				}
				if err := a.Store.UpdateService(id, config.ServiceState{Enabled: true, Route: "auto", Sources: sources}); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			a.autonomyEnroll(w, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", map[string]any{
				"service_id": id, "enabled": true, "use_defaults": true,
				"expected_revision": a.autonomyPolicy().Revision, "confirm": "MANAGE_SERVICE",
			}))
			if w.Code != http.StatusOK {
				t.Fatal("Mihomo service enrollment", w.Code, w.Body.String())
			}
			before := a.Store.Get()
			priorNodes, err := a.Nodes.Snapshot(ctx, now)
			if err != nil {
				t.Fatal(err)
			}
			priorEntries := maps.Clone(a.nodeReadiness.entries)
			a.nodeReadinessRound(ctx, now.Add(nodeReadinessSpacing+time.Second))
			nextNodes, err := a.Nodes.Snapshot(ctx, now)
			if err != nil || checker.count() != 1 || !reflect.DeepEqual(before, a.Store.Get()) ||
				!reflect.DeepEqual(priorNodes, nextNodes) || !reflect.DeepEqual(priorEntries, a.nodeReadiness.entries) {
				t.Fatal("unsupported Mihomo demanded another engine or changed existing evidence", checker.count(), err)
			}
			// Another service still creates its own demand. A Mihomo selection
			// cannot suppress the permitted pool of Sing-box or Xray services.
			policy, spec := a.autonomyPolicy(), a.autonomy.doc.Services[id]
			definition, _ := a.autonomyService(id)
			definition.ID = "supported-service"
			a.Catalog.Services = append(a.Catalog.Services, definition)
			a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": &readinessChecker{}}
			for _, engine := range []string{"sing-box", "xray"} {
				cfg, supported := a.Store.Get(), spec
				supported.ID, supported.ExpectedRoute = definition.ID, engine
				cfg.Services[supported.ID] = config.ServiceState{Enabled: true, Route: engine, Sources: sources}
				engines, freePool := a.nodeReadinessEngines(policy, cfg, []autonomy.Service{spec, supported})
				if freePool || !reflect.DeepEqual(engines, map[string]bool{engine: true}) {
					t.Fatal("unrelated supported demand changed", engine, engines, freePool)
				}
			}
		})
	}
}
