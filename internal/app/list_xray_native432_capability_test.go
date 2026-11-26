package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/security"
)

// Reproduces the Router432 fixture/compile boundary with actual authenticated
// HTTP consent, Store, control/ScopeReview, applied inline service, private
// node/source/proof, registered adapter and compiler. Physical/WAN and the
// recorded initial service health remain explicit models; no native PASS.
func TestXrayNative432StandaloneBypassRefusedAndEmptyRulesCompile(t *testing.T) {
	for _, standalone := range []bool{true, false} {
		t.Run(map[bool]string{true: "former-injected-bypass", false: "selected-service-empty-rules"}[standalone], func(t *testing.T) {
			f, service := newSelectedTCPInlineScopeFixture(t)
			if err := f.scope.Close(); err != nil {
				t.Fatal(err)
			}
			state := f.a.Store.Get().Services[service.ID]
			state.Sources = []string{"192.168.1.40/32"}
			if err := f.a.Store.UpdateService(service.ID, state); err != nil {
				t.Fatal(err)
			}
			var err error
			f.a.Security, err = security.NewGate(componentRecoveryToken)
			if err != nil {
				t.Fatal(err)
			}
			before := f.a.Store.Get()
			policy := config.CloneNetworkPolicy(before.NetworkPolicy)
			policy.Rules = nil
			if standalone {
				policy.Rules = []config.NetworkRule{{ID: "qa-selected-tcp", Revision: 1, Kind: "service", Value: service.ID, Action: "bypass"}}
			}
			grant := config.DefaultRouteGrant{Resolved: "xray:" + f.nodeID, ProviderClass: "node", ProviderID: f.nodeID, SourceIDs: []string{"manual"}, SourceKinds: []string{"manual"}, Protocols: []string{"vless"}}
			body := map[string]any{"expected_revision": before.Revision, "expected_policy_revision": before.NetworkPolicy.Revision, "policy": policy, "grants": []config.DefaultRouteGrant{grant}, "confirm": "APPROVE_NETWORK_POLICY"}
			server := httptest.NewServer(f.a.Handler(http.NotFoundHandler()))
			defer server.Close()
			status, data := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL)
			var response struct {
				Approved    bool `json:"approved"`
				LiveApplied bool `json:"live_applied"`
			}
			if status != http.StatusOK || json.Unmarshal(data, &response) != nil || !response.Approved || response.LiveApplied {
				t.Fatal("actual empty/injected-rule consent refused or claimed live apply", status)
			}
			after := f.a.Store.Get()
			if !config.CurrentDefaultRouteScopeConsent(after) || !reflect.DeepEqual(after.Services, before.Services) || !reflect.DeepEqual(after.NetworkPolicy.Clients, before.NetworkPolicy.Clients) || !reflect.DeepEqual(after.NetworkPolicy.Rules, policy.Rules) {
				t.Fatal("consent changed service/device intent")
			}
			listScopeOperation(t, f.a, func(ctx context.Context) {
				consent, err := f.a.ReviewDefaultConsent(ctx, grant.Resolved)
				if err != nil {
					t.Fatal("actual node grant unavailable", err)
				}
				if err := consent.Current(ctx); err != nil {
					t.Fatal(err)
				}
				b := modeledXrayFiniteScope(t, ctx, f)
				r := finiteXraySource(t, ctx, f, b, service.ID)
				p, err := r.prepare(ctx, true)
				if standalone {
					if !errors.Is(err, ErrDefaultRouteCapability) || p != nil || b.boundOnce || b.compilation != nil {
						t.Fatal("former native bypass did not reproduce compiler refusal")
					}
					if !reflect.DeepEqual(f.a.Store.Get(), after) {
						t.Fatal("refused preparation wrote original Store")
					}
					return
				}
				if err != nil || p == nil {
					t.Fatal("actual selected-service path refused", err)
				}
				defer p.close()
				lan := p.compilation.LAN()
				if lan.Mode != dataplane.LANPolicyXraySelectedTCPMode || len(lan.Ingress) != 1 || lan.Ingress[0].Interface != "br0" || lan.Ingress[0].Membership != "mac" || !slices.Equal(lan.Ingress[0].Sources, state.Sources) || !slices.Equal(lan.Ingress[0].IncludedMACs, []string{"02:00:00:00:00:01"}) || !slices.Contains(lan.Ingress[0].ExcludedMACs, "02:00:00:00:00:FF") {
					t.Fatal("empty rules widened selected attachment or dropped known negative")
				}
				var destinations []string
				for _, rule := range p.compilation.rules {
					if rule.ServiceID != service.ID || rule.Route != grant.Resolved || rule.Source.String() != state.Sources[0] || rule.Protocol != "tcp" || rule.FirstPort != 443 || rule.LastPort != 443 {
						t.Fatal("selected service/node/TCP scope changed")
					}
					destinations = append(destinations, rule.Destination.String())
				}
				if !slices.Equal(destinations, service.CIDRs) {
					t.Fatal("finite destination set changed")
				}
				input := (&DefaultRouteExecutor{app: f.a}).input(p.compilation, r.expected)
				if len(input.Routes) != 1 || input.Routes[0].Selected != grant.Resolved || !slices.Equal(input.Routes[0].CIDRs, service.CIDRs) || !slices.Equal(input.Routes[0].Sources, state.Sources) {
					t.Fatal("selected route/source lost in runtime input")
				}
				if err := p.current(ctx); err != nil {
					t.Fatal("original finite binding lost", err)
				}
				if !reflect.DeepEqual(f.a.Store.Get(), after) {
					t.Fatal("preparation applied or rewrote selected service")
				}
			})
		})
	}
}
