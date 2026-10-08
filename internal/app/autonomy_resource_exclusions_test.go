package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func autonomyExclusionPolicy() *config.NetworkPolicy {
	return &config.NetworkPolicy{Schema: 2, Revision: 1,
		Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"},
		Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
}

// Test setup loads the strict real config at the SAME path; this supplies no
// runtime source/provider permission and is not a production API operation.
func autonomyExclusionSetup(t *testing.T, a *App, policy *config.NetworkPolicy) {
	t.Helper()
	cfg := a.Store.Get()
	cfg.NetworkPolicy = policy
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := strings.TrimSuffix(a.Store.AutomationStatePath(), ".automation.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	a.Store, err = config.LoadExisting(path)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAutonomyResourceNegativeStopsBeforeCheckAndHistory(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*config.NetworkPolicy)
	}{
		{"manual-service", func(p *config.NetworkPolicy) {
			p.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "service", Value: "my-independent-site"}}}
		}},
		{"manual-domain", func(p *config.NetworkPolicy) {
			p.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "suffix", Value: "example.org"}}}
		}},
		{"auxiliary-negative", func(p *config.NetworkPolicy) {
			p.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "exact", Value: "api.ipify.org"}}}
		}},
		{"accepted-Russian-service", func(p *config.NetworkPolicy) {
			v := &config.AcceptedRussianSnapshot{CatalogID: "reviewed-ru", Revision: 1, Entries: []config.ResourceMatch{{Kind: "service", Value: "my-independent-site"}}}
			v.Digest = config.RussianSnapshotDigest(v)
			p.Russian.Enabled = true
			p.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, RussianSnapshot: v}
		}},
		{"device-identity-unavailable", func(p *config.NetworkPolicy) { p.Clients.ExcludedDeviceIDs = []string{"ps5"} }},
		{"excluded-client-prefix", func(p *config.NetworkPolicy) { p.Clients.ExcludedCIDRs = []string{"192.168.1.0/24"} }},
		{"conditional-device-negative", func(p *config.NetworkPolicy) {
			p.Rules = []config.NetworkRule{{ID: "device-negative", Revision: 1, Kind: "service", Value: "my-independent-site", Action: "direct", Mandatory: true, DeviceIDs: []string{"ps5"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			policy := autonomyExclusionPolicy()
			tc.configure(policy)
			autonomyExclusionSetup(t, a, policy)
			before := a.Store.Get()
			nodesBefore, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			checks := 0
			a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks++
				return dataplane.NodeCheckResult{}, errors.New("must not start")
			})
			a.autonomyRound(context.Background(), time.Now())
			nodesAfter, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil || checks != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(a.Store.Get(), before) || !reflect.DeepEqual(nodesBefore, nodesAfter) {
				t.Fatal("negative resource started checks/history/Apply or changed config", checks, adapter.calls, err)
			}
			wantState := "excluded"
			if tc.name == "conditional-device-negative" {
				wantState = "paused"
			}
			if state := autonomyTestState(a); state.Failures != 0 || len(state.CandidateFailures) != 0 || state.State != wantState {
				t.Fatal("exclusion became a node failure", state.State)
			}
		})
	}
}

func TestAutonomyInactiveServiceIsNotAutomaticallyChecked(t *testing.T) {
	a, _, _ := autonomousIntegrationFixture(t)
	state := a.Store.Get().Services["my-independent-site"]
	state.Enabled = false
	if err := a.Store.UpdateService("my-independent-site", state); err != nil {
		t.Fatal(err)
	}
	checks := 0
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		return dataplane.NodeCheckResult{}, nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if checks != 0 {
		t.Fatal("inactive service was probed")
	}
}

func TestAutonomyClosingNegativeDoesNotRecordCandidateFailure(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	autonomyExclusionSetup(t, a, autonomyExclusionPolicy())
	before, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		manual := []config.ResourceMatch{{Kind: "service", Value: request.Service.ID}}
		if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
			t.Fatal(err)
		}
		return d10Result(request, "sing-box", false), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	after, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || checks != 1 || !reflect.DeepEqual(before, after) || len(adapter.calls) != 0 {
		t.Fatal("closing negative published history or Apply", checks, err)
	}
	state := autonomyTestState(a)
	if state.Failures != 0 || len(state.CandidateFailures) != 0 || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) == "sing-box:"+ids[0] {
		t.Fatal("changed exclusions gave a negative node receipt or route")
	}
}

func TestAutonomyResourceGuardSameRevisionDriftAndOriginalOwner(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	p := a.autonomyPolicy()
	a.autonomy.mu.Lock()
	spec := a.autonomy.doc.Services["my-independent-site"]
	a.autonomy.mu.Unlock()
	service, _ := a.autonomyService(spec.ID)
	cfg := a.Store.Get()
	if a.autonomyResourceGuard(context.Background(), p, spec, cfg, service) == nil {
		t.Fatal("ambient context granted observation")
	}
	ctx, release, err := a.privateExclusiveOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := a.autonomyResourceGuard(ctx, p, spec, cfg, service); err != nil {
		t.Fatal("active primary does not need positive auxiliary entries", err)
	}
	changed := cfg
	changed.NetworkPolicy = autonomyExclusionPolicy()
	changed.NetworkPolicy.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "service", Value: spec.ID}}}
	autonomyExclusionSetup(t, a, changed.NetworkPolicy)
	if a.Store.Get().Revision != cfg.Revision {
		t.Fatal("test must exercise same-revision drift")
	}
	if a.autonomyResourceGuard(ctx, p, spec, cfg, service) == nil {
		t.Fatal("different config with same revision accepted")
	}
	profile, err := stableNodeProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.applyAutonomyRoute(ctx, p, spec, cfg, profile, "sing-box") == nil || len(adapter.calls) != 0 {
		t.Fatal("stale Apply entered adapter")
	}
	if err := a.autonomyResourceGuard(ctx, p, spec, a.Store.Get(), service); err == nil {
		t.Fatal("fresh negative accepted")
	}
	release()
	if err := a.autonomyResourceGuard(context.WithoutCancel(ctx), p, spec, cfg, service); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("released original owner was revived", err)
	}
}

func TestAutonomyResourceCIDRExclusionInsidePositivePrefix(t *testing.T) {
	service := catalog.Service{ID: "owned-site", CIDRs: []string{"93.184.216.0/24"}}
	spec := autonomy.Service{ID: service.ID, Enabled: true, Sources: []string{"192.168.1.50/32"}}
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services[service.ID] = config.ServiceState{Enabled: true}
	policy := autonomyExclusionPolicy()
	policy.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "ip", Value: "93.184.216.99"}}}
	set, err := config.EffectiveResourceExclusions(policy)
	if err != nil {
		t.Fatal(err)
	}
	if autonomyResourceEligibility(context.Background(), cfg, spec, service, set) == nil {
		t.Fatal("narrow negative within positive CIDR was waived")
	}
}

func TestAutonomyResourceInactiveManualStopsBeforeCheck(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	manual := []config.ResourceMatch{{Kind: "service", Value: "my-independent-site"}}
	if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	checks := 0
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		return dataplane.NodeCheckResult{}, errors.New("must not start")
	})
	a.autonomyRound(context.Background(), time.Now())
	if checks != 0 || len(adapter.calls) != 0 || autonomyTestState(a).Failures != 0 {
		t.Fatal("inactive manual exclusion started a check or Apply")
	}
	before := a.Store.Get()
	changed := before
	changed.InactiveResourceExclusions = nil
	if sameAutonomyResourcePolicy(changed, before) {
		t.Fatal("post-publication policy guard ignored inactive exclusions")
	}
}

func TestAutonomyResourceObservationBoundRefusesLargeDefinition(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services["owned-site"] = config.ServiceState{Enabled: true}
	spec := autonomy.Service{ID: "owned-site", Enabled: true, Sources: []string{"192.168.1.50/32"}}
	service := catalog.Service{ID: spec.ID, Domains: make([]string, 257)}
	if err := autonomyResourceEligibility(context.Background(), cfg, spec, service, config.EffectiveExclusionSet{}); !errors.Is(err, errAutonomyResourceIneligible) {
		t.Fatal("oversized closed observation was admitted", err)
	}
}

func TestAutonomyResourceNegativeAllowsPendingRemoval(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	if _, err := a.requestAutonomyRemoval(context.Background(), "my-independent-site", false); err != nil {
		t.Fatal(err)
	}
	manual := []config.ResourceMatch{{Kind: "service", Value: "my-independent-site"}}
	if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	checks := 0
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		return dataplane.NodeCheckResult{}, errors.New("must not start")
	})
	a.autonomyRound(context.Background(), time.Now())
	if a.Store.Get().Services["my-independent-site"].Enabled || checks != 0 || len(adapter.calls) != 0 {
		t.Fatal("exclusion prevented teardown or started a check/Apply")
	}
}

type autonomyResourceRouteProber func(context.Context, catalog.Service, string) testlab.Result

func (p autonomyResourceRouteProber) Probe(ctx context.Context, service catalog.Service, route string) testlab.Result {
	return p(ctx, service, route)
}

func TestAutonomyResourceRouteProbeClosingRefusalDoesNotPublishHistory(t *testing.T) {
	for _, outcome := range []string{"allowed", "negative-edit", "cancel", "foreign-profile", "network-change", "unknown-before"} {
		t.Run(outcome, func(t *testing.T) {
			a, _, _ := autonomousIntegrationFixture(t)
			a.TestLab = testlab.NewRunner()
			profile, err := stableNodeProfile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, release, err := a.privateExclusiveOperation(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			calls := 0
			a.FreshProfile = func(context.Context) (string, error) {
				if outcome == "unknown-before" || outcome == "network-change" && calls != 0 {
					return "network-unknown", nil
				}
				return profile, nil
			}
			a.RouteProber = autonomyResourceRouteProber(func(probeCtx context.Context, service catalog.Service, route string) testlab.Result {
				calls++
				if outcome == "negative-edit" {
					manual := []config.ResourceMatch{{Kind: "service", Value: service.ID}}
					if _, err := a.Store.UpdateResourceExclusions(probeCtx, a.Store.Get(), &manual, nil); err != nil {
						t.Fatal(err)
					}
				}
				if outcome == "cancel" {
					cancel()
				}
				result := confirmedRouteProber{}.Probe(probeCtx, service, route)
				if outcome == "foreign-profile" {
					result.NetworkProfileID = "wan-ffffffffffff"
				}
				return result
			})
			service, _ := a.autonomyService("my-independent-site")
			want := "INCONCLUSIVE"
			if outcome == "allowed" {
				want = "PASS"
			}
			if got := a.autonomyProbeRoute(ctx, service, "direct", profile); got != want {
				t.Fatal("wrong guarded verdict", got, want)
			}
			wantCalls := 1
			if outcome == "unknown-before" {
				wantCalls = 0
			}
			if calls != wantCalls || len(a.TestLab.Snapshot(a.catalogSnapshot()).Current) != 0 {
				t.Fatal("route observation ran before network admission or leaked into history", calls)
			}
		})
	}
}

func TestAutonomyResourceNodeCheckPreservesLowerGuardContext(t *testing.T) {
	a, ids, _ := autonomousIntegrationFixture(t)
	type originalMarker struct{}
	ctx, release, err := a.privateExclusiveOperation(context.WithValue(context.Background(), originalMarker{}, "original-owner"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	checks := 0
	a.NodeChecker = jobNodeChecker(func(checkCtx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		if checkCtx == ctx || checkCtx.Value(originalMarker{}) != "original-owner" {
			t.Fatal("checker lost derived lower guard or original owner context")
		}
		return d10Result(request, "sing-box", true), nil
	})
	p := a.autonomyPolicy()
	a.autonomy.mu.Lock()
	spec := a.autonomy.doc.Services["my-independent-site"]
	a.autonomy.mu.Unlock()
	service, _ := a.autonomyService(spec.ID)
	profile, err := stableNodeProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.checkAutonomyCurrentNode(ctx, p, spec, a.Store.Get(), "sing-box", ids[0], service, profile)
	if err != nil || checks != 1 || !result.Available {
		t.Fatal("guarded node check did not complete", checks, err)
	}
}
