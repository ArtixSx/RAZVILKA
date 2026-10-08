package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

// These are portable source/admission models, with no physical client, runtime
// owner, DNS alias lifetime or native route proof.
func nodeResourceTestStore(t *testing.T, id string) *config.Store {
	t.Helper()
	s, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService(id, config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func installNodeResourcePolicy(t *testing.T, a *App, manual []config.ResourceMatch, russian bool) {
	t.Helper()
	cfg := a.Store.Get()
	cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 2, Revision: 1,
		Clients:    config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"},
		Traffic:    config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"},
		Exclusions: &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: manual},
	}
	if russian {
		cfg.NetworkPolicy.Russian.Enabled = true
		feed := &config.AcceptedRussianSnapshot{CatalogID: "reviewed-ru", Revision: 1, Entries: []config.ResourceMatch{{Kind: "service", Value: "telegram"}}}
		feed.Digest = config.RussianSnapshotDigest(feed)
		cfg.NetworkPolicy.Exclusions.RussianSnapshot = feed
	}
	path := filepath.Join(t.TempDir(), "config.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	a.Store, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNodeResourceAdmissionNegativesWinAndDoNotRecord(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manual   []config.ResourceMatch
		russian  bool
		inactive bool
	}{
		{"service", []config.ResourceMatch{{Kind: "service", Value: "telegram"}}, false, false},
		{"exact", []config.ResourceMatch{{Kind: "exact", Value: "telegram.org"}}, false, false},
		{"suffix", []config.ResourceMatch{{Kind: "suffix", Value: "telegram.org"}}, false, false},
		{"accepted-russian", nil, true, false},
		{"inactive", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, id, _ := nodeApplyFixture(t)
			installNodeResourcePolicy(t, a, tc.manual, tc.russian)
			if tc.inactive {
				state := a.Store.Get().Services["telegram"]
				state.Enabled = false
				if err := a.Store.UpdateService("telegram", state); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			calls := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls++
				return autofallbackResult(r, true), nil
			})
			_, _, err := a.checkAndRecordNode(context.Background(), id, a.Catalog.Services[0], "", 0)
			after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if !errors.Is(err, dataplane.ErrNodeResourceDenied) || calls != 0 || before.Generation != after.Generation {
				t.Fatalf("err=%v calls=%d generation=%d/%d", err, calls, before.Generation, after.Generation)
			}
		})
	}
}

func TestNodeResourceAdmissionClosesRealExclusionRevisionBeforeRecord(t *testing.T) {
	a, id, _ := nodeApplyFixture(t)
	installNodeResourcePolicy(t, a, nil, false)
	before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		manual := []config.ResourceMatch{{Kind: "service", Value: "telegram"}}
		if _, err := a.Store.UpdateResourceExclusions(ctx, a.Store.Get(), &manual, nil); err != nil {
			t.Fatal(err)
		}
		return autofallbackResult(r, true), nil
	})
	result, _, err := a.checkAndRecordNode(context.Background(), id, a.Catalog.Services[0], "", 0)
	after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	if !errors.Is(err, dataplane.ErrNodeResourceDenied) || result.Available || result.Verdict != evidence.VerdictInconclusive || result.EgressIP != "" || before.Generation != after.Generation {
		t.Fatalf("result=%+v err=%v generations=%d/%d", result, err, before.Generation, after.Generation)
	}
}

func TestNodeResourceAdmissionClosesInPlaceDefinitionAndStoreReplacement(t *testing.T) {
	for _, change := range []string{"definition", "owner"} {
		t.Run(change, func(t *testing.T) {
			a, id, _ := nodeApplyFixture(t)
			before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				if change == "definition" {
					a.Catalog.Services[0].Domains[0] = "changed.example"
				} else {
					raw, _ := json.Marshal(a.Store.Get())
					path := filepath.Join(t.TempDir(), "config.json")
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					var err error
					a.Store, err = config.Load(path)
					if err != nil {
						t.Fatal(err)
					}
				}
				return autofallbackResult(r, true), nil
			})
			result, _, err := a.checkAndRecordNode(context.Background(), id, a.Catalog.Services[0], "", 0)
			after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if !errors.Is(err, dataplane.ErrNodeResourceDenied) || result.Available || before.Generation != after.Generation {
				t.Fatal(change, result, err)
			}
		})
	}
}

func TestNodeResourceAdmissionRequiredRecipeAndLiteralDestination(t *testing.T) {
	a, _, _ := nodeApplyFixture(t)
	installNodeResourcePolicy(t, a, []config.ResourceMatch{{Kind: "exact", Value: "required.example"}, {Kind: "cidr", Value: "203.0.113.0/24"}}, false)
	service := a.Catalog.Services[0]
	if err := a.nodeResourceAdmission(context.Background(), a.Store.Get(), service, "allowed.example", netip.MustParseAddr("203.0.113.9")); !errors.Is(err, dataplane.ErrNodeResourceDenied) {
		t.Fatal("excluded literal pin", err)
	}
	service.Probes = []catalog.Probe{{ID: "second", Required: true, URL: "https://required.example/"}}
	a.Catalog.Services[0] = service
	if err := a.nodeResourceAdmission(context.Background(), a.Store.Get(), service, "", netip.Addr{}); !errors.Is(err, dataplane.ErrNodeResourceDenied) {
		t.Fatal("required probe omission", err)
	}
}

func TestNodeResourceAdmissionDoesNotInventSuffixOrPositiveRecipeGrant(t *testing.T) {
	a, _, _ := nodeApplyFixture(t)
	installNodeResourcePolicy(t, a, []config.ResourceMatch{{Kind: "exact", Value: "www.cloudflare.com"}}, false)
	cfg := a.Store.Get()
	if err := a.nodeResourceAdmission(context.Background(), cfg, a.Catalog.Services[0], "api.ipify.org", netip.Addr{}); err != nil {
		t.Fatal("auxiliary diagnostic need not be a client list entry", err)
	}
	if err := a.nodeResourceAdmission(context.Background(), cfg, a.Catalog.Services[0], "sub.www.cloudflare.com", netip.Addr{}); err != nil {
		t.Fatal("exact selector became suffix", err)
	}
	if err := a.nodeResourceAdmission(context.Background(), cfg, a.Catalog.Services[0], "www.cloudflare.com", netip.Addr{}); !errors.Is(err, dataplane.ErrNodeResourceDenied) {
		t.Fatal("excluded auxiliary recipe", err)
	}
	if !reflect.DeepEqual(cfg, a.Store.Get()) {
		t.Fatal("diagnostic observation created permission")
	}
}

func TestNodeResourceAdmissionClassifiesHostingHostnameWithoutAuthorizingRule(t *testing.T) {
	a, _, _ := nodeApplyFixture(t)
	a.Catalog.Services = append(a.Catalog.Services, catalog.Service{ID: "discord", Domains: []string{"discordsays.com", "discordsez.com"}})
	installNodeResourcePolicy(t, a, []config.ResourceMatch{{Kind: "service", Value: "discord"}}, false)
	cfg := a.Store.Get()
	service := a.Catalog.Services[0]
	for _, host := range []string{"api.ipify.org", "notdiscordsays.com", "discordsays.com.attacker.test"} {
		if err := a.nodeResourceAdmission(context.Background(), cfg, service, host, netip.Addr{}); err != nil {
			t.Fatal("unrelated hosting catalog identity blocked observed target", host, err)
		}
	}
	for _, host := range []string{"discordsays.com", "assets.discordsays.com", "discordsez.com"} {
		if err := a.nodeResourceAdmission(context.Background(), cfg, service, host, netip.Addr{}); !errors.Is(err, dataplane.ErrNodeResourceDenied) {
			t.Fatal("known excluded service hostname was not denied", host, err)
		}
	}
	if !reflect.DeepEqual(cfg, a.Store.Get()) {
		t.Fatal("hostname comparison changed current intent")
	}
}

func TestNodeResourceAdmissionExcludedRecoveryAndFallbackStartNoChecks(t *testing.T) {
	a, _, _, checker, previous := nodeRecoveryFixture(t)
	installNodeResourcePolicy(t, a, []config.ResourceMatch{{Kind: "service", Value: "telegram"}}, false)
	if _, err := a.nodeRecoveryIntent(context.Background(), previous, recoveryProfile); err == nil || len(checker.requests) != 0 {
		t.Fatal("old committed recovery ignored current exclusion", err)
	}
	a, _, _, adapter, _ := nodeAutofallbackFixture(t, 1)
	installNodeResourcePolicy(t, a, []config.ResourceMatch{{Kind: "service", Value: "telegram"}}, false)
	calls := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		return autofallbackResult(r, false), nil
	})
	a.nodeAutofallbackRound(context.Background(), time.Now())
	if calls != 0 || len(adapter.calls) != 0 {
		t.Fatal("excluded primary triggered failover", calls, adapter.calls)
	}
}

func TestNodeResourceAdmissionQueuedApplyRefusesNewExclusionBeforeRuntime(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	initReconcilerFixture(t, a, time.Now())
	job := durableNodeAccept(t, a, id, reviewedNode(t, a, id), "node-exclusion-revocation")
	// Install a controlled scoped negative document, then use the real Store
	// CAS for its new revision. The already queued job retains the old review.
	installNodeResourcePolicy(t, a, nil, false)
	manual := []config.ResourceMatch{{Kind: "service", Value: "telegram"}}
	if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	a.runDurableServiceJob(context.Background(), time.Now())
	got := durableJobAt(t, a, job.ID)
	if got.State != "failed" || got.NodeCode != "NODE_REVIEW_CHANGED" || len(adapter.calls) != 0 {
		t.Fatal("stale queued grant reached runtime", got, adapter.calls)
	}
}

func TestNodeResourceAdmissionDisabledAppliedPrimaryIsNotRecoveredOrRetried(t *testing.T) {
	a, _, _, checker, plan := nodeRecoveryFixture(t)
	state := a.Store.Get().Services["telegram"]
	state.Enabled = false
	if err := a.Store.UpdateService("telegram", state); err != nil {
		t.Fatal(err)
	}
	if _, err := a.nodeRecoveryIntent(context.Background(), plan, recoveryProfile); err == nil || len(checker.requests) != 0 {
		t.Fatal("disabled desired service restored from old applied state", err)
	}
	a, _, _, adapter, _ := nodeAutofallbackFixture(t, 1)
	state = a.Store.Get().Services["telegram"]
	state.Enabled = false
	if err := a.Store.UpdateService("telegram", state); err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		return autofallbackResult(r, false), nil
	})
	a.nodeAutofallbackRound(context.Background(), time.Now())
	if calls != 0 || len(adapter.calls) != 0 {
		t.Fatal("disabled primary entered fallback", calls, adapter.calls)
	}
}
