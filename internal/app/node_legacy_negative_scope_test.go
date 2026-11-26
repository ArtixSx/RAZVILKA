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

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Use the existing modeled adapter and real App review/apply, Config Store and
// private Node Store. This tests legacy admission, not native client capability.
func legacyCIDRRecoveryFixture(t *testing.T, fallback bool) (*App, *nodeApplyAdapter, *recoveryChecker, dataplane.Plan, nodestore.NodeGroup) {
	t.Helper()
	ctx := context.Background()
	a, id, adapter := nodeApplyFixture(t)
	a.Catalog.Services[0].Domains = nil
	a.Catalog.Services[0].CIDRs = []string{"8.8.8.0/24"}
	a.Catalog.Services[0].ProbeURL = "https://8.8.8.8/"
	a.Catalog.Services[0].Probes = nil
	review := reviewedNode(t, a, id)
	if response := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", ctx); response.Code != 200 {
		t.Fatalf("initial CIDR apply: %d %s", response.Code, response.Body.String())
	}
	previous, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || len(previous.Routes) != 1 || !reflect.DeepEqual(previous.Routes[0].CIDRs, []string{"8.8.8.0/24"}) {
		t.Fatal("missing committed CIDR fixture", previous, err)
	}
	var group nodestore.NodeGroup
	if fallback {
		snapshot, err := a.Nodes.Import(ctx, nodestore.Source{ID: "reserve", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@reserve.example:443?security=tls", time.Now(), time.Hour, false)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, node := range snapshot.Nodes {
			ids = append(ids, node.ID)
		}
		group, err = a.Nodes.CreateGroup(ctx, "Резерв", "fallback", ids, "", 5*time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// Match the existing autofallback fixture's applied group journal setup.
		if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + group.ID, Sources: previous.Routes[0].Sources}); err != nil {
			t.Fatal(err)
		}
		if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"}); err != nil {
			t.Fatal(err)
		}
		if err := a.Store.ApplyDraft(); err != nil {
			t.Fatal(err)
		}
		previous.Revision, previous.Routes[0].Selected = a.Store.Get().AppliedRevision, "sing-box:"+group.ID
		if err := a.Dataplane.Record(previous); err != nil {
			t.Fatal(err)
		}
	}
	adapter.calls = nil
	a.Dataplane.Adapters["sing-box"] = &observedNodeApplyAdapter{adapter}
	a.FreshProfile = func(context.Context) (string, error) { return recoveryProfile, nil }
	a.Dataplane.FreshProfile = a.FreshProfile
	checker := &recoveryChecker{}
	a.NodeChecker = checker
	return a, adapter, checker, previous, group
}

func saveLegacyNegativeScope(t *testing.T, a *App, kind string) {
	t.Helper()
	before := a.Store.Get()
	if kind == "inactive-ip" {
		// The negative lies within the old positive CIDR but differs from the
		// canary literal. Checking only the probe URL cannot revoke this scope.
		manual := []config.ResourceMatch{{Kind: "ip", Value: "8.8.8.9"}}
		updated, err := a.Store.UpdateResourceExclusions(context.Background(), before, &manual, nil)
		if err != nil || updated.InactiveResourceExclusions == nil || updated.Revision <= before.Revision || updated.AppliedRevision != before.AppliedRevision || !reflect.DeepEqual(updated.AppliedServices, before.AppliedServices) {
			t.Fatal("negative did not preserve the old applied scope", updated, err)
		}
		matched, err := config.ConfigResourceExcluded(updated, config.ResourceTarget{Address: netip.MustParseAddr("8.8.8.9")})
		if err != nil || !matched {
			t.Fatal("actual saved exclusion does not cover the old CIDR", matched, err)
		}
		return
	}
	policy := &config.NetworkPolicy{Schema: 2, Revision: 1,
		Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, ExcludedDeviceIDs: []string{"device-excluded"}, NewDevices: "inherit"},
		Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"},
	}
	if err := config.ValidateAppliedNetworkPolicy(policy); err != nil {
		t.Fatal("invalid excluded-device policy fixture", err)
	}
	before.Revision++
	if kind == "editor-device" {
		before.NetworkPolicy = policy
	} else {
		before.AppliedNetworkPolicy = policy
	}
	// Like installNodeResourcePolicy, load a strictly validated saved config;
	// no policy execution or grant is modeled by installing negative intent.
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	a.Store, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLegacyNodeRecoveryRefusesNewNegativeScopeBeforeProbeOrReapply(t *testing.T) {
	for _, kind := range []string{"inactive-ip", "editor-device", "applied-device"} {
		t.Run(kind, func(t *testing.T) {
			a, adapter, checker, previous, _ := legacyCIDRRecoveryFixture(t, false)
			intent, err := a.nodeRecoveryIntent(context.Background(), previous, recoveryProfile)
			if err != nil {
				t.Fatal("unchanged legacy CIDR scope was already refused", err)
			}
			saveLegacyNegativeScope(t, a, kind)
			before := a.Store.Get()
			if _, err := a.nodeRecoveryIntent(context.Background(), previous, recoveryProfile); !errors.Is(err, errNodeRecoveryReview) {
				t.Fatal("new negative acquired recovery intent", err)
			}
			intent.config = before
			if plan, err := a.buildNodeRecoveryPlan(intent); !errors.Is(err, errNodeRecoveryReview) || plan.Ready {
				t.Fatal("legacy builder restored excluded scope", plan, err)
			}
			release, err := a.Operations.Exclusive(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.recoverAppliedNodes(context.Background(), previous, recoveryProfile)
			release()
			if !errors.Is(err, errNodeRecoveryReview) || len(checker.requests) != 0 || len(adapter.calls) != 0 {
				t.Fatal("excluded legacy scope reached a probe or transaction", err, checker.requests, adapter.calls)
			}
			current, _, err := a.Dataplane.Committed()
			if err != nil || !sameNodeRecoveryPlan(previous, current) || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("refusal changed saved intent or committed scope", err)
			}
		})
	}
}

func TestLegacyNodeAutofallbackRefusesNewNegativeScopeBeforeProbeOrSwitch(t *testing.T) {
	for _, kind := range []string{"inactive-ip", "editor-device", "applied-device"} {
		t.Run(kind, func(t *testing.T) {
			a, adapter, checker, previous, group := legacyCIDRRecoveryFixture(t, true)
			if _, err := a.newNodeAutofallbackIntent(context.Background(), previous, recoveryProfile, group, "telegram"); err != nil {
				t.Fatal("unchanged legacy fallback scope was already refused", err)
			}
			saveLegacyNegativeScope(t, a, kind)
			before := a.Store.Get()
			if _, err := a.newNodeAutofallbackIntent(context.Background(), previous, recoveryProfile, group, "telegram"); !errors.Is(err, errNodeRecoveryReview) {
				t.Fatal("new negative acquired fallback intent", err)
			}
			a.nodeAutofallbackRound(context.Background(), time.Now())
			if len(checker.requests) != 0 || len(adapter.calls) != 0 {
				t.Fatal("excluded legacy scope reached a probe or switch", checker.requests, adapter.calls)
			}
			current, _, err := a.Dataplane.Committed()
			if err != nil || !sameNodeRecoveryPlan(previous, current) || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("refusal changed saved intent or committed scope", err)
			}
		})
	}
}
