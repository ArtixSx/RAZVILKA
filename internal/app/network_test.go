package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

type networkChangingProber struct {
	changed *atomic.Bool
	calls   *atomic.Int32
}

func (p networkChangingProber) Probe(ctx context.Context, service catalog.Service, route string) testlab.Result {
	p.calls.Add(1)
	p.changed.Store(true)
	return confirmedRouteProber{}.Probe(ctx, service, route)
}

func TestProbeBatchRejectsUnknownAndChangedNetwork(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{true: "unknown", false: "changed"}[unknown], func(t *testing.T) {
			var changed atomic.Bool
			var calls atomic.Int32
			a := &App{TestLab: testlab.NewRunner(), RouteProber: networkChangingProber{&changed, &calls}, FreshProfile: func(context.Context) (string, error) {
				if unknown {
					return "network-unknown", nil
				}
				if changed.Load() {
					return "wan-222222222222", nil
				}
				return "wan-111111111111", nil
			}}
			cat := catalog.Catalog{Services: []catalog.Service{{ID: "probe", Name: "Probe", ProbeURL: "https://example.com/"}}}
			results, profile, err := a.probeRoutesInCurrentNetwork(context.Background(), cat, []string{"probe"}, []string{"direct"})
			if !errors.Is(err, dataplane.ErrExactNodeNetworkChanged) || len(results) != 0 || profile != "" {
				t.Fatalf("stale batch accepted: profile=%q err=%v", profile, err)
			}
			if unknown && calls.Load() != 0 {
				t.Fatal("unknown network started an authoritative probe")
			}
			if !unknown && calls.Load() == 0 {
				t.Fatal("test did not run a probe")
			}
			if len(a.TestLab.Snapshot(cat).Current) != 0 {
				t.Fatal("rejected batch leaked successful observations into diagnostics")
			}
		})
	}
}

func TestNodePlanBindsProofAndRejectsNetworkChangeDuringBuild(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Add(-time.Second)
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls", now, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Nodes[0].ID
	_, err = store.RecordCheck(context.Background(), id, nodestore.CheckRecord{ProbeID: "node-check-plan", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now, ExpiresAt: now.Add(time.Hour), HTTPStatus: 200}, now)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Nodes: store, FreshProfile: stableNodeProfile, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}}}}}
	cfg := config.Config{Revision: 1, Services: map[string]config.ServiceState{"telegram": {Enabled: true, Route: "sing-box:" + id}}}
	options := []routecatalog.Option{{ID: "sing-box:" + id, Selectable: true, Services: []string{"telegram"}}, {ID: "sing-box", Installed: true, Selectable: true}}
	plan, err := a.buildDataplanePlan(cfg, options)
	if err != nil || plan.NetworkProfileID != "wan-0123456789ab" {
		t.Fatalf("proof not bound: profile=%q err=%v", plan.NetworkProfileID, err)
	}
	calls := 0
	a.FreshProfile = func(context.Context) (string, error) {
		calls++
		if calls > 1 {
			return "wan-222222222222", nil
		}
		return "wan-0123456789ab", nil
	}
	if _, err = a.buildDataplanePlan(cfg, options); !errors.Is(err, dataplane.ErrExactNodeNetworkChanged) {
		t.Fatalf("network change during build accepted: %v", err)
	}
}
