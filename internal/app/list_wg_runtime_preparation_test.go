package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestListWGPreparationBindsActualListSourceAndOperation(t *testing.T) {
	f := newListWGSourceFixture(t)
	f.a.Catalog.Services[0].Name = "Listed fixture"
	f.a.Catalog.Services[0].Category = "fixture"
	f.a.Catalog.Services[0].Strategy = []string{"wireguard"}
	// This ownership test performs review, preparation, repeated Input reads and
	// separate post-Close observations in one operation. Each validates durable
	// control and the actual race-instrumented child executable. A five-second
	// fixture budget expires during the final observation on the Linux VM; it
	// is not a production deadline or the behavior asserted by this test.
	listScopeOperationWithin(t, f.a, 30*time.Second, func(ctx context.Context) {
		r, err := f.a.ReviewWGListRuntimeSource(ctx, f.scope, "listed")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		p, err := r.Prepare(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		input, err := p.Input(ctx)
		if err != nil || input.LAN == nil || len(input.Routes) == 0 {
			t.Fatal(input, err)
		}
		for _, route := range input.Routes {
			if route.LogicalServiceID != "listed" || route.Selected != "wireguard" || route.Resolved != "wireguard" || len(route.Ingress) != 1 || len(route.Sources) != 1 || route.NetworkPolicyRole != "override" {
				t.Fatal("list intent widened", route)
			}
			for _, prefix := range route.CIDRs {
				if prefix == "0.0.0.0/0" || prefix == "::/0" {
					t.Fatal("catchall in list preparation")
				}
			}
		}
		if !reflect.DeepEqual(input.LAN, f.scope.bound) {
			t.Fatal("different scope compiled")
		}
		if _, err := p.OperationContext(ctx); err != nil {
			t.Fatal(err)
		}
		copy := &WGListRuntimePreparation{self: p, source: p.source, material: p.material, binding: p.binding, compilation: p.compilation}
		if _, err := copy.Input(ctx); !errors.Is(err, dataplane.ErrWGOperationOwner) {
			t.Fatal("copied preparation accepted", err)
		}
		input.Routes[0].CIDRs[0] = "0.0.0.0/0"
		again, err := p.Input(ctx)
		if err != nil || again.Routes[0].CIDRs[0] == "0.0.0.0/0" {
			t.Fatal("detached intent changed original compilation", err)
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Input(ctx); err == nil {
			t.Fatal("closed preparation survived")
		}
		if err := r.Current(ctx); err != nil {
			t.Fatal("preparation closed caller source", err)
		}
		if _, err := f.scope.Observe(ctx); err != nil {
			t.Fatal("preparation closed caller physical scope", err)
		}
	})
}

func TestListWGPreparationPhaseGuardCannotReviveChangedCatalog(t *testing.T) {
	f := newListWGSourceFixture(t)
	f.a.Catalog.Services[0].Name, f.a.Catalog.Services[0].Category = "Listed fixture", "fixture"
	f.a.Catalog.Services[0].Strategy = []string{"wireguard"}
	listScopeOperation(t, f.a, func(ctx context.Context) {
		r, err := f.a.ReviewWGListRuntimeSource(ctx, f.scope, "listed")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		p, err := r.Prepare(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		operation, err := p.OperationContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.guard(operation); err != nil {
			t.Fatal(err)
		}
		f.a.Catalog.Services[0].CIDRs[0] = "9.9.9.9/32"
		if err := p.guard(operation); err == nil {
			t.Fatal("phase guard lost original catalog")
		}
		f.a.Catalog.Services[0].CIDRs[0] = "1.1.1.0/24"
		if err := p.guard(operation); err == nil {
			t.Fatal("restored catalog revived source authority")
		}
	})
}

func TestListWGPreparationHonorsManualRussianAndEmptyList(t *testing.T) {
	for _, mode := range []string{"manual", "russian", "excluded-service", "allLAN"} {
		t.Run(mode, func(t *testing.T) {
			f := newListWGSourceFixture(t)
			f.a.Catalog.Services[0].Name, f.a.Catalog.Services[0].Category = "Listed fixture", "fixture"
			f.a.Catalog.Services[0].Strategy = []string{"wireguard"}
			listScopeOperation(t, f.a, func(ctx context.Context) {
				policy := config.CloneNetworkPolicy(f.a.Store.Get().NetworkPolicy)
				if mode == "allLAN" {
					policy.Clients.Mode, policy.Clients.DeviceIDs, policy.Clients.NewDevices = "lan_except", nil, "inherit"
				} else {
					negative := []config.ResourceMatch{{Kind: "cidr", Value: "1.1.1.128/25"}}
					patch := config.ResourceExclusionsPatch{Manual: &negative}
					if mode == "excluded-service" {
						negative[0] = config.ResourceMatch{Kind: "service", Value: "listed"}
					}
					if mode == "russian" {
						accepted := &config.AcceptedRussianSnapshot{CatalogID: "ru-fixture", Revision: 1, Entries: negative}
						accepted.Digest = config.RussianSnapshotDigest(accepted)
						enabled := true
						patch = config.ResourceExclusionsPatch{Accepted: accepted, RussianEnabled: &enabled}
					}
					if _, err := f.a.Store.UpdateResourceExclusionsPatch(ctx, f.a.Store.Get(), patch); err != nil {
						t.Fatal(err)
					}
					policy = config.CloneNetworkPolicy(f.a.Store.Get().NetworkPolicy)
				}
				epoch, err := f.a.Operations.ReviewControlEpoch(ctx, f.a.SelfUpdateFiles.ControlRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer epoch.Close()
				ref := epoch.Reference()
				policy.Revision++
				if _, err := f.a.Store.ApproveDefaultRouteConsent(ctx, f.a.Store.Get(), policy, nil, ref.InstallationID, ref.Sequence); err != nil {
					t.Fatal(err)
				}
				if err := f.scope.Close(); err != nil {
					t.Fatal(err)
				}
				f.scope, err = newListScopeBinding(ctx, f.a, f.physical.acquire)
				if err != nil {
					t.Fatal(err)
				}
				defer f.scope.Close()
				r, err := f.a.ReviewWGListRuntimeSource(ctx, f.scope, "listed")
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				p, err := r.Prepare(ctx)
				if mode == "excluded-service" {
					if err == nil || p != nil || f.scope.bound != nil {
						t.Fatal("empty active list acquired WG operation", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				input, err := p.Input(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, route := range input.Routes {
					for _, cidr := range route.CIDRs {
						want := "1.1.1.0/25"
						if mode == "allLAN" {
							want = "1.1.1.0/24"
						}
						if cidr != want {
							t.Fatal("negative or list coverage lost", mode, cidr)
						}
					}
				}
				if mode == "allLAN" && (input.LAN.Ingress[0].Membership != "all" || len(input.LAN.Ingress[0].ExcludedMACs) == 0) {
					t.Fatal("allLAN lost router exclusion")
				}
			})
		})
	}
}
