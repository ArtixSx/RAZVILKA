package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestListScopeInfrastructureNegativesAllowActualHomeMembership(t *testing.T) {
	for _, mode := range []string{"all", "mac"} {
		t.Run(mode, func(t *testing.T) {
			// Original Store/control/gate, with the existing explicit physical
			// and compiler path models. This does not claim native execution.
			a, binding, _ := listScopeFixture(t, mode, true)
			listScopeOperation(t, a, func(ctx context.Context) {
				compiled := listScopeCompilation(t, ctx, a, binding)
				gate := compiled.LAN().Ingress[0]
				if !reflect.DeepEqual(gate.ExcludedMACs, []string{"02:00:00:00:00:FF"}) || slices.Contains(gate.IncludedMACs, "02:00:00:00:00:FF") || len(compiled.snapshot.Scope.Devices) != 1 {
					t.Fatal("observed router lost its exclusively negative role", gate)
				}
				if err := binding.BindCompilation(ctx, compiled); err != nil {
					t.Fatal("Home membership with original infrastructure negatives refused", err)
				}
			})
		})
	}
}

func TestListScopeRejectsMissingOrForgedInfrastructureSnapshot(t *testing.T) {
	for _, kind := range []string{"missing", "mac", "address", "flags", "type", "interface", "segment"} {
		t.Run(kind, func(t *testing.T) {
			a, binding, _ := listScopeFixture(t, "all", true)
			listScopeOperation(t, a, func(ctx context.Context) {
				compiled := listScopeCompilation(t, ctx, a, binding)
				neighbor := &compiled.snapshot.Infrastructure[0]
				switch kind {
				case "missing":
					compiled.snapshot.Infrastructure = nil
				case "mac":
					neighbor.MAC = "02:00:00:00:00:fe"
				case "address":
					neighbor.Address = "2001:db8::2"
				case "flags":
					neighbor.Flags = 0
				case "type":
					neighbor.Type++
				case "interface":
					neighbor.Interface = "br1"
				case "segment":
					neighbor.SegmentID = "foreign"
				}
				if err := binding.BindCompilation(ctx, compiled); !errors.Is(err, ErrListScopeChanged) || binding.boundOnce {
					t.Fatal("detached infrastructure image borrowed original scope", err)
				}
			})
		})
	}
}

func TestDefaultRouteInfrastructureDigestCloneAndNegativePrecedence(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	neighbor := DefaultRouteInfrastructureNeighbor{SegmentID: "home", Interface: "br0", Address: "fe80::1", MAC: snapshot.Scope.Devices[0].MAC, Flags: 128, Type: 1}
	snapshot.Infrastructure = []DefaultRouteInfrastructureNeighbor{neighbor}
	compile := func(snapshot DefaultRouteSnapshot) *DefaultRouteCompilation {
		t.Helper()
		compiled, err := CompileDefaultRoutePolicy(cfg, snapshot, defaultRouteListedRoutes(), now)
		if err != nil {
			t.Fatal(err)
		}
		return compiled
	}
	compiled := compile(snapshot)
	if !slices.Contains(compiled.LAN().Ingress[0].ExcludedMACs, strings.ToUpper(neighbor.MAC)) {
		t.Fatal("infrastructure negative omitted for a positive device")
	}
	snapshot.Infrastructure[0].MAC = strings.ToUpper(neighbor.MAC)
	if compile(snapshot).Digest() != compiled.Digest() {
		t.Fatal("equivalent MAC case changed infrastructure identity")
	}
	snapshot.Infrastructure[0].Flags = 0
	if compile(snapshot).Digest() == compiled.Digest() || compiled.snapshot.Infrastructure[0] != neighbor {
		t.Fatal("infrastructure flags escaped digest or caller altered frozen snapshot")
	}
	for _, kind := range []string{"foreign-segment", "foreign-interface", "multicast-mac", "zero-mac", "duplicate-address"} {
		t.Run(kind, func(t *testing.T) {
			candidate := defaultRouteClone(compiled.snapshot)
			switch kind {
			case "foreign-segment":
				candidate.Infrastructure[0].SegmentID = "foreign"
			case "foreign-interface":
				candidate.Infrastructure[0].Interface = "br1"
			case "multicast-mac":
				candidate.Infrastructure[0].MAC = "01:00:00:00:00:01"
			case "zero-mac":
				candidate.Infrastructure[0].MAC = "00:00:00:00:00:00"
			case "duplicate-address":
				candidate.Infrastructure = append(candidate.Infrastructure, candidate.Infrastructure[0])
			}
			if _, err := CompileDefaultRoutePolicy(cfg, candidate, defaultRouteListedRoutes(), now); !errors.Is(err, dataplane.ErrReviewChanged) {
				t.Fatal("ambiguous or invalid infrastructure accepted", err)
			}
		})
	}
}
