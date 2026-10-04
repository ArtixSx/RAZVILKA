package app

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestDefaultRouteSharedLANGateBindsMembershipAndGeneration(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	cfg.NetworkPolicy.Clients.NewDevices = "base"
	cfg.NetworkPolicy.Clients.ExcludedDeviceIDs = []string{"excluded"}
	snapshot.Scope.Devices[0].MAC = "02:ab:cd:00:00:01"
	snapshot.Scope.Devices[1].MAC = "02:cd:ab:00:00:02"
	c, err := CompileDefaultRoutePolicy(cfg, snapshot, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	p := c.LAN()
	if err := dataplane.ValidateLANPolicyRuntime(p); err != nil || p.Generation != c.Digest() || len(p.Ingress) != 1 {
		t.Fatal("shared gate does not bind the compiler generation", err)
	}
	g := c.LAN().Ingress[0]
	if g.Interface != "br0" || g.Membership != "mac" || !reflect.DeepEqual(g.IncludedMACs, []string{"02:AB:CD:00:00:01", "02:CD:AB:00:00:02"}) || !reflect.DeepEqual(g.ExcludedMACs, []string{"02:CD:AB:00:00:02"}) ||
		!reflect.DeepEqual(g.Sources, []string{"192.168.1.0/24", "fd00::/64"}) || !reflect.DeepEqual(g.ExcludedSources, []string{"192.168.1.50/32", "fd00::50/128"}) {
		t.Fatal("shared gate lost exact physical/MAC/source boundaries", g)
	}
	if effects, err := p.Effects(); err != nil || len(effects) == 0 {
		t.Fatal("actual shared effect compiler refused reviewed gate", err)
	}
	// Neither the presentation nor the original observation can edit intent.
	p.Ingress[0].IncludedMACs[0] = "02:00:00:00:00:99"
	p.Ingress[0].Sources[0] = "10.0.0.0/8"
	p.Generation = "changed"
	snapshot.Scope.Devices[0].MAC = "02:00:00:00:00:99"
	if err := dataplane.ValidateLANPolicyRuntime(c.LAN()); err != nil || c.LAN().Generation != c.Digest() || !reflect.DeepEqual(c.LAN().Ingress[0], g) {
		t.Fatal("caller changed frozen gate", err)
	}
}

func TestDefaultRouteSharedLANGateRejectsOwnedTunnelIngress(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	iface := dataplane.PolicyOwnershipSpecs()[0].Interface
	snapshot.Scope.Segments[0].Interface = iface
	for i := range snapshot.Scope.Devices {
		snapshot.Scope.Devices[i].Interface = iface
	}
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, nil, now); !errors.Is(err, ErrDefaultRouteCapability) || !errors.Is(err, dataplane.ErrLANPolicyRuntime) {
		t.Fatal("owned tunnel masqueraded as physical LAN", err)
	}
}

func TestDefaultRouteSharedLANGateActualEffectBound(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	cfg.NetworkPolicy.Clients.NewDevices = "base"
	snapshot.Scope.Segments[0].Prefixes = nil
	for i := 0; i < 8; i++ {
		snapshot.Scope.Segments[0].Prefixes = append(snapshot.Scope.Segments[0].Prefixes, netip.MustParsePrefix(fmt.Sprintf("10.0.%d.0/24", i)))
	}
	snapshot.Scope.Devices, snapshot.Devices = nil, nil
	for i := 0; i < 512; i++ {
		snapshot.Scope.Devices = append(snapshot.Scope.Devices, autonomy.DeviceBinding{
			ID: fmt.Sprintf("device-%d", i), MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256), Interface: "br0", SegmentID: "home", Confirmed: true,
		})
	}
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, nil, now); !errors.Is(err, ErrDefaultRouteCapability) || !errors.Is(err, dataplane.ErrLANPolicyRuntime) {
		t.Fatal("actual shared effect capacity was bypassed", err)
	}
}
