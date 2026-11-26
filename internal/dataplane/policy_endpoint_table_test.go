package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyTransportTablesAreReservedSeparately(t *testing.T) {
	seen := map[int]string{}
	for _, spec := range PolicyOwnershipSpecs() {
		if other := seen[spec.Table]; other != "" {
			t.Fatal("duplicate service table", spec, other)
		}
		seen[spec.Table] = spec.Adapter
	}
	want := map[string]int{"warp-wg": 211, "amneziawg": 212, "wireguard": 213}
	for _, spec := range PolicyOwnershipSpecs() {
		if spec.EndpointTable != want[spec.Adapter] {
			t.Fatal("transport coordinates drifted", spec)
		}
		if spec.EndpointTable == 0 {
			continue
		}
		if other := seen[spec.EndpointTable]; other != "" {
			t.Fatal("transport table overlaps another reservation", spec, other)
		}
		seen[spec.EndpointTable] = spec.Adapter
		state := PolicyState{Interface: spec.Interface, Table: spec.Table, PriorityBase: spec.PriorityBase,
			NetworkPolicyGeneration: strings.Repeat("a", 64), NetworkDefault: true,
			Rules:             []PolicyRule{{Source: "192.168.1.0/24", Destination: "0.0.0.0/0", Ingress: "br0", Managed: true}},
			WireGuardEndpoint: &WGEndpointState{Table: spec.EndpointTable}}
		initializePolicyLayout(&state)
		if err := validPolicyLayout(state); err != nil {
			t.Fatal("separate network-policy transport table refused", spec.Adapter, err)
		}
		for _, wrong := range []int{0, spec.Table, 210} {
			state.WireGuardEndpoint.Table = wrong
			if !errors.Is(validPolicyLayout(state), ErrNetworkPolicyAuthority) {
				t.Fatal("network-policy pin may bypass its default", spec.Adapter, wrong)
			}
		}
		// Retained legacy service-table pins keep their existing cleanup shape.
		state.NetworkPolicyGeneration, state.NetworkDefault = "", false
		state.Rules[0].Managed = false
		state.WireGuardEndpoint.Table = spec.Table
		if err := validPolicyLayout(state); err != nil {
			t.Fatal("legacy pin receipt shape was discarded", err)
		}
	}
}

func TestPolicyTransportRouteOwnershipAcceptsOnlyExactNumericSemantics(t *testing.T) {
	for _, family := range []int{4, 6} {
		e := &WGEndpointState{Endpoint: "203.0.113.9:443", Table: 211, Device: "wan0", Gateway: "192.0.2.1", Source: "192.0.2.2", Metric: 1}
		if family == 6 {
			e.Endpoint, e.Gateway, e.Source = "[2001:db8::9]:443", "2001:db8:1::1", "2001:db8:1::2"
		}
		base := fmt.Sprintf("%s via %s dev %s proto static src %s metric 1 onlink", e.prefix(), e.Gateway, e.Device, e.Source)
		for _, protocol := range []string{"static", "4"} {
			for _, scope := range []string{"", " scope global", " scope 0", " scope link", " scope 253"} {
				line := strings.Replace(base, "proto static", "proto "+protocol, 1) + scope
				if !ownsWGEndpointRoute(e, family, line) {
					t.Fatal("exact numeric protocol/scope refused", family, line)
				}
			}
		}
		for _, line := range []string{
			strings.Replace(base, "proto static", "proto boot", 1),
			strings.Replace(base, "proto static", "proto 3", 1),
			strings.Replace(base, "proto static", "proto 04", 1),
			base + " scope 200", base + " scope 254", base + " scope 0253",
			base + " proto 4", base + " linkdown",
		} {
			if ownsWGEndpointRoute(e, family, line) {
				t.Fatal("foreign/ambiguous route explained", family, line)
			}
		}
	}
}

func TestPolicyRouteOwnershipKeepsRetainedTableIdentity(t *testing.T) {
	a, _, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	ctx := context.Background()
	if err := a.Snapshot(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ProfilePath = filepath.Join(t.TempDir(), "client.conf")
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Activate(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	manager := New(t.TempDir())
	if err := manager.Register(a); err != nil {
		t.Fatal(err)
	}
	route := "93.184.216.34 via 192.0.2.1 dev eth0 proto static src 192.0.2.2 metric 1 onlink"
	if !manager.OwnsPolicyRouteInTable("wireguard", 4, 206, route) || manager.OwnsPolicyRouteInTable("wireguard", 4, 213, route) {
		t.Fatal("legacy full receipt explained a pin in a different table")
	}
	if manager.OwnsPolicyRouteInTable("wireguard", 4, 206, route+" linkdown") {
		t.Fatal("table identity admitted a changed pin")
	}
}
