package dataplane

import (
	"strings"
	"testing"
	"time"
)

func TestNetworkPolicyManagerNamedWGProfileRevisionSealed(t *testing.T) {
	route := Route{ServiceID: "service", Selected: "wireguard:home", Resolved: "wireguard:home", WireGuardProfileRevision: strings.Repeat("a", 64)}
	before, err := BuildAt(Input{Routes: []Route{route}}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	route.WireGuardProfileRevision = strings.Repeat("b", 64)
	after, err := BuildAt(Input{Routes: []Route{route}}, time.Unix(100, 0))
	if err != nil || before.Digest == after.Digest {
		t.Fatal("profile replacement did not change review", err)
	}
	scoped := before.RoutePlanFor("wireguard")
	got, err := FrozenWireGuardProfileRevision(scoped.Routes[0])
	if err != nil || got != strings.Repeat("a", 64) {
		t.Fatal("scoped revision lost", got, err)
	}
}

func TestNetworkPolicyManagerNamedWGProfileRevisionRefusesWeakMetadata(t *testing.T) {
	for _, route := range []Route{
		{Resolved: "wireguard:home"},
		{Resolved: "wireguard:home", WireGuardProfileRevision: strings.Repeat("A", 64)},
		{Resolved: "wireguard:home", WireGuardProfileRevision: "short"},
		{Resolved: "wireguard:main", WireGuardProfileRevision: strings.Repeat("a", 64)},
		{Resolved: "warp-wg:home", WireGuardProfileRevision: strings.Repeat("a", 64)},
		{Selected: "wireguard:other", Resolved: "wireguard:home", WireGuardProfileRevision: strings.Repeat("a", 64)},
	} {
		if _, err := FrozenWireGuardProfileRevision(route); err == nil {
			t.Fatal("weak profile binding accepted", route)
		}
		if route.WireGuardProfileRevision != "" {
			if _, err := BuildAt(Input{Routes: []Route{route}}, time.Unix(100, 0)); err == nil {
				t.Fatal("malformed provided metadata accepted")
			}
		}
	}
}
