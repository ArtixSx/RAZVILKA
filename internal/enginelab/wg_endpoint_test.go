package enginelab

import "testing"

func TestWGEndpointResourcesRequireExactOwnerCallbacks(t *testing.T) {
	rule := "52: from all to 93.184.216.34 fwmark 0x4000000 lookup 206"
	route := "93.184.216.34 via 192.0.2.1 dev eth0 proto static src 192.0.2.2 metric 1 onlink"
	tables := map[string]string{"wireguard|4": route}
	if got := policyConflictsFromStateWithOwner([]string{rule}, tables, nil); len(got) != 2 {
		t.Fatal("unconfirmed WG pin was accepted", got)
	}
	ownRule := func(id string, family int, line string) bool { return id == "wireguard" && family == 4 && line == rule }
	ownRoute := func(id string, family int, line string) bool {
		return id == "wireguard" && family == 4 && line == route
	}
	if got := policyConflictsFromStateWithOwner([]string{rule}, tables, ownRule, ownRoute); len(got) != 0 {
		t.Fatal("confirmed WG pin reported foreign", got)
	}
	if got := policyConflictsFromStateWithOwner([]string{"52: from all blackhole"}, tables, ownRule, ownRoute); len(got) != 1 {
		t.Fatal("foreign endpoint priority accepted", got)
	}
}
