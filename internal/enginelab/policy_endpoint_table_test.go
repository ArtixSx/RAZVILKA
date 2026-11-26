package enginelab

import "testing"

func TestDedicatedTransportTableRequiresExactOwner(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		route := "203.0.113.9 dev rz-wg proto 4 scope 253 src 192.0.2.2 metric 1"
		familyNumber := 4
		rules := []string{"47: from all to 203.0.113.9 lookup 213"}
		if family == "6" {
			familyNumber, route = 6, "2001:db8::9 dev rz-wg proto 4 scope 253 src 2001:db8:1::2 metric 1"
			rules = []string{"", "47: from all to 2001:db8::9 lookup 213"}
		}
		tables := map[string]string{"wireguard|endpoint|" + family: route}
		if got := policyConflictsFromStateWithOwner(rules, tables, nil); len(got) != 2 {
			t.Fatal("same-name interface or non-endpoint priority granted ownership", family, got)
		}
		ownRule := func(id string, f int, line string) bool {
			return id == "wireguard" && f == familyNumber && line == rules[len(rules)-1]
		}
		ownRoute := func(id string, f int, line string) bool {
			return id == "wireguard" && f == familyNumber && line == route
		}
		ownTableRoute := func(id string, f, table int, line string) bool {
			return table == 213 && ownRoute(id, f, line)
		}
		if got := policyConflictsFromStateWithTableOwner(rules, tables, ownRule, ownRoute, ownTableRoute); len(got) != 0 {
			t.Fatal("exact owned transport resources reported foreign", family, got)
		}
		if got := policyConflictsFromStateWithOwner(rules, tables, ownRule, ownRoute); len(got) != 1 {
			t.Fatal("same tuple from an unspecified table explained the transport pin", family, got)
		}
		if got := policyConflictsFromStateWithOwner(rules, tables, ownRule); len(got) != 1 {
			t.Fatal("rule receipt granted route ownership", family, got)
		}
	}
}
