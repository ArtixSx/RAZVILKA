package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func defaultLANDependencyFixture(t *testing.T, family int) (PolicyState, *LANPolicyRuntimePlan, []string) {
	t.Helper()
	p, err := CompileLANPolicyRuntime(strings.Repeat("b", 64), []LANPolicyIngress{
		{SegmentID: "home", Interface: "br0", Sources: []string{"192.168.1.0/24", "fd00:1::/64"}},
		{SegmentID: "guest", Interface: "br1", Sources: []string{"192.168.2.0/24", "fd00:2::/64"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := PolicyState{Table: 213, NetworkPolicyGeneration: p.Generation}
	var lines []string
	for _, rule := range lanPolicyRules(p) {
		if rule.family == family {
			lines = append(lines, rule.line())
		}
	}
	return state, p, lines
}

func defaultDependencyReadRunner(t *testing.T, family int, lines []string) NFQWS2Runner {
	t.Helper()
	return networkCleanupRunner(func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		want := "-N rule show"
		if family == 6 {
			want = "-N -6 rule show"
		}
		if strings.Join(args, " ") != want {
			t.Fatal("negative dependency check attempted a write/other read", args)
		}
		return []byte("0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n" + strings.Join(lines, "\n")), nil
	})
}

func TestPolicyDefaultLANDependencyRequiresFrozenCompleteUniqueGate(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			state, plan, lines := defaultLANDependencyFixture(t, family)
			for _, observed := range [][]string{nil, lines} {
				if err := AssertPolicyDefaultUnreferencedWithLAN(context.Background(), defaultDependencyReadRunner(t, family, observed), "ip", state, family, plan); err != nil {
					t.Fatal("absent or exact complete negative gate refused", err)
				}
			}
			if !errors.Is(AssertPolicyDefaultUnreferenced(context.Background(), defaultDependencyReadRunner(t, family, lines), "ip", state, family), ErrPolicyDefaultReferenced) {
				t.Fatal("legacy check recognized an unbound LAN gate")
			}
			for name, observed := range map[string][]string{
				"anchor alone":    lines[:1],
				"missing anchor":  lines[1:],
				"missing ingress": lines[:2],
				"duplicate":       append(append([]string(nil), lines...), lines[1]),
				"foreign ingress": {lines[0], strings.Replace(lines[1], "br0", "foreign0", 1), lines[2]},
				"changed mask":    {lines[0], strings.Replace(lines[1], "/0x8000000", "/0xffffffff", 1), lines[2]},
				"extra selector":  append(append([]string(nil), lines...), "53: from all fwmark 0x8000000/0x8000000 iif br2 goto 73"),
				"other goto":      append(append([]string(nil), lines...), "54: from all goto 73"),
				"other nop":       append(append([]string(nil), lines...), "74: from all nop"),
				"same table":      append(append([]string(nil), lines...), "40: from all to 203.0.113.9 lookup 213"),
			} {
				t.Run(name, func(t *testing.T) {
					if !errors.Is(AssertPolicyDefaultUnreferencedWithLAN(context.Background(), defaultDependencyReadRunner(t, family, observed), "ip", state, family, plan), ErrPolicyDefaultReferenced) {
						t.Fatal("unknown/partial/remaining dependency ignored")
					}
				})
			}
			for _, bad := range []*LANPolicyRuntimePlan{nil, CloneLANPolicyRuntime(plan)} {
				if bad != nil {
					if bad.Generation == plan.Generation {
						bad.Generation = strings.Repeat("c", 64)
					}
				}
				if !errors.Is(AssertPolicyDefaultUnreferencedWithLAN(context.Background(), defaultDependencyReadRunner(t, family, lines), "ip", state, family, bad), ErrPolicyDefaultReferenced) {
					t.Fatal("missing or changed frozen payload accepted")
				}
			}
			other, err := CompileLANPolicyRuntime(strings.Repeat("c", 64), plan.Ingress)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(AssertPolicyDefaultUnreferencedWithLAN(context.Background(), defaultDependencyReadRunner(t, family, lines), "ip", state, family, other), ErrPolicyDefaultReferenced) {
				t.Fatal("valid but different frozen generation accepted")
			}
		})
	}
}

func TestPolicyDefaultDependencyUnderstandsOtherWGTableWithoutAdoptingIt(t *testing.T) {
	for _, family := range []int{4, 6} {
		address := "203.0.113.9"
		if family == 6 {
			address = "2001:db8::9"
		}
		for _, spec := range PolicyOwnershipSpecs() {
			if spec.EndpointPriority == 0 {
				continue
			}
			for _, table := range []int{spec.Table, spec.EndpointTable} {
				line := fmt.Sprintf("%d: from all to %s fwmark 0x%x/0xffffffff lookup %d", spec.EndpointPriority, address, spec.EndpointMark, table)
				state := PolicyState{Table: 210}
				if err := AssertPolicyDefaultUnreferenced(context.Background(), defaultDependencyReadRunner(t, family, []string{line}), "ip", state, family); err != nil {
					t.Fatal("known other transport table refused", spec.Adapter, family, table, err)
				}
				state.Table = table
				if !errors.Is(AssertPolicyDefaultUnreferenced(context.Background(), defaultDependencyReadRunner(t, family, []string{line}), "ip", state, family), ErrPolicyDefaultReferenced) {
					t.Fatal("same-table transport dependency adopted without immutable pin", line)
				}
				state.Table = 210
				for _, changed := range []string{strings.Replace(line, "/0xffffffff", "/0xff000000", 1), line + " iif br0", strings.Replace(line, "from all", "not from all", 1)} {
					if !errors.Is(AssertPolicyDefaultUnreferenced(context.Background(), defaultDependencyReadRunner(t, family, []string{changed}), "ip", state, family), ErrPolicyDefaultReferenced) {
						t.Fatal("unknown transport syntax admitted", changed)
					}
				}
			}
		}
	}
}
