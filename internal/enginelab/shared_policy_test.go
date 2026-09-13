package enginelab

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
)

func TestSharedPolicySlotsRequireExactOwnershipEvenForOwnTable(t *testing.T) {
	for _, spec := range dataplane.PolicyOwnershipSpecs() {
		t.Run(spec.Adapter, func(t *testing.T) {
			if spec.SharedPriorityBase < 60 || spec.SharedPriorityEnd != spec.SharedPriorityBase+1 || spec.SharedPriorityEnd > 69 {
				t.Fatalf("unexpected shared reservation: %+v", spec)
			}
			exclusion := fmt.Sprintf("%d: from 192.168.1.40 to 203.0.113.9 lookup main", spec.SharedPriorityBase)
			service := fmt.Sprintf("%d: from 192.168.1.40 to 198.51.100.20 lookup %d", spec.SharedPriorityEnd, spec.Table)
			lines := []string{exclusion + "\n" + service + "\n", ""}
			conflicts := policyConflictsFromState(lines, nil)
			if len(conflicts) != 2 {
				t.Fatalf("shared own-table rule bypassed ownership: %+v", conflicts)
			}
			for _, conflict := range conflicts {
				if conflict.Kind != "priority" || !conflict.Blocking || len(conflict.Engines) != 1 || conflict.Engines[0] != spec.Adapter || strings.Contains(conflict.SystemUse, "203.0.113.9") || strings.Contains(conflict.SystemUse, "192.168.1.40") {
					t.Fatalf("wrong attribution or private tuple disclosed: %+v", conflict)
				}
			}
			seen := 0
			owns := func(adapter string, family int, line string) bool {
				seen++
				return adapter == spec.Adapter && family == 4 && (line == exclusion || line == service)
			}
			if got := policyConflictsFromStateWithOwner(lines, nil, owns); len(got) != 0 || seen != 2 {
				t.Fatalf("exact rules were not checked independently: calls=%d conflicts=%+v", seen, got)
			}
			report := Report{Engines: []EngineReport{{Status: engine.Status{ID: spec.Adapter, Running: true}}}, Conflicts: conflicts}
			if got := report.ApplyConflicts([]string{spec.Adapter}); len(got) != 2 {
				t.Fatal("running engine hid an unowned early rule")
			}
		})
	}
}

func TestSharedPolicyUnknownActionsAndSelectorsRemainBlocking(t *testing.T) {
	for _, line := range []string{
		"65: from all blackhole",
		"65: from all prohibit",
		"65: from all goto 100",
		"65: unrecognized action",
		"65: from 192.168.1.40 to 198.51.100.20 fwmark 0xffffaaa lookup 203",
		"65: from 192.168.1.40 to 198.51.100.20 lookup 203 suppress_prefixlength 0",
		"065: from 192.168.1.40 to 198.51.100.20 lookup 203",
	} {
		t.Run(line, func(t *testing.T) {
			var received string
			owns := func(adapter string, family int, whole string) bool {
				received = whole
				return adapter == "sing-box" && family == 4 && whole == "65: from 192.168.1.40 to 198.51.100.20 lookup 203"
			}
			conflicts := policyConflictsFromStateWithOwner([]string{line, ""}, nil, owns)
			if len(conflicts) != 1 || !conflicts[0].Blocking || conflicts[0].Engines[0] != "sing-box" || received != line {
				t.Fatalf("unknown/marked early rule was ignored or simplified: received=%q conflicts=%+v", received, conflicts)
			}
		})
	}
}

func TestSharedPolicyInspectionKeepsFamilyAndLegacyBoundaries(t *testing.T) {
	line := "65: from 2001:db8:1::40 to 2001:db8:2::20 lookup 203"
	seenFamily := 0
	owns := func(adapter string, family int, whole string) bool {
		seenFamily = family
		return adapter == "sing-box" && family == 6 && whole == line
	}
	if conflicts := policyConflictsFromStateWithOwner([]string{"0: from all lookup local\n100: from all fwmark 0xffffaaa lookup 4096\n", line}, nil, owns); len(conflicts) != 0 || seenFamily != 6 {
		t.Fatalf("IPv6 ownership/fixed reservations changed: family=%d conflicts=%+v", seenFamily, conflicts)
	}
	legacy := "22000: from all to 198.51.100.20 lookup 203\n22001: from all to 203.0.113.9 lookup main"
	if conflicts := policyConflictsFromState([]string{legacy, ""}, nil); len(conflicts) != 1 || conflicts[0].Value != "22001" {
		t.Fatalf("legacy table/exclusion behavior changed: %+v", conflicts)
	}
}
