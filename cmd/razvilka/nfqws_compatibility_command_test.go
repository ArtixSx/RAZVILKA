package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNFQWSCompatibilityCommandUsesConfiguredOriginalPathsAndIdentityOnly(t *testing.T) {
	base := t.TempDir()
	state, control := filepath.Join(base, "strategy-lab.json"), filepath.Join(base, "control")
	t.Setenv("RAZVILKA_STRATEGY_LAB_STATE", state)
	t.Setenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE", control)
	id := strings.Repeat("a", 32)
	calls := 0
	if code := runNFQWSCompatibilityCommand([]string{id}, func(actualID, actualState, actualControl string) int {
		calls++
		if actualID != id || actualState != state || actualControl != control {
			t.Fatal("helper paths or invocation changed")
		}
		return 71
	}); code != 71 || calls != 1 {
		t.Fatal("actual helper dispatch", code, calls)
	}
	for _, args := range [][]string{nil, {id, state, control}, {"../../command"}, {strings.Repeat("A", 32)}, {strings.Repeat("a", 31)}} {
		if code := runNFQWSCompatibilityCommand(args, func(string, string, string) int { t.Fatal("untrusted argv reached producer"); return 0 }); code != 2 {
			t.Fatal("invalid argv accepted", code)
		}
	}
}

func TestNFQWSCompatibilityCommandRefusesUnconfiguredRelativeOrAmbiguousSource(t *testing.T) {
	for _, state := range []string{"strategy-lab.json", " " + filepath.Join(t.TempDir(), "strategy-lab.json"), filepath.Join(t.TempDir(), "strategy-lab.json") + "\n"} {
		t.Setenv("RAZVILKA_STRATEGY_LAB_STATE", state)
		if code := runNFQWSCompatibilityCommand([]string{strings.Repeat("a", 32)}, func(string, string, string) int { t.Fatal("invalid configured path reached producer"); return 0 }); code != 3 {
			t.Fatal("invalid source spelling accepted", code)
		}
	}
	for _, command := range []string{"NFQWS-COMPATIBILITY-SUPERVISOR", " nfqws-compatibility-supervisor"} {
		if handled, code := runCommand([]string{command, strings.Repeat("a", 32)}); !handled || code != 2 {
			t.Fatal("noncanonical early entry", handled, code)
		}
	}
}
