package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNFQWSManagedCommandUsesOnlyFixedOwnerRootsAndInvocation(t *testing.T) {
	base, control := t.TempDir(), t.TempDir()
	t.Setenv("RAZVILKA_DATAPLANE_STATE", base)
	t.Setenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE", control)
	id, calls := strings.Repeat("a", 32), 0
	code := runNFQWSManagedProcessCommand([]string{id}, func(gotID, gotState, gotControl string) int {
		calls++
		if gotID != id || gotState != filepath.Join(base, "runtime", "nfqws2") || gotControl != control {
			t.Fatal("helper coordinates differ from registered owner")
		}
		return 7
	})
	if code != 7 || calls != 1 {
		t.Fatal("fixed producer result lost")
	}
	for _, args := range [][]string{nil, {id, "/caller/path"}, {"../escape"}, {strings.Repeat("A", 32)}, {strings.Repeat("a", 31)}} {
		if runNFQWSManagedProcessCommand(args, func(string, string, string) int { t.Fatal("invalid argv reached producer"); return 0 }) != 2 {
			t.Fatal("invalid argv accepted")
		}
	}
	for _, root := range []string{base, control} {
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("early dispatch initialized state/control", err)
		}
	}
}

func TestNFQWSActualEarlyCommandRefusesMissingIntentBeforeDaemonBootstrap(t *testing.T) {
	base, control := t.TempDir(), t.TempDir()
	t.Setenv("RAZVILKA_DATAPLANE_STATE", base)
	t.Setenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE", control)
	for _, args := range [][]string{{"nfqws-managed-process-supervisor"}, {"NFQWS-MANAGED-PROCESS-SUPERVISOR", strings.Repeat("a", 32)}} {
		if handled, code := runCommand(args); !handled || code != 2 {
			t.Fatal("invalid early command fell into daemon startup", handled, code)
		}
	}
	if handled, code := runCommand([]string{"nfqws-managed-process-supervisor", strings.Repeat("a", 32)}); !handled || code != 1 {
		t.Fatal("missing intent reached daemon bootstrap", handled, code)
	}
	for _, root := range []string{base, control} {
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("missing intent created authority/marker", err)
		}
	}
}
