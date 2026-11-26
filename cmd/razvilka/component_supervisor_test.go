package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComponentPrivateSupervisorRejectsUnreviewedInput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "unused-component-root")
	t.Setenv("RAZVILKA_COMPONENT_STATE", root)
	for _, args := range [][]string{
		{"component-package-supervisor"},
		{"component-package-supervisor", "id", "nfqws2"},
		{"component-package-supervisor", "id", "nfqws2", "upgrade", "arbitrary-path"},
		{"component-package-supervisor", "invalid-job-ID", "nfqws2", "upgrade"},
		{"component-package-supervision-probe", "arbitrary-path"},
	} {
		handled, code := runCommand(args)
		if !handled || code == 0 {
			t.Fatalf("unreviewed helper input accepted: %v handled=%t code=%d", args, handled, code)
		}
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("private helper followed the public component directory override", err)
	}
}
