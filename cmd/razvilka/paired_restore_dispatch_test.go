package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestPairedRestoreOrdinaryDispatcherPreservesClosedAdmission(t *testing.T) {
	base := t.TempDir()
	roots := selfUpdateReadRoots(base)
	before := selfUpdateReadTree(t, base)
	for _, test := range []struct {
		name string
		args []string
		code int
	}{
		{"missing ID", []string{"self-update-paired-restore"}, 2},
		{"invalid ID", []string{"self-update-paired-restore", "invalid"}, 2},
		{"extra argument", []string{"self-update-paired-restore", strings.Repeat("a", 32), "extra"}, 2},
		{"unreviewed roots", []string{"self-update-paired-restore", strings.Repeat("a", 32)}, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			handled, code := runCommandWithSelfUpdateJournalRoots(test.args, roots)
			if !handled || code != test.code {
				t.Fatal("ordinary dispatcher missed original paired restore admission", handled, code)
			}
			if !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
				t.Fatal("refused dispatch bootstrapped or changed protected state")
			}
		})
	}
}
