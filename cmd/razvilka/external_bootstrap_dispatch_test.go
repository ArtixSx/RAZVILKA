package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExternalBootstrapOrdinaryDispatcherRequiresOriginalProductionRoots(t *testing.T) {
	base := t.TempDir()
	roots := selfUpdateReadRoots(base)
	before := selfUpdateReadTree(t, base)
	valid := []string{"self-update-bootstrap-old193", strings.Repeat("a", 32), filepath.Join(base, "release.tar.gz"), strings.Repeat("b", 64)}
	for _, test := range []struct {
		args []string
		code int
	}{
		{valid[:1], 2},
		{valid[:3], 2},
		{append(append([]string(nil), valid...), "extra"), 2},
		{[]string{valid[0], "invalid", valid[2], valid[3]}, 2},
		{valid, 3},
	} {
		handled, code := runCommandWithSelfUpdateJournalRoots(test.args, roots)
		if !handled || code != test.code {
			t.Fatal("ordinary Main missed closed bootstrap dispatch", handled, code, test.code)
		}
		if !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
			t.Fatal("refused bootstrap dispatch changed protected files")
		}
	}
}
