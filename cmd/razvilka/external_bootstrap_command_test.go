package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalBootstrapCommandRejectsUnknownInputBeforeProtectedRoots(t *testing.T) {
	if handled, _ := runExternalBootstrapCommand([]string{"status"}, selfUpdateJournalRoots{}); handled {
		t.Fatal("unrelated command intercepted")
	}
	valid := []string{"self-update-bootstrap-old193", strings.Repeat("a", 32), filepath.Join(t.TempDir(), "release.tar.gz"), strings.Repeat("b", 64)}
	for _, args := range [][]string{valid[:1], valid[:2], valid[:3], append(append([]string(nil), valid...), "extra"), {valid[0], strings.Repeat("A", 32), valid[2], valid[3]}, {valid[0], valid[1], "relative.tar.gz", valid[3]}, {valid[0], valid[1], valid[2], strings.Repeat("B", 64)}} {
		if handled, code := runExternalBootstrapCommand(args, selfUpdateJournalRoots{}); !handled || code != 2 {
			t.Fatal("malformed public command did not refuse", code)
		}
	}
	if handled, code := runExternalBootstrapCommand(valid, selfUpdateJournalRoots{}); !handled || code != 3 {
		t.Fatal("public command accepted fixture roots", code)
	}
}
