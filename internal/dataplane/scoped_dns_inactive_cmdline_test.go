package dataplane

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopedDNSInactiveRewrittenCmdlineStillUsesStableExeAndScope(t *testing.T) {
	for _, image := range []string{"other", "other\x00--unrelated=value"} {
		f := newScopedDNSInactiveFixture(t)
		f.process(t, 102, "other")
		writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, "102", "cmdline"), []byte(image))
		if err := f.verify(); err != nil {
			t.Fatal("bounded stable non-controller title refused", err)
		}
	}
	for _, kind := range []string{"named-controller", "same-exe", "scope-flag", "empty-first", "too-many", "oversized", "argv-drift", "exe-drift"} {
		t.Run(kind, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			f.process(t, 102, "other")
			path := filepath.Join(f.proof.procRoot, "102", "cmdline")
			image := "other"
			switch kind {
			case "named-controller":
				image = "razvilka"
			case "same-exe":
				f.proof.sameExecutable = func(string, string) (bool, error) { return true, nil }
			case "scope-flag":
				image = "other\x00--dns-state=" + f.a.InactivitySettingsPath
			case "empty-first":
				image = "\x00other"
			case "too-many":
				image = "other\x00" + strings.Repeat("arg\x00", 256) + "final"
			case "oversized":
				image = strings.Repeat("x", (64<<10)+1)
			case "argv-drift", "exe-drift":
				read := f.proof.readlink
				reads := 0
				f.proof.readlink = func(p string) (string, error) {
					if strings.Contains(p, string(filepath.Separator)+"102"+string(filepath.Separator)) {
						reads++
						if kind == "argv-drift" && reads == 1 {
							writeDNSInactiveFixture(t, path, []byte("changed"))
						}
						if kind == "exe-drift" && reads == 2 {
							return "/opt/bin/changed", nil
						}
					}
					return read(p)
				}
			}
			writeDNSInactiveFixture(t, path, []byte(image))
			if f.verify() == nil {
				t.Fatal("rewrite bypassed ownership, bounded input or bookends")
			}
		})
	}
}

func TestScopedDNSInactiveSelfRewrittenTitleKeepsBookends(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, "101", "cmdline"), []byte("razvilka"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := f.a.verifyDNSRuntimeInactive(ctx, f.proof); err != nil {
		t.Fatal(err)
	}
}
