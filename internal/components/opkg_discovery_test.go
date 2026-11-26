package components

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/installpath"
)

func TestOpkgDefaultUsesEntwareDiscovery(t *testing.T) {
	if got, want := New().Opkg, installpath.EntwareOpkg(); got != want {
		t.Fatalf("default %q want %q", got, want)
	}
}

func TestOpkgMissingDefaultCannotRunOrWriteFeeds(t *testing.T) {
	m := newWithOpkg("")
	r := &fakeRunner{output: map[string]string{"list-installed": "warp - 9.9 - foreign firmware package\n", "update": "ok"}}
	m.Runner = r
	root := t.TempDir()
	m.RepoDir = filepath.Join(root, "feeds")
	m.StateDir = filepath.Join(root, "state")
	m.BinDir = filepath.Join(root, "bin")
	installed, available, errText := m.packageInventory(context.Background(), true, false)
	if len(installed) != 0 || len(available) != 0 || errText != "" {
		t.Fatal("invented package inventory", installed, available, errText)
	}
	if _, err := m.Apply(context.Background(), "xray"); err == nil || !strings.Contains(err.Error(), "opkg is not available") {
		t.Fatal("missing package manager accepted", err)
	}
	if _, err := m.run(context.Background(), "update"); err == nil || !strings.Contains(err.Error(), "opkg is not available") {
		t.Fatal("direct package refresh accepted missing executable", err)
	}
	if len(r.calls) != 0 {
		t.Fatal("missing default reached package runner", r.calls)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("missing default wrote feeds/state", entries, err)
	}
}

func TestOpkgExplicitManagerInjectionRemainsAvailable(t *testing.T) {
	m := newWithOpkg("")
	m.Opkg = "explicit-test-package-manager"
	r := &fakeRunner{output: map[string]string{"list-installed": "warp - 1.2 - explicit package\n"}}
	m.Runner = r
	installed, err := m.installedPackageVersions(context.Background())
	if err != nil || installed["warp"] != "1.2" {
		t.Fatal(installed, err)
	}
	if len(r.calls) != 1 || len(r.calls[0]) != 2 || r.calls[0][0] != m.Opkg || r.calls[0][1] != "list-installed" {
		t.Fatal("explicit injection changed", r.calls)
	}
}
