//go:build linux

package app

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNFQWS2HookJournalTrustedEntwareAliasAndNestedSymlink(t *testing.T) {
	home := t.TempDir()
	volume := filepath.Join(home, "volume")
	alias := filepath.Join(home, "opt")
	state := filepath.Join(volume, "razvilka", "state", "dataplane")
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(volume, alias); err != nil {
		t.Fatal(err)
	}
	requested := filepath.Join(alias, "razvilka", "state", "dataplane")
	r, err := openNFQWS2HookJournalAt(requested, alias)
	if err != nil {
		t.Fatal("trusted Entware alias refused", err)
	}
	r.Close()
	other := filepath.Join(home, "other")
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(volume, "razvilka", "state"), filepath.Join(volume, "razvilka", "state-old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(volume, "razvilka", "state")); err != nil {
		t.Fatal(err)
	}
	if r, err := openNFQWS2HookJournalAt(requested, alias); err == nil {
		r.Close()
		t.Fatal("nested symlink admitted")
	}
}

func TestNFQWS2HookJournalWrongPermissionsFailClosed(t *testing.T) {
	a, _, _ := nfqws2HookAppFixture(t)
	if err := os.Chmod(a.Dataplane.StateRoot, 0777); err != nil {
		t.Fatal(err)
	}
	if CheckNFQWS2HookRecovery(a.Dataplane.StateRoot) == nil {
		t.Fatal("unsafe private root admitted")
	}
}

func TestNFQWS2HookJournalFIFORefusesWithoutBlocking(t *testing.T) {
	a, _, _ := nfqws2HookAppFixture(t)
	if err := syscall.Mkfifo(filepath.Join(a.Dataplane.StateRoot, nfqws2HookJournalName), 0600); err != nil {
		t.Fatal(err)
	}
	if CheckNFQWS2HookRecovery(a.Dataplane.StateRoot) == nil {
		t.Fatal("FIFO admitted")
	}
}
