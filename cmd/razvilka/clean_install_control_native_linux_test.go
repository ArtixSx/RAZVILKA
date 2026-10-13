//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanInstallControlNativeRejectsUninstalledTestImage(t *testing.T) {
	// An ordinary Go test process is not /opt/bin/razvilka. No temp-path
	// substitution exists in the production entry and no epoch may be made.
	ctx, gate := cleanInstallTestContext(t)
	const control = "/opt/razvilka/state/self-update-stop"
	before, beforeErr := os.Lstat(control)
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	sha, err := cleanInstallImageDigest(ctx, self, 128<<20)
	_ = self.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeNativeCleanInstallControl(ctx, gate, sha); err == nil {
		t.Fatal("uninstalled test image issued production control")
	}
	after, afterErr := os.Lstat(control)
	if os.IsNotExist(beforeErr) {
		if !os.IsNotExist(afterErr) {
			t.Fatal("uninstalled process created control")
		}
	} else if beforeErr == nil && (afterErr != nil || !os.SameFile(before, after)) {
		t.Fatal("uninstalled process replaced existing control")
	}
}

func TestCleanInstallControlNativeImageFullDigestAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image")
	raw := []byte("complete owned image model")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	want := sha256.Sum256(raw)
	got, err := cleanInstallImageDigest(context.Background(), file, 128<<20)
	if err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatal("complete image not hashed", err)
	}
	if _, err := cleanInstallImageDigest(context.Background(), file, 1); err == nil {
		t.Fatal("image bound was waived")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cleanInstallImageDigest(ctx, file, 128<<20); err == nil {
		t.Fatal("canceled image check succeeded")
	}
}

func TestCleanInstallControlNativePermissionsRejectWritableAndForeignUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("model"), 0600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(path)
	if cleanInstallProtected(info, true) != (os.Geteuid() == 0) {
		t.Fatal("foreign UID admitted")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Lstat(path)
	if cleanInstallProtected(info, true) || cleanInstallProtected(info, false) {
		t.Fatal("writable image admitted")
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Lstat(link)
	if cleanInstallProtected(info, true) {
		t.Fatal("linked image admitted")
	}
}
