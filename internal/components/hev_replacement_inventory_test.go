package components

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestHEVSameVersionUpdateRequiresDifferentIntegrityOwnedBytes(t *testing.T) {
	m, spec, info := hevReleaseFixture(t)
	target := filepath.Join(m.BinDir, spec.Binary)
	if err := os.MkdirAll(m.BinDir, 0700); err != nil {
		t.Fatal(err)
	}
	old := []byte("old owned image")
	next := []byte("new reviewed image")
	sum := sha256.Sum256(next)
	info.PinnedSHA256 = hex.EncodeToString(sum[:])
	m.external = map[string]releaseInfo{spec.ID: info}
	if err := os.WriteFile(target, old, 0755); err != nil {
		t.Fatal(err)
	}
	if err := writeExternalReceipt(target, info.Version, old); err != nil {
		t.Fatal(err)
	}
	view, err := m.externalView(context.Background(), spec, false)
	if err != nil || !view.UpdateAvailable || view.State != "update" || view.InstalledVersion != view.AvailableVersion || view.InstalledVersionSource != "receipt" {
		t.Fatal("same-version changed image hidden", view, err)
	}
	if err := os.WriteFile(target, next, 0755); err != nil {
		t.Fatal(err)
	}
	if err := writeExternalReceipt(target, info.Version, next); err != nil {
		t.Fatal(err)
	}
	view, err = m.externalView(context.Background(), spec, false)
	if err != nil || view.UpdateAvailable {
		t.Fatal("identical pin offered update", view, err)
	}
	if err := os.WriteFile(externalReceiptPath(target), []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	view, _ = m.externalView(context.Background(), spec, false)
	if view.InstalledVersionSource == "receipt" {
		t.Fatal("foreign receipt retained integrity ownership", view)
	}
	views, err := m.listLocked(context.Background(), false, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range views {
		if v.ID == spec.ID && v.CanUpdate {
			t.Fatal("foreign receipt granted update action", v)
		}
	}
}
