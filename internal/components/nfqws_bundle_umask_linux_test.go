//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Only the exact child changes its process umask. The parent's test process
// (including unrelated parallel tests) is never changed. This is actual Linux
// filesystem install/publication/lease coverage with data-only archive bytes;
// it executes no payload, hooks, network command or production path.
func TestNativeManagedNFQWSInstallWithRestrictiveUmask(t *testing.T) {
	const child = "RAZVILKA_TEST_MANAGED_NFQWS_UMASK_CHILD"
	if os.Getenv(child) != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "-test.run=^TestNativeManagedNFQWSInstallWithRestrictiveUmask$", "-test.v")
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, child+"=") {
				command.Env = append(command.Env, value)
			}
		}
		command.Env = append(command.Env, child+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated umask077 regression: %v\n%s", err, output)
		}
		return
	}
	syscall.Umask(0077)
	t.Run("full-install-and-current-lease", func(t *testing.T) {
		manifest, input, _ := bundleFixtureManifest(t, "fixture-umask077")
		manager := bundleFixtureManager(t, input)
		base := manager.nfqwsFixture.path
		baseline, err := os.Lstat(base)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := manager.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
		if err != nil {
			t.Fatal("first install must create its own traversable ancestors despite umask077", err)
		}
		for _, relative := range []string{"releases"} {
			info, err := os.Lstat(filepath.Join(base, relative))
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0755 || manager.trustedManagedNFQWSNode(info) != nil {
				t.Fatal("new ancestor lacks exact public owned mode", relative, info, err)
			}
		}
		for _, relative := range []string{".", "bin", "lua", "blobs"} {
			info, err := os.Lstat(filepath.Join(receipt.GenerationPath, relative))
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0555 {
				t.Fatal("generation or asset directory was not sealed", relative, info, err)
			}
		}
		for _, member := range manifest.Members {
			mode := os.FileMode(0444)
			if member.Destination == "bin/rzv-nfqws2" {
				mode = 0555
			}
			info, err := os.Lstat(filepath.Join(receipt.GenerationPath, member.Destination))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
				t.Fatal("binary/Lua/blob mode was masked", member.Destination, info, err)
			}
		}
		lease, err := manager.AcquireCurrentManagedNFQWSRuntime(context.Background())
		if err != nil {
			t.Fatal("genuine receipt/image filesystem lease refused after install", err)
		}
		if lease.Descriptor().ReceiptID != receipt.TransactionID {
			t.Error("current lease lost installed receipt")
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.verifyManagedNFQWS(context.Background(), receipt.GenerationPath, receipt.ManifestSHA256); err != nil {
			t.Fatal("independent sealed image readback", err)
		}
		end, err := os.Lstat(base)
		if err != nil || !os.SameFile(baseline, end) || baseline.Mode() != end.Mode() || end.Mode().Perm() != 0700 {
			t.Fatal("creation widened its preexisting private fixture boundary", err)
		}
	})
	t.Run("preexisting-private-ancestor-is-not-repaired", func(t *testing.T) {
		manifest, input, _ := bundleFixtureManifest(t, "fixture-private-ancestor")
		manager := bundleFixtureManager(t, input)
		ancestor := filepath.Join(manager.nfqwsFixture.path, "lib")
		if err := os.Mkdir(ancestor, 0755); err != nil {
			t.Fatal(err)
		}
		before, err := os.Lstat(ancestor)
		if err != nil || before.Mode().Perm() != 0700 {
			t.Fatal("child umask did not produce the private existing ancestor", before, err)
		}
		manager.nfqwsReleases = filepath.Join(ancestor, "razvilka", "nfqws2", "releases")
		if _, err := manager.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority()); err == nil {
			t.Fatal("preexisting private ancestor was widened/adopted")
		}
		after, err := os.Lstat(ancestor)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
			t.Fatal("refusal changed existing private ancestor", err)
		}
		for _, absent := range []string{filepath.Join(ancestor, "razvilka"), manager.StateDir} {
			if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("private ancestor refusal created descendants/journal", absent, err)
			}
		}
	})
}
