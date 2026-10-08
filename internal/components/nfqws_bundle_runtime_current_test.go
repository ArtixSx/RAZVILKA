package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedNFQWSCurrentRuntimeUsesInstalledReceiptAfterRestart(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "current-runtime")
	m := bundleFixtureManager(t, input)
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	// A new configured Manager has no caller-supplied receipt ID or DTO. These
	// private fixture hooks model only installation; no process is launched.
	n := &Manager{StateDir: m.StateDir, nfqwsReleases: m.nfqwsReleases, Arch: m.Arch,
		nfqwsReview: m.nfqwsReview, nfqwsFixture: m.nfqwsFixture}
	lease, err := n.AcquireCurrentManagedNFQWSRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := lease.Descriptor(); got.ReceiptID != receipt.TransactionID || got.GenerationPath != receipt.GenerationPath || lease.Check(context.Background()) != nil {
		t.Fatal("current lease did not bind the installed terminal generation", got)
	}
	if _, err := m.AcquireCurrentManagedNFQWSRuntime(context.Background()); err == nil {
		t.Fatal("a second source reader crossed the existing runtime writer lease")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if lease.Check(context.Background()) == nil || lease.Descriptor().ReceiptID != "" {
		t.Fatal("closed current lease remained usable")
	}
	lease, err = n.AcquireCurrentManagedNFQWSRuntime(context.Background())
	if err != nil {
		t.Fatal("closing the lease failed to release its existing writer", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedNFQWSCurrentRuntimeRefusesMissingCorruptAndUnacceptedReceipt(t *testing.T) {
	for _, change := range []string{"missing", "corrupt", "no-terminal", "payload-changed"} {
		t.Run(change, func(t *testing.T) {
			manifest, input, _ := bundleFixtureManifest(t, "current-refusal")
			m := bundleFixtureManager(t, input)
			receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
			if err != nil {
				t.Fatal(err)
			}
			receiptPath := filepath.Join(m.StateDir, "receipts", managedNFQWSReceiptName)
			switch change {
			case "missing":
				err = os.Remove(receiptPath)
			case "corrupt":
				err = os.WriteFile(receiptPath, []byte("{}"), 0600)
			case "no-terminal":
				err = os.Remove(filepath.Join(m.updateJournalDir(), receipt.TransactionID, "managed-"+UpdateAcceptedIdle+".json"))
			case "payload-changed":
				path := filepath.Join(receipt.GenerationPath, filepath.FromSlash(manifest.Members[0].Destination))
				if err = os.Chmod(path, 0600); err == nil {
					err = os.WriteFile(path, []byte("changed"), 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if lease, err := m.AcquireCurrentManagedNFQWSRuntime(context.Background()); err == nil || lease != nil {
				t.Fatal("invalid current source acquired a runtime lease", err)
			}
		})
	}
}

func TestManagedNFQWSCurrentRuntimeRequiresManagerAndLiveContext(t *testing.T) {
	if _, err := (*Manager)(nil).AcquireCurrentManagedNFQWSRuntime(context.Background()); err == nil {
		t.Fatal("nil Manager admitted")
	}
	m := &Manager{}
	if _, err := m.AcquireCurrentManagedNFQWSRuntime(nil); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.AcquireCurrentManagedNFQWSRuntime(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not retained", err)
	}
}
