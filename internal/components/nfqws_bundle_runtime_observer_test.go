package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Actual existing journal/files/lease lifetime, with explicitly MODEL payload
// and installer authority. Observer data cannot start a runtime or issue a lease.
func TestManagedNFQWSRuntimeObserverKeepsDescriptorAndWriterExclusion(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "observer-equivalence")
	m := bundleFixtureManager(t, input)
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	before, err := m.ObserveCurrentManagedNFQWSRuntime(context.Background())
	if err != nil || before.ReceiptID != receipt.TransactionID {
		t.Fatal(before, err)
	}
	lease, err := m.AcquireCurrentManagedNFQWSRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	during, err := m.ObserveCurrentManagedNFQWSRuntime(context.Background())
	if err != nil || !reflect.DeepEqual(before, during) || !reflect.DeepEqual(during, lease.Descriptor()) {
		t.Fatal("observer data diverged from original live lease", err)
	}
	if _, err := m.UpdateManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority()); err == nil {
		t.Fatal("read-only observer released runtime writer exclusion")
	}
	if _, err := m.AcquireCurrentManagedNFQWSRuntime(context.Background()); err == nil {
		t.Fatal("read-only observer admitted a second runtime writer")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := m.ObserveCurrentManagedNFQWSRuntime(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("completed generation observation changed", err)
	}
	after.Lua[0].Path = "caller comparison mutation"
	again, err := m.ObserveCurrentManagedNFQWSRuntime(context.Background())
	if err != nil || !reflect.DeepEqual(before, again) {
		t.Fatal("observer returned aliased data", err)
	}
}

func TestManagedNFQWSRuntimeObserverRefusesActualReceiptAndImageFaults(t *testing.T) {
	for _, kind := range []string{"missing-receipt", "corrupt-receipt", "missing-accepted-journal", "changed-payload", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			manifest, input, _ := bundleFixtureManifest(t, "observer-refusal")
			m := bundleFixtureManager(t, input)
			receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "missing-receipt":
				err = os.Remove(filepath.Join(m.StateDir, "receipts", managedNFQWSReceiptName))
			case "corrupt-receipt":
				err = os.WriteFile(filepath.Join(m.StateDir, "receipts", managedNFQWSReceiptName), []byte("{}"), 0600)
			case "missing-accepted-journal":
				err = os.Remove(filepath.Join(m.updateJournalDir(), receipt.TransactionID, "managed-"+UpdateAcceptedIdle+".json"))
			case "changed-payload":
				path := filepath.Join(receipt.GenerationPath, filepath.FromSlash(manifest.Members[0].Destination))
				if err = os.Chmod(path, 0600); err == nil {
					err = os.WriteFile(path, []byte("changed after legitimate install"), 0600)
				}
			case "canceled":
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			value, err := m.ObserveCurrentManagedNFQWSRuntime(ctx)
			if err == nil || !reflect.DeepEqual(value, NFQWSRuntimeDescriptor{}) {
				t.Fatal("unknown source returned a descriptor", value, err)
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				// The original observer's entry guard intentionally returns the
				// bundle sentinel; neither variant may yield positive metadata.
				if !errors.Is(err, ErrManagedNFQWSBundle) {
					t.Fatal(err)
				}
			}
		})
	}
}
