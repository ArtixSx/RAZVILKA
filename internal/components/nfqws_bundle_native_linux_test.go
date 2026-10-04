//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual Stop lock and actual RENAME_NOREPLACE/receipt rename, entirely in
// TempDir. No binary, upstream hook, process runtime, network or opkg is run.
func TestNativeManagedNFQWSStopBeforeAtomicPublication(t *testing.T) {
	for _, barrier := range []string{"nfqws-publish-generation", "nfqws-publish-receipt"} {
		t.Run(barrier, func(t *testing.T) {
			manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
			m := bundleFixtureManager(t, input)
			control := filepath.Join(filepath.Dir(m.StateDir), "control")
			ready, err := operationgate.InitializeSelfUpdateControl(context.Background(), control)
			if err != nil {
				t.Fatal(err)
			}
			a := bundleFixtureAuthority()
			a.InstallationID, a.Sequence = ready.InstallationID, ready.Sequence
			a.Check = func(ctx context.Context, installation string, sequence, revision uint64, reader int) error {
				current, present, err := operationgate.ReadSelfUpdateStop(ctx, control)
				if err != nil || !present || current.Stopped || current.InstallationID != installation || current.Sequence != sequence || revision != 7 || reader != 3 {
					return errors.Join(ErrRecoveryAuthority, err)
				}
				return nil
			}
			reached, began := false, false
			a.Admit = func(ctx context.Context, transactionID, installation string, sequence, revision uint64, effect string, begin func() error) error {
				if effect == barrier {
					reached = true
					if _, err := operationgate.RequestSelfUpdateStop(ctx, control, transactionID, revision); err != nil {
						return err
					}
				}
				return operationgate.WithSelfUpdateEffectAdmission(ctx, control, transactionID, installation, sequence, effect, func() error {
					if effect == barrier {
						began = true
					}
					return begin()
				})
			}
			if _, err := m.InstallManagedBundle(context.Background(), manifest, 7, a); err == nil || !reached || began {
				t.Fatal("Stop did not fence actual file effect", reached, began, err)
			}
			inventory, err := m.managedNFQWSInventory(false)
			if err != nil {
				t.Fatal(err)
			}
			receipt, _, err := readManagedNFQWSReceipt(inventory)
			inventory.Close()
			if err != nil || receipt != nil {
				t.Fatal("Stop published ready receipt", receipt, err)
			}
			hash, _ := manifest.Digest()
			if barrier == "nfqws-publish-generation" {
				if _, err := os.Stat(filepath.Join(m.nfqwsReleases, hash)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("Stop published generation", err)
				}
			} else if _, err := verifyManagedNFQWS(context.Background(), filepath.Join(m.nfqwsReleases, hash), hash); err != nil {
				t.Fatal("retained complete generation lost", err)
			}
			state, pending, err := m.PendingManagedUpdate()
			if err != nil || !pending || state.SchemaVersion != 3 {
				t.Fatal(state, pending, err)
			}
			if _, err := m.RecoverManagedBundle(context.Background(), state.TransactionID, "resume", a); err == nil {
				t.Fatal("revoked frozen authority resumed")
			}
			after, present, err := operationgate.ReadSelfUpdateStop(context.Background(), control)
			if err != nil || !present || !after.Stopped || after.Sequence != ready.Sequence+1 {
				t.Fatal("cleanup cleared durable Stop", after, err)
			}
		})
	}
}
