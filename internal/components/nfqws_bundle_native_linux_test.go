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
				journal, err := openUpdateRoot(m.updateJournalDir(), false)
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := readUpdateJournal(journal)
				journal.Close()
				if err != nil || doc.ManagedNFQWS == nil {
					t.Fatal(doc, err)
				}
				if info, err := os.Stat(filepath.Join(m.nfqwsReleases, doc.ManagedNFQWS.Stage)); err != nil || info.Mode().Perm() != 0700 {
					t.Fatal("Stop exposed unpublished stage", info, err)
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

func TestNativeManagedNFQWSPrivateAncestorRefusesWithoutChmod(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	private := filepath.Join(filepath.Dir(m.nfqwsReleases), "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	m.nfqwsReleases = filepath.Join(private, "releases")
	if _, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority()); err == nil {
		t.Fatal("UID drop was allowed across a private ancestor")
	}
	if info, err := os.Stat(private); err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("installer weakened private ancestor permissions", info, err)
	}
	entries, err := os.ReadDir(m.nfqwsReleases)
	if err != nil || len(entries) != 0 {
		t.Fatal("private path acquired staged payload", entries, err)
	}
}

func TestNativeManagedNFQWSPublishedPayloadIsPublicWhileControlsStayPrivate(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := publicManagedNFQWSPath(receipt.GenerationPath); err != nil {
		t.Fatal("published payload is not traversable", err)
	}
	for _, path := range []string{m.updateJournalDir(), filepath.Join(m.StateDir, "receipts")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("control root lost privacy", path, info, err)
		}
	}
	for _, member := range manifest.Members {
		info, err := os.Stat(filepath.Join(receipt.GenerationPath, filepath.FromSlash(member.Destination)))
		if err != nil || info.Mode().Perm()&0004 == 0 || info.Mode().Perm()&0222 != 0 {
			t.Fatal("payload unreadable or mutable by runtime", member.Destination, info, err)
		}
	}
	info, err := os.Stat(filepath.Join(m.StateDir, "receipts", managedNFQWSReceiptName))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("receipt lost privacy", info, err)
	}
}
