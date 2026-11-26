package components

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func retainedPackageReadFixture(t *testing.T, state string, schema int) []byte {
	t.Helper()
	doc := updateJournal{ManagedUpdateState: ManagedUpdateState{SchemaVersion: schema, TransactionID: strings.Repeat("a", 32), Component: "nfqws2", Phase: UpdatePrepared, BeforeVersion: "1.0", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}, Package: "nfqws2-keenetic", PackageFile: "nfqws2-keenetic_1.0_arm64.ipk", PackageSHA256: strings.Repeat("b", 64)}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "update-journal", "current.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRetainedManagedUpdateReaderUsesActualBundlePublicationCuts(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "reader-model")
	m := bundleFixtureManager(t, input)
	authority := bundleFixtureAuthority()
	check := authority.Check
	observedPendingReceipt := false
	authority.Check = func(ctx context.Context, id string, sequence, revision uint64, reader int) error {
		if err := check(ctx, id, sequence, revision, reader); err != nil {
			return err
		}
		required, err := RequiredRetainedManagedUpdateReadVersion(ctx, m.StateDir)
		if err != nil || required > reader {
			t.Fatalf("reader refused an actual publication cut under the existing lease: %d %v", required, err)
		}
		if _, err := os.Stat(filepath.Join(m.StateDir, "receipts", managedNFQWSReceiptName)); err == nil {
			root, err := openUpdateRoot(m.updateJournalDir(), false)
			if err != nil {
				return err
			}
			doc, _, err := readUpdateJournal(root)
			_ = root.Close()
			if err != nil {
				return err
			}
			if doc.Phase == UpdateAwaitingLive {
				observedPendingReceipt = true
			}
		}
		return nil
	}
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, authority)
	if err != nil || !observedPendingReceipt {
		t.Fatalf("reader blocked its own receipt-before-archive cut: %v", err)
	}
	required, first, err := InspectRetainedManagedUpdateReadVersion(context.Background(), m.StateDir)
	if err != nil || required != 3 || len(first) != 64 {
		t.Fatal("actual accepted bundle did not require its typed reader", required, err)
	}
	_, second, err := InspectRetainedManagedUpdateReadVersion(context.Background(), m.StateDir)
	if err != nil || first != second {
		t.Fatal("read-only inspection changed retained state", err)
	}
	if _, err := m.RecoverManagedBundle(context.Background(), receipt.TransactionID, "rollback", authority); err != nil {
		t.Fatal(err)
	}
	// Even after exact prior absence is restored, the retained immutable
	// managed archive still prevents an incompatible controller downgrade.
	if required, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), m.StateDir); err != nil || required != 3 {
		t.Fatal("rollback/deleted live receipt discarded retained reader3", required, err)
	}
}

func TestRetainedManagedUpdateReaderRejectsMissingCorruptFutureAndOrphanEvidence(t *testing.T) {
	for _, change := range []string{"missing-archive", "corrupt-archive", "future-current", "foreign-archive-id", "orphan-receipt", "symlink-archive"} {
		t.Run(change, func(t *testing.T) {
			manifest, input, _ := bundleFixtureManifest(t, "reader-negative")
			m := bundleFixtureManager(t, input)
			receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
			if err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(m.updateJournalDir(), receipt.TransactionID, "managed-"+UpdateAcceptedIdle+".json")
			current := filepath.Join(m.updateJournalDir(), "current.json")
			switch change {
			case "missing-archive":
				err = os.Remove(archive)
			case "corrupt-archive":
				err = os.WriteFile(archive, []byte("{}"), 0600)
			case "future-current":
				data, readErr := os.ReadFile(current)
				if readErr != nil {
					t.Fatal(readErr)
				}
				err = os.WriteFile(current, bytes.Replace(data, []byte(`"schema_version":3`), []byte(`"schema_version":4`), 1), 0600)
			case "foreign-archive-id":
				err = os.Rename(filepath.Dir(archive), filepath.Join(m.updateJournalDir(), strings.Repeat("f", 32)))
			case "orphan-receipt":
				err = os.Remove(current)
				if err == nil {
					err = os.Remove(archive)
				}
			case "symlink-archive":
				data, readErr := os.ReadFile(archive)
				if readErr != nil {
					t.Fatal(readErr)
				}
				outside := filepath.Join(t.TempDir(), "archive")
				if err := os.WriteFile(outside, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(archive); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, archive); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if required, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), m.StateDir); err == nil || required != 0 {
				t.Fatal("invalid retained managed metadata became readable", required, err)
			}
		})
	}
}

func TestRetainedManagedUpdateReaderKeepsLegacyFloorAndRejectsDuplicateOrUnknownFields(t *testing.T) {
	ctx := context.Background()
	missing := filepath.Join(t.TempDir(), "absent")
	if required, err := RequiredRetainedManagedUpdateReadVersion(ctx, missing); err != nil || required != ComponentUpdateSchema {
		t.Fatal("absent state changed existing component2 floor", required, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("reader created missing state")
	}
	for _, schema := range []int{1, 2} {
		state := t.TempDir()
		data := retainedPackageReadFixture(t, state, schema)
		if required, err := RequiredRetainedManagedUpdateReadVersion(ctx, state); err != nil || required != ComponentUpdateSchema {
			t.Fatal("known ordinary component record refused", schema, required, err)
		}
		for _, malformed := range [][]byte{
			append(append([]byte{}, data...), []byte(` {}`)...),
			bytes.Replace(data, []byte(`{`), []byte(`{"schema_version":2,`), 1),
			bytes.Replace(data, []byte(`{`), []byte(`{"foreign":true,`), 1),
		} {
			if err := os.WriteFile(filepath.Join(state, "update-journal", "current.json"), malformed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := RequiredRetainedManagedUpdateReadVersion(ctx, state); err == nil {
				t.Fatal("malformed/duplicate record authorized a read capability")
			}
		}
	}
}

func TestRetainedManagedUpdateReaderRejectsForeignJournalRootLayout(t *testing.T) {
	for _, layout := range []string{"file-instead-of-directory", "unknown-current-name"} {
		t.Run(layout, func(t *testing.T) {
			state := t.TempDir()
			journal := filepath.Join(state, "update-journal")
			if layout == "file-instead-of-directory" {
				if err := os.WriteFile(journal, []byte("foreign layout"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				retainedPackageReadFixture(t, state, 2)
				if err := os.Rename(filepath.Join(journal, "current.json"), filepath.Join(journal, "unrecognized-current.json")); err != nil {
					t.Fatal(err)
				}
			}
			if required, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), state); err == nil || required != 0 {
				t.Fatal("foreign journal layout became an absent/legacy reader floor", required, err)
			}
		})
	}
}
