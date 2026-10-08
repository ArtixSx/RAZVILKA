package components

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

// The existing private bundle fixture uses real receipt/journal/filesystem
// producers and a forbidden command runner. Its authority/inactive callbacks
// remain explicit models; this is no native or App/runtime acceptance claim.
// Revision and disk-image observation below use the actual fresh config Store.
func bundleZeroRevisionFixture(t *testing.T) (*Manager, ManagedNFQWSManifest, *config.Store, ManagedNFQWSBundleAuthority) {
	t.Helper()
	manifest, input, _ := bundleFixtureManifest(t, "fixture-cold-zero")
	m := bundleFixtureManager(t, input)
	store, err := config.Load(filepath.Join(filepath.Dir(m.StateDir), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	expected := store.Get()
	if expected.Revision != 0 || !reflect.DeepEqual(expected, config.Default()) {
		t.Fatal("fixture changed actual cold configuration")
	}
	a := bundleFixtureAuthority()
	check := a.Check
	a.Check = func(ctx context.Context, installation string, sequence, revision uint64, reader int) error {
		if revision != expected.Revision || !reflect.DeepEqual(store.Get(), expected) {
			return ErrRecoveryAuthority
		}
		return store.WithRevisionObservation(ctx, revision, func() error {
			// Keep the fixture's installation/epoch/reader checks; translate
			// only its previous fixed revision value to the genuine Store zero.
			return check(ctx, installation, sequence, 7, reader)
		})
	}
	a.Admit = func(ctx context.Context, transaction, installation string, sequence, revision uint64, _ string, begin func() error) error {
		if !bundleHash(transaction, 32) || begin == nil {
			return ErrRecoveryAuthority
		}
		if err := a.Check(ctx, installation, sequence, revision, ManagedNFQWSJournalSchema); err != nil {
			return err
		}
		if err := begin(); err != nil {
			return err
		}
		return a.Check(ctx, installation, sequence, revision, ManagedNFQWSJournalSchema)
	}
	return m, manifest, store, a
}

func bundleZeroRevisionJournalPaths(m *Manager, id string) []string {
	return []string{filepath.Join(m.updateJournalDir(), "current.json"), filepath.Join(m.updateJournalDir(), id, "managed-"+UpdateAcceptedIdle+".json")}
}

func assertBundleZeroRevisionFiles(t *testing.T, m *Manager, receipt ManagedNFQWSBundleReceipt) {
	t.Helper()
	for _, path := range bundleZeroRevisionJournalPaths(m, receipt.TransactionID) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc updateJournal
		if json.Unmarshal(data, &doc) != nil || validateManagedNFQWSJournal(doc) != nil || doc.ManagedNFQWS.Revision != 0 || doc.ManagedNFQWS.Sequence == 0 {
			t.Fatal("actual journal lost zero revision or positive epoch")
		}
		canonical, _ := json.Marshal(doc)
		if !bytes.Equal(bytes.TrimSuffix(data, []byte{'\n'}), canonical) || strings.Count(string(data), `"revision":0`) != 1 {
			t.Fatal("zero revision is not an explicit canonical journal field")
		}
	}
	ctx := context.Background()
	if version, _, err := InspectRetainedManagedUpdateReadVersion(ctx, m.StateDir); err != nil || version != ManagedNFQWSJournalSchema || version <= ComponentUpdateSchema {
		t.Fatal("cold zero record lost schema3 retained reader requirement", version, err)
	}
	if version, err := RequiredRetainedManagedUpdateReadVersion(ctx, m.StateDir); err != nil || version != ManagedNFQWSJournalSchema {
		t.Fatal("required retained reader disagrees on actual zero record", version, err)
	}
	lease, err := m.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		t.Fatal("actual current receipt/terminal archive refused zero", err)
	}
	if lease.Descriptor().ReceiptID != receipt.TransactionID {
		t.Fatal("zero-revision current lease adopted another receipt")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedNFQWSBundleZeroRevisionColdInstallAndCanonicalFiles(t *testing.T) {
	m, manifest, store, authority := bundleZeroRevisionFixture(t)
	before := store.Get()
	settings := filepath.Join(filepath.Dir(m.StateDir), "settings.json")
	beforeBytes, _ := os.ReadFile(settings)
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 0, authority)
	if err != nil || !validManagedNFQWSReceipt(receipt) {
		t.Fatal("actual first installation rejected actual Store zero", err)
	}
	assertBundleZeroRevisionFiles(t, m, receipt)
	afterBytes, _ := os.ReadFile(settings)
	if !reflect.DeepEqual(store.Get(), before) || !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatal("file-only installation edited or bumped cold configuration")
	}
}

func TestManagedNFQWSBundleZeroRevisionRecoveryKeepsOriginalAuthority(t *testing.T) {
	for _, point := range []string{"after:" + UpdatePrepared, "after:nfqws-publish-receipt"} {
		t.Run(point, func(t *testing.T) {
			m, manifest, store, authority := bundleZeroRevisionFixture(t)
			crash := errors.New("zero-revision file publication interrupted")
			m.updateFault = func(actual string) error {
				if actual == point {
					return crash
				}
				return nil
			}
			if _, err := m.InstallManagedBundle(context.Background(), manifest, 0, authority); !errors.Is(err, crash) {
				t.Fatal("zero-revision publication boundary missed", err)
			}
			state, pending, err := m.PendingManagedUpdate()
			if err != nil || !pending || state.TransactionID == "" {
				t.Fatal("actual zero-revision pending record cannot be read", err)
			}
			n := &Manager{StateDir: m.StateDir, nfqwsReleases: m.nfqwsReleases, nfqwsFixture: m.nfqwsFixture, nfqwsPublish: m.nfqwsPublish, Runner: bundleForbiddenRunner{t}}
			wrong := bundleFixtureAuthority() // original fixed revision7 cannot replace actual0
			current := filepath.Join(m.updateJournalDir(), "current.json")
			before, _ := os.ReadFile(current)
			if _, err := n.RecoverManagedBundle(context.Background(), state.TransactionID, "resume", wrong); !errors.Is(err, ErrRecoveryAuthority) {
				t.Fatal("recovery exchanged frozen zero for another revision", err)
			}
			after, _ := os.ReadFile(current)
			if !bytes.Equal(before, after) {
				t.Fatal("refused recovery mutated original journal")
			}
			receipt, err := n.RecoverManagedBundle(context.Background(), state.TransactionID, "resume", authority)
			if err != nil {
				t.Fatal("original zero-revision file recovery refused", err)
			}
			assertBundleZeroRevisionFiles(t, n, receipt)
			if store.Get().Revision != 0 {
				t.Fatal("recovery changed actual Store revision")
			}
		})
	}
}

func TestManagedNFQWSBundleZeroRevisionStillFencesChangedStoreAndEpoch(t *testing.T) {
	for _, fault := range []string{"wrong-expected-revision", "changed-store", "zero-epoch", "foreign-installation", "external-disk-image"} {
		t.Run(fault, func(t *testing.T) {
			m, manifest, store, authority := bundleZeroRevisionFixture(t)
			revision := uint64(0)
			switch fault {
			case "wrong-expected-revision":
				revision = 1
			case "changed-store":
				if err := store.UpdateService("changed", config.ServiceState{Enabled: false, Route: "direct"}); err != nil {
					t.Fatal(err)
				}
			case "zero-epoch":
				authority.Sequence = 0
			case "foreign-installation":
				authority.InstallationID = strings.Repeat("a", 32)
			case "external-disk-image":
				settings := filepath.Join(filepath.Dir(m.StateDir), "settings.json")
				data, err := os.ReadFile(settings)
				if err != nil || os.WriteFile(settings, append(data, '\n'), 0600) != nil {
					t.Fatal("cannot replace fixture disk image", err)
				}
			}
			if _, err := m.InstallManagedBundle(context.Background(), manifest, revision, authority); err == nil {
				t.Fatal("zero revision waived original authority", fault)
			}
			if _, err := os.Stat(m.StateDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused original authority created a component journal", err)
			}
		})
	}
}

func TestManagedNFQWSBundleZeroRevisionMalformedJournalPreserved(t *testing.T) {
	for _, location := range []string{"current", "archive"} {
		for _, replacement := range []string{"", `"revision":null,`, `"revision":0,"revision":0,`, `"revision":-1,`, `"revision":"0",`} {
			t.Run(location+"/"+replacement, func(t *testing.T) {
				m, manifest, _, authority := bundleZeroRevisionFixture(t)
				receipt, err := m.InstallManagedBundle(context.Background(), manifest, 0, authority)
				if err != nil {
					t.Fatal(err)
				}
				index := 0
				if location == "archive" {
					index = 1
				}
				path := bundleZeroRevisionJournalPaths(m, receipt.TransactionID)[index]
				data, err := os.ReadFile(path)
				if err != nil || strings.Count(string(data), `"revision":0,`) != 1 {
					t.Fatal("missing actual canonical zero field", err)
				}
				corrupt := []byte(strings.Replace(string(data), `"revision":0,`, replacement, 1))
				if err := os.WriteFile(path, corrupt, 0600); err != nil {
					t.Fatal(err)
				}
				if _, _, err := InspectRetainedManagedUpdateReadVersion(context.Background(), m.StateDir); err == nil {
					t.Fatal("retained reader admitted missing/null/invalid zero field")
				}
				if _, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), m.StateDir); err == nil {
					t.Fatal("required reader admitted malformed zero field")
				}
				if location == "current" {
					if _, _, err := m.PendingManagedUpdate(); err == nil {
						t.Fatal("current typed reader admitted malformed revision")
					}
				} else if lease, err := m.AcquireCurrentManagedNFQWSRuntime(context.Background()); err == nil {
					_ = lease.Close()
					t.Fatal("actual terminal archive reader admitted malformed revision")
				}
				if _, err := m.RecoverManagedBundle(context.Background(), receipt.TransactionID, "resume", authority); err == nil {
					t.Fatal("recovery admitted malformed current/archive revision")
				}
				after, _ := os.ReadFile(path)
				if !bytes.Equal(after, corrupt) {
					t.Fatal("malformed zero field was repaired/adopted")
				}
			})
		}
	}
}
