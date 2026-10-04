//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
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
			} else if _, err := m.verifyManagedNFQWS(context.Background(), filepath.Join(m.nfqwsReleases, hash), hash); err != nil {
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

func TestNativeManagedNFQWSRejectsUntrustedAncestorsBeforeMkdir(t *testing.T) {
	for _, kind := range []string{"foreign-owner", "group-write", "other-write", "sticky-write"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "foreign-owner" && os.Geteuid() != 0 {
				t.Skip("actual foreign UID fixture requires the coordinator root-euid runner")
			}
			manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
			m := bundleFixtureManager(t, input)
			ancestor := filepath.Join(m.nfqwsFixture.path, "ancestor")
			if err := os.Mkdir(ancestor, 0755); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0755)
			switch kind {
			case "foreign-owner":
				if err := os.Chown(ancestor, 65534, -1); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Chown(ancestor, os.Geteuid(), -1); err != nil {
						t.Error(err)
					}
				}()
			case "group-write":
				mode = 0775
			case "other-write":
				mode = 0777
			case "sticky-write":
				mode = 0777 | os.ModeSticky
			}
			if kind != "foreign-owner" {
				if err := os.Chmod(ancestor, mode); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(ancestor)
			if err != nil {
				t.Fatal(err)
			}
			m.nfqwsReleases = filepath.Join(ancestor, "releases")
			if _, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority()); err == nil {
				t.Fatal("untrusted ancestor was accepted", kind)
			}
			after, err := os.Lstat(ancestor)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Sys().(*syscall.Stat_t).Uid != after.Sys().(*syscall.Stat_t).Uid {
				t.Fatal("refusal changed ancestor identity/owner/mode", before, after, err)
			}
			if _, err := os.Lstat(m.nfqwsReleases); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created below an untrusted ancestor", err)
			}
		})
	}
}

func TestNativeManagedNFQWSFixtureBoundaryIsPrivateAndPinned(t *testing.T) {
	seed := t.TempDir()
	seed, err := filepath.EvalSymlinks(seed)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(seed)
	before, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	_, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	base := m.nfqwsFixture.path
	if filepath.Dir(base) != parent {
		t.Fatal("TempDir parent changed unexpectedly")
	}
	if _, root, err := m.managedNFQWSRoot(true); err != nil {
		t.Fatal(err)
	} else {
		root.Close()
	}
	after, err := os.Lstat(parent)
	info, statErr := os.Lstat(base)
	if err != nil || statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || info.Mode().Perm() != 0700 {
		t.Fatal("fixture relaxed its container or an outside ancestor", before, after, info, err, statErr)
	}
	strict := &Manager{nfqwsReleases: m.nfqwsReleases}
	if _, root, err := strict.managedNFQWSRoot(false); err == nil {
		root.Close()
		t.Fatal("test relocation implicitly bypassed production ownership/traversal")
	}
	if err := m.publicManagedNFQWSPath(parent, false); err == nil {
		t.Fatal("fixture exemption escaped its exact boundary")
	}
	boundary := filepath.Join(base, "pinned")
	if err := os.Mkdir(boundary, 0700); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(boundary)
	if err != nil {
		t.Fatal(err)
	}
	m.nfqwsFixture = &managedNFQWSFixtureBoundary{boundary, original}
	if err := os.Rename(boundary, filepath.Join(base, "retained")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(boundary, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.publicManagedNFQWSPath(filepath.Join(boundary, "releases"), true); err == nil {
		t.Fatal("replacement inode inherited the test exemption")
	}
}

func TestNativeManagedNFQWSProductionOwnerContract(t *testing.T) {
	_, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	info, err := os.Lstat(m.nfqwsFixture.path)
	if err != nil {
		t.Fatal(err)
	}
	strict := &Manager{}
	err = strict.trustedManagedNFQWSNode(info)
	if (os.Geteuid() == 0) != (err == nil) {
		t.Fatal("production did not require both root-euid and root ownership", os.Geteuid(), err)
	}
	if m.trustedManagedNFQWSNode(info) != nil {
		t.Fatal("explicit private fixture did not accept its own euid")
	}
}

func TestNativeManagedNFQWSForeignAssetInvalidatesLease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual foreign UID fixture requires the coordinator root-euid runner")
	}
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := m.AcquireManagedNFQWSRuntime(context.Background(), receipt.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	asset := lease.Descriptor().Lua[0].Path
	if err := os.Chown(asset, 65534, -1); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chown(asset, os.Geteuid(), -1); err != nil {
			t.Error(err)
		}
	}()
	if lease.Check(context.Background()) == nil || lease.Close() == nil {
		t.Fatal("foreign owner retained acceptance through unchanged hashes/modes")
	}
	info, err := os.Lstat(asset)
	if err != nil || info.Mode().Perm() != 0444 || info.Sys().(*syscall.Stat_t).Uid != 65534 {
		t.Fatal("refusal chmod'ed/chown'ed the foreign asset", info, err)
	}
}

// The fault is inside real chmod -> RENAME_NOREPLACE. Recovery uses another
// Manager and the retained exact journal; no downloader/runtime replay occurs.
func TestNativeManagedNFQWSSealedStageCrashCut(t *testing.T) {
	for _, kind := range []string{"resume", "wrong-mode", "corrupt", "foreign-owner", "stop", "cancel", "prepared"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "foreign-owner" && os.Geteuid() != 0 {
				t.Skip("actual foreign UID fixture requires the coordinator root-euid runner")
			}
			manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
			m := bundleFixtureManager(t, input)
			cut := "after:bundle-stage-chmod"
			if kind == "prepared" {
				cut = "after:" + UpdatePrepared
			}
			crash := errors.New("chmod/rename crash cut")
			m.updateFault = func(point string) error {
				if point == cut {
					return crash
				}
				return nil
			}
			a := bundleFixtureAuthority()
			stopReached := false
			if kind == "stop" {
				control := filepath.Join(m.nfqwsFixture.path, "stop-control")
				ready, err := operationgate.InitializeSelfUpdateControl(context.Background(), control)
				if err != nil {
					t.Fatal(err)
				}
				a.InstallationID, a.Sequence = ready.InstallationID, ready.Sequence
				a.Check = func(ctx context.Context, installation string, sequence, revision uint64, reader int) error {
					current, present, err := operationgate.ReadSelfUpdateStop(ctx, control)
					if err != nil || !present || current.Stopped || current.InstallationID != installation || current.Sequence != sequence || revision != 7 || reader != 3 {
						return errors.Join(ErrRecoveryAuthority, err)
					}
					return nil
				}
				a.Admit = func(ctx context.Context, transactionID, installation string, sequence, _ uint64, effect string, begin func() error) error {
					return operationgate.WithSelfUpdateEffectAdmission(ctx, control, transactionID, installation, sequence, effect, begin)
				}
				// Install reaches the crash cut with actual frozen control identity.
				defer func() {
					current, present, err := operationgate.ReadSelfUpdateStop(context.Background(), control)
					if err != nil || !present || !current.Stopped || current.Sequence != ready.Sequence+1 || !stopReached {
						t.Error("resumed rename did not preserve actual durable Stop", current, present, stopReached, err)
					}
				}()
			}
			if _, err := m.InstallManagedBundle(context.Background(), manifest, 7, a); !errors.Is(err, crash) {
				t.Fatal("real cut missed", err)
			}
			journal, err := openUpdateRoot(m.updateJournalDir(), false)
			if err != nil {
				t.Fatal(err)
			}
			doc, _, err := readUpdateJournal(journal)
			journal.Close()
			if err != nil || doc.ManagedNFQWS == nil || (kind != "prepared" && doc.Phase != UpdateStarted) {
				t.Fatal(doc, err)
			}
			stage := filepath.Join(m.nfqwsReleases, doc.ManagedNFQWS.Stage)
			if kind == "prepared" {
				if err := os.Chmod(stage, 0555); err != nil {
					t.Fatal(err)
				}
			}
			if info, err := os.Lstat(stage); err != nil || info.Mode().Perm() != 0555 {
				t.Fatal("cut did not retain sealed stage", info, err)
			}
			if _, err := os.Lstat(doc.ManagedNFQWS.After.GenerationPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cut published generation", err)
			}
			if _, err := os.Lstat(filepath.Join(m.StateDir, "receipts", managedNFQWSReceiptName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cut published ready inventory", err)
			}
			ctx := context.Background()
			switch kind {
			case "wrong-mode":
				if err := os.Chmod(stage, 0755); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				asset := filepath.Join(stage, "lua/zapret-lib.lua")
				if err := os.Chmod(asset, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(asset, []byte("third bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(asset, 0444); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				if err := os.Chown(stage, 65534, -1); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Chown(stage, os.Geteuid(), -1); err != nil {
						t.Error(err)
					}
				}()
			case "stop":
				control := filepath.Join(m.nfqwsFixture.path, "stop-control")
				// Use actual Stop admission at the resumed rename boundary.
				a.Admit = func(ctx context.Context, transactionID, installation string, sequence, revision uint64, effect string, begin func() error) error {
					stopReached = true
					if _, err := operationgate.RequestSelfUpdateStop(ctx, control, transactionID, revision); err != nil {
						return err
					}
					return operationgate.WithSelfUpdateEffectAdmission(ctx, control, transactionID, installation, sequence, effect, begin)
				}
			case "cancel":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			before, err := os.ReadFile(filepath.Join(m.updateJournalDir(), "current.json"))
			if err != nil {
				t.Fatal(err)
			}
			stageBefore, err := os.Lstat(stage)
			if err != nil {
				t.Fatal(err)
			}
			n := &Manager{StateDir: m.StateDir, nfqwsReleases: m.nfqwsReleases, nfqwsFixture: m.nfqwsFixture, Runner: bundleForbiddenRunner{t}}
			receipt, err := n.RecoverManagedBundle(ctx, doc.TransactionID, "resume", a)
			if kind == "resume" {
				if err != nil || receipt != doc.ManagedNFQWS.After {
					t.Fatal("sealed owned stage did not recover", receipt, err)
				}
				if _, err := n.verifyManagedNFQWS(ctx, receipt.GenerationPath, receipt.ManifestSHA256); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("unknown/revoked sealed stage was accepted", kind)
			}
			after, err := os.ReadFile(filepath.Join(m.updateJournalDir(), "current.json"))
			if err != nil || string(before) != string(after) {
				t.Fatal("refusal changed the journal", err)
			}
			if _, err := os.Lstat(doc.ManagedNFQWS.After.GenerationPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal published generation", err)
			}
			if _, err := os.Lstat(filepath.Join(m.StateDir, "receipts", managedNFQWSReceiptName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal published ready inventory", err)
			}
			stageAfter, err := os.Lstat(stage)
			if err != nil || !os.SameFile(stageBefore, stageAfter) || stageBefore.Mode() != stageAfter.Mode() || stageBefore.Sys().(*syscall.Stat_t).Uid != stageAfter.Sys().(*syscall.Stat_t).Uid {
				t.Fatal("refusal discarded or changed stage evidence", stageBefore, stageAfter, err)
			}
			if kind == "corrupt" {
				data, err := os.ReadFile(filepath.Join(stage, "lua/zapret-lib.lua"))
				if err != nil || string(data) != "third bytes" {
					t.Fatal("refusal rewrote third bytes", string(data), err)
				}
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
	if _, err := os.Stat(m.nfqwsReleases); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private path acquired releases directory", err)
	}
}

func TestNativeManagedNFQWSPublishedPayloadModesPublicControlsPrivate(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.publicManagedNFQWSPath(receipt.GenerationPath, false); err != nil {
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
