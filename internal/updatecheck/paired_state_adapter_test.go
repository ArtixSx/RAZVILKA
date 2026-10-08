package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

type pairedReaderFixture struct {
	adapter *SelfUpdateFileAdapter
	updater *Updater
	review  fileReview
	ctx     context.Context
	control string
	store   *selfupdatejournal.Store
	parent  fileProcess
	newSHA  string
}

// Real canonical reviewed files, private archive bytes, control admissions,
// writer lease and all reader implementations. Native process observations are
// modeled; this fixture is not App/bootstrap or native upgrade acceptance.
func pairedReaderSetup(t *testing.T) *pairedReaderFixture {
	t.Helper()
	a, u, review := fileAdapterFixture(t)
	f := &pairedReaderFixture{adapter: a, updater: u, review: review}
	var cancel context.CancelFunc
	f.ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	old, err := os.ReadFile(u.record.Deployment.Executable)
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(u.Deployment.Paths["config"])
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(a.installation, "var/lib/razvilka")
	for _, path := range []string{filepath.Join(a.installation, "bin"), filepath.Join(a.installation, "etc/init.d"), filepath.Join(a.installation, "etc/razvilka"), state} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	helper := filepath.Join(state, "self-update")
	if err := os.Rename(u.Directory, helper); err != nil {
		t.Fatal(err)
	}
	u.Directory, a.directory = helper, helper
	a.fileJournal = filepath.Join(state, "self-update-files")
	// Windows forbids a second handle reading the byte-locked writer marker.
	// Only this model stores the journal outside the captured source and moves
	// its unchanged evidence before inventory checks. Linux exercises the real
	// complete state-root placement and reads the held flock marker normally.
	if runtime.GOOS == "windows" {
		a.fileJournal = filepath.Join(t.TempDir(), "file-journal")
	}
	if err := os.MkdirAll(a.fileJournal, 0700); err != nil {
		t.Fatal(err)
	}
	u.record.Deployment.Executable = filepath.Join(a.installation, "bin/razvilka")
	u.record.Deployment.Paths["config"] = filepath.Join(a.installation, "etc/razvilka/config.json")
	u.Deployment = u.record.Deployment
	retainedFile(t, a.installation, "bin/razvilka", old)
	retainedFile(t, a.installation, "etc/init.d/S99razvilka", []byte("trusted old init"))
	retainedFile(t, a.installation, "etc/razvilka/config.json", config)
	retainedFile(t, a.installation, "etc/razvilka/unknown-private-tree/evidence", []byte("complete prior bytes, never auto-adopted"))
	f.control = filepath.Join(state, "self-update-stop")
	control, err := operationgate.InitializeSelfUpdateControl(f.ctx, f.control)
	if err != nil {
		t.Fatal(err)
	}
	review.AuthorityInstallationID, review.AuthoritySequence = control.InstallationID, control.Sequence
	review.Files = reviewedFileList(filepath.Join(a.directory, review.ID), *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
	f.review = review
	u.record.Job.State, u.record.Job.HelperPID, u.record.ParentPID = "restarting", 20, 21
	u.record.Job.ReviewToken = ""
	saveStoppedReview(t, a, u, review)
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "control.bin"), old, 0700); err != nil {
		t.Fatal(err)
	}
	f.parent = fileProcess{Boot: "01234567-89ab-cdef-0123-456789abcdef", PID: 20, Start: "10", ExecutableSHA256: review.OldExecutableSHA256, Device: 1, Inode: 2}
	panel := f.parent
	panel.PID = 21
	identity, _ := json.Marshal(fileHelperIdentity{selfUpdateProtocolSchema, review.ID, f.parent, panel})
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "helper.identity.json"), identity, 0600); err != nil {
		t.Fatal(err)
	}
	a.processInactive = func(context.Context, fileProcess) error { return nil }
	a.stopCheck = func(ctx context.Context, id string) (bool, error) {
		v, present, err := operationgate.ReadSelfUpdateStop(ctx, f.control)
		if err != nil || !present || v.InstallationID != review.AuthorityInstallationID || (!v.Stopped && v.Sequence != review.AuthoritySequence) {
			return false, ErrFileProtocol
		}
		return v.Stopped, nil
	}
	a.admission = func(ctx context.Context, id, installation string, sequence uint64, action, effect string, rename func() error) error {
		if ctx != f.ctx || action != "start/live" {
			return ErrFileProtocol
		}
		return operationgate.WithSelfUpdateEffectAdmission(ctx, f.control, id, installation, sequence, effect, rename)
	}
	f.store, err = a.OpenFileJournal()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	guard := func(ctx context.Context) error {
		if ctx != f.ctx {
			return ErrFileProtocol
		}
		return a.Authority(ctx, review.ID, review.Revision)
	}
	if err := f.store.Prepare(f.ctx, review.ID, review.Files, guard, guard); err != nil {
		t.Fatal(err)
	}
	root, err := a.commandRoot(review.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		if err := f.store.Execute(f.ctx, review.ID, command, guard, func(ctx context.Context) error {
			if command == "prepare-private-state" {
				if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
					return err
				}
			}
			r := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: review.ID, Command: command, State: "reaped", Parent: f.parent, Supervisor: f.parent, WaitECHILD: true}
			if command != "prepare-private-state" {
				r.DirectPID, r.Reaped = 22, 1
			}
			return writeFileCommand(root, r)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.SealPairedPriorState(f.ctx, review.ID, guard, guard, func(ctx context.Context, r selfupdatejournal.Receipt) (selfupdatejournal.PairedBinding, error) {
		data, _ := json.Marshal(r)
		binding := pairedPriorBinding{ID: r.ID, ReviewSHA256: u.record.FileReviewSHA256, ReceiptSHA256: digestBytes(data), InstallationID: review.AuthorityInstallationID, Sequence: review.AuthoritySequence, Revision: review.Revision}
		digest, err := capturePairedPriorState(ctx, a.installation, binding, r, a.owned, guard, func(rename func() error) error {
			return a.EffectAdmission(ctx, r.ID, "start/live", pairedPriorManifestEffect, rename)
		}, nil)
		return selfupdatejournal.PairedBinding{ManifestSHA256: digest, PreparedSHA256: binding.ReceiptSHA256, ReviewSHA256: binding.ReviewSHA256, InstallationID: binding.InstallationID, Sequence: binding.Sequence, Revision: binding.Revision}, err
	}, func(ctx context.Context, effect string, rename func() error) error {
		return a.EffectAdmission(ctx, review.ID, "start/live", "paired-seal-"+effect, rename)
	}); err != nil {
		t.Fatal(err)
	}
	for _, file := range review.Files {
		if file.Target == "bin/razvilka" {
			f.newSHA = file.SHA256
		}
	}
	return f
}

func (f *pairedReaderFixture) accept(t *testing.T) {
	t.Helper()
	okay := func(ctx context.Context) error { return ctx.Err() }
	if err := f.store.Install(f.ctx, f.review.ID, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Execute(f.ctx, f.review.ID, "start-candidate-panel", okay, func(ctx context.Context) error {
		root, err := f.adapter.commandRoot(f.review.ID)
		if err != nil {
			return err
		}
		defer root.Close()
		worker := f.parent
		worker.PID = 22
		candidate := f.parent
		candidate.PID = 23
		candidate.Inode = 3
		candidate.ExecutableSHA256 = f.newSHA
		return writeFileCommand(root, fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: f.review.ID, Command: "start-candidate-panel", State: "runtime-handed-off", Parent: f.parent, Supervisor: worker, Runtime: candidate, DirectPID: 24, Reaped: 1})
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Accept(f.ctx, f.review.ID, false, okay, okay); err != nil {
		t.Fatal(err)
	}
	u := f.updater
	u.record.Job.State, u.record.Job.Stage = "completed", "completed"
	u.record.Job.CanApply, u.record.Job.CanCancel = false, false
	u.record.Job.Code, u.record.Job.ReviewToken = "", ""
	if err := archiveHelperRecord(f.adapter.directory, u.record); err != nil {
		t.Fatal(err)
	}
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
}

func (f *pairedReaderFixture) retire(t *testing.T) error {
	t.Helper()
	data, _ := json.Marshal(f.updater.record)
	guard := func(ctx context.Context) error { return f.adapter.Authority(ctx, f.review.ID, f.review.Revision) }
	terminal := func(ctx context.Context) error {
		r, err := f.store.RetainedReceipt(ctx, f.review.ID)
		if err != nil {
			return err
		}
		return f.adapter.pairedSettledFormats(ctx, f.updater.record, f.review, r)
	}
	return f.store.RetirePairedPriorState(f.ctx, f.review.ID, digestBytes(data), guard, terminal, func(ctx context.Context, effect string, rename func() error) error {
		return f.adapter.EffectAdmission(ctx, f.review.ID, "start/live", "paired-retire-"+effect, rename)
	})
}

func (f *pairedReaderFixture) inventoryPlacement(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	f.store.Close()
	path := filepath.Join(f.adapter.installation, "var/lib/razvilka/self-update-files")
	if err := os.Rename(f.adapter.fileJournal, path); err != nil {
		t.Fatal(err)
	}
	f.adapter.fileJournal = path
	var err error
	f.store, err = f.adapter.OpenFileJournal()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPairedReadersShareActualArchiveAndSingleDisposition(t *testing.T) {
	f := pairedReaderSetup(t)
	if err := f.retire(t); err == nil {
		t.Fatal("prepared copy granted retirement")
	}
	f.accept(t)
	images, err := f.store.RetainedBinaryImages(f.ctx)
	if err != nil || len(images) != 2 {
		t.Fatal("terminal without retirement excluded images", err)
	}
	if err := f.retire(t); err != nil {
		t.Fatal(err)
	}
	f.inventoryPlacement(t)
	images, err = f.store.RetainedBinaryImages(f.ctx)
	if err != nil || len(images) != 0 {
		t.Fatal("journal reader disagreed", err)
	}
	images, err = f.adapter.journalReaderImagesWithCurrent(f.ctx, f.review, f.newSHA)
	if err != nil || len(images) != 1 || images[0].SHA256 != f.newSHA {
		t.Fatal("helper reader disagreed", err)
	}
	state := filepath.Join(f.adapter.installation, "var/lib/razvilka")
	images, err = retainedControllerImagesWithAdapter(f.ctx, f.adapter.installation, state, f.adapter)
	if err != nil || len(images) != 0 {
		t.Fatal("common fleet reader disagreed", err)
	}
	if required, err := f.adapter.requiredJournalReadVersion(f.ctx); err != nil || required != 4 {
		t.Fatal("reader3 could see retired format as readable", required, err)
	}
	if err := f.store.Restore(f.ctx, f.review.ID, func(context.Context) error { return nil }, func(context.Context) error { return nil }); !errors.Is(err, selfupdatejournal.ErrRetired) {
		t.Fatal("settlement restored a retired partial image", err)
	}
	// A neighboring unknown legacy image remains a fence, even when these
	// exact journal/helper controllers have a complete offline disposition.
	legacy := filepath.Join(state, "update-backups", "unknown-neighbor")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "razvilka.bin"), []byte("unknown legacy reader"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedControllerImagesWithAdapter(f.ctx, f.adapter.installation, state, f.adapter); err == nil {
		t.Fatal("retirement adopted unknown neighboring history")
	}
	if _, err := f.adapter.journalReaderImagesWithCurrent(f.ctx, f.review, f.newSHA); err == nil {
		t.Fatal("helper reader adopted unknown neighboring history")
	}
}

func TestPairedReadersAllRefuseCorruptArchiveAndOrphanEvidence(t *testing.T) {
	for _, change := range []string{"payload", "manifest", "missing-archive", "helper", "unknown-process", "missing-private", "missing-image", "extra-journal", "orphan-helper"} {
		t.Run(change, func(t *testing.T) {
			f := pairedReaderSetup(t)
			f.accept(t)
			if err := f.retire(t); err != nil {
				t.Fatal(err)
			}
			f.inventoryPlacement(t)
			archive := filepath.Join(f.adapter.installation, filepath.FromSlash(pairedPriorArchiveDirectory), f.review.ID)
			switch change {
			case "payload":
				if err := os.WriteFile(filepath.Join(archive, "payload-00000000"), []byte("changed frozen bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := os.WriteFile(filepath.Join(archive, "manifest.json"), []byte(`{"schema":4}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-archive":
				if err := os.Rename(archive, archive+"-preserved"); err != nil {
					t.Fatal(err)
				}
			case "helper":
				r := f.updater.record
				r.Job.Code = "changed-terminal-body"
				data, _ := json.Marshal(r)
				if err := os.WriteFile(filepath.Join(f.adapter.directory, f.review.ID, "retained-helper.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-process":
				root, err := f.adapter.commandRoot(f.review.ID)
				if err != nil {
					t.Fatal(err)
				}
				r, err := readFileCommand(root, f.review.ID, "quiesce-old-runtime")
				if err != nil {
					t.Fatal(err)
				}
				r.State, r.WaitECHILD, r.DirectPID, r.Reaped = "running", false, 22, 0
				err = writeFileCommand(root, r)
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "missing-private":
				if err := os.Remove(filepath.Join(f.adapter.directory, f.review.ID, "private-snapshot.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-image":
				if err := os.Remove(filepath.Join(f.adapter.fileJournal, f.review.ID, "old-0")); err != nil {
					t.Fatal(err)
				}
			case "extra-journal":
				if err := os.Mkdir(filepath.Join(f.adapter.fileJournal, strings.Repeat("e", 32)), 0700); err != nil {
					t.Fatal(err)
				}
			case "orphan-helper":
				if err := os.Mkdir(filepath.Join(f.adapter.directory, strings.Repeat("e", 32)), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.RetainedBinaryImages(f.ctx); err == nil {
				t.Fatal("journal reader ignored invalid paired evidence")
			}
			if _, err := f.adapter.journalReaderImagesWithCurrent(f.ctx, f.review, f.newSHA); err == nil {
				t.Fatal("helper reader ignored invalid paired evidence")
			}
			if _, err := retainedControllerImagesWithAdapter(f.ctx, f.adapter.installation, filepath.Join(f.adapter.installation, "var/lib/razvilka"), f.adapter); err == nil {
				t.Fatal("common fleet reader ignored invalid paired evidence")
			}
		})
	}
}

func TestPairedRetainedHistoryAllowsOnlyMatchingFuturePreparationWithReader4(t *testing.T) {
	f := pairedReaderSetup(t)
	f.accept(t)
	if err := f.retire(t); err != nil {
		t.Fatal(err)
	}
	f.inventoryPlacement(t)
	a := f.adapter
	oldJob := filepath.Join(a.directory, f.review.ID)
	newID := strings.Repeat("a", 32)
	newJob := filepath.Join(a.directory, newID)
	if err := os.Mkdir(newJob, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bundle", "staged"} {
		if err := os.CopyFS(filepath.Join(newJob, name), os.DirFS(filepath.Join(oldJob, name))); err != nil {
			t.Fatal(err)
		}
	}
	current, err := os.ReadFile(filepath.Join(a.installation, "bin/razvilka"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newJob, "control.bin"), current, 0700); err != nil {
		t.Fatal(err)
	}
	currentInit, err := os.ReadFile(filepath.Join(a.installation, "etc/init.d/S99razvilka"))
	if err != nil {
		t.Fatal(err)
	}
	currentConfig, err := os.ReadFile(filepath.Join(a.installation, "etc/razvilka/config.json"))
	if err != nil {
		t.Fatal(err)
	}
	review := f.review
	review.ID, review.JournalReaders = newID, nil
	review.OldExecutableSHA256, review.OldInitSHA256, review.OldConfigSHA256 = digestBytes(current), digestBytes(currentInit), digestBytes(currentConfig)
	review.OldVersion = review.NewVersion
	review.Files = reviewedFileList(newJob, *f.updater.record.Job.Release, f.updater.record.Files, review.MigratedConfigSHA256)
	f.updater.record.Job.ID, f.updater.record.Job.State = newID, "ready"
	f.updater.record.Job.Stage, f.updater.record.Job.HelperPID, f.updater.record.ParentPID = "ready", 0, 0
	f.updater.record.Job.CanApply = true
	f.updater.record.ExecutableHash, f.updater.record.CurrentVersion = review.OldExecutableSHA256, review.OldVersion
	saveStoppedReview(t, a, f.updater, review)
	if _, err := f.store.RetainedBinaryImages(f.ctx); !errors.Is(err, selfupdatejournal.ErrPending) {
		t.Fatal("default fleet omitted a newly pending helper", err)
	}
	if required, err := a.requiredJournalReadVersion(f.ctx); err != nil || required != 4 {
		t.Fatal("format-only observation refused the exact known preparation", required, err)
	}
	ready := func(context.Context, string) (SelfUpdateAuthority, error) {
		return SelfUpdateAuthority{review.AuthorityInstallationID, review.AuthoritySequence}, nil
	}
	if _, err := a.sealOptionalJournalReadersWithProbe(f.ctx, review, ready, func(context.Context, fileReview, selfupdatejournal.BinaryImage) (int, error) { return 3, nil }); err == nil {
		t.Fatal("new reader3 candidate borrowed ordinary2 compatibility over retained4")
	}
	proof, err := a.sealJournalReadersWithProbe(f.ctx, review, ready, func(context.Context, fileReview, selfupdatejournal.BinaryImage) (int, error) { return 4, nil })
	if err != nil || !validJournalReaderProof(proof) || proof.RequiredReader != 4 {
		t.Fatal("exact future reader4 preparation blocked by retired history", err)
	}
	if _, err := os.Lstat(filepath.Join(a.fileJournal, newID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("metadata preparation wrote a new file transaction", err)
	}
}
