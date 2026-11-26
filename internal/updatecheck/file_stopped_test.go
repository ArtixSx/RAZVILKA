package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func saveStoppedReview(t *testing.T, a *SelfUpdateFileAdapter, u *Updater, review fileReview) {
	t.Helper()
	data, _ := json.Marshal(review)
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "file-review.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	u.record.FileReviewSHA256 = digestBytes(data)
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
}

func stoppedAdapterFixture(t *testing.T) (*SelfUpdateFileAdapter, *Updater, fileReview, SelfUpdateStoppedSettlementAuthority) {
	t.Helper()
	a, u, review := fileAdapterFixture(t)
	for _, path := range []string{"bin", "etc/init.d", "etc/razvilka", "razvilka/run", "razvilka/state"} {
		if err := os.MkdirAll(filepath.Join(a.installation, filepath.FromSlash(path)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	old, err := os.ReadFile(u.record.Deployment.Executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.installation, "bin/razvilka"), old, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "control.bin"), old, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.installation, "etc/init.d/S99razvilka"), []byte("trusted old init"), 0755); err != nil {
		t.Fatal(err)
	}
	configData, err := os.ReadFile(u.Deployment.Paths["config"])
	if err != nil {
		t.Fatal(err)
	}
	u.record.Deployment.Executable = filepath.Join(a.installation, "bin/razvilka")
	u.record.Deployment.Paths["config"] = filepath.Join(a.installation, "etc/razvilka/config.json")
	u.Deployment = u.record.Deployment
	if err := os.WriteFile(u.Deployment.Paths["config"], configData, 0600); err != nil {
		t.Fatal(err)
	}
	u.record.Job.State, u.record.Job.HelperPID, u.record.ParentPID = "requires-review", 20, 21
	if err := os.MkdirAll(a.fileJournal, 0700); err != nil {
		t.Fatal(err)
	}
	saveStoppedReview(t, a, u, review)
	ready := func(context.Context, string) (SelfUpdateAuthority, error) {
		return SelfUpdateAuthority{review.AuthorityInstallationID, review.AuthoritySequence}, nil
	}
	proof, err := a.sealJournalReadersWithProbe(context.Background(), review, ready, func(context.Context, fileReview, selfupdatejournal.BinaryImage) (int, error) { return 3, nil })
	if err != nil {
		t.Fatal(err)
	}
	review.JournalReaders = proof
	saveStoppedReview(t, a, u, review)
	parent := fileProcess{Boot: "01234567-89ab-cdef-0123-456789abcdef", PID: 20, Start: "10", ExecutableSHA256: review.OldExecutableSHA256, Device: 1, Inode: 2}
	oldPanel := parent
	oldPanel.PID = 21
	identity, _ := json.Marshal(fileHelperIdentity{selfUpdateProtocolSchema, review.ID, parent, oldPanel})
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "helper.identity.json"), identity, 0600); err != nil {
		t.Fatal(err)
	}
	a.processInactive = func(context.Context, fileProcess) error { return nil } // model only; native uses /proc birth checks
	store, err := selfupdatejournal.Open(a.installation, a.fileJournal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	okay := func(context.Context) error { return nil }
	if err := store.Prepare(context.Background(), review.ID, review.Files, okay, okay); err != nil {
		t.Fatal(err)
	}
	root, err := a.commandRoot(review.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		if err := store.Execute(context.Background(), review.ID, command, okay, func(context.Context) error {
			if command == "prepare-private-state" {
				if err := a.preparePrivateSnapshot(context.Background(), review.ID); err != nil {
					return err
				}
			}
			r := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: review.ID, Command: command, State: "reaped", Parent: parent, Supervisor: parent, WaitECHILD: true}
			if command != "prepare-private-state" {
				r.DirectPID, r.Reaped = 22, 1
			}
			return writeFileCommand(root, r)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Install(context.Background(), review.ID, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(context.Background(), review.ID, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), review.ID, "restore-private-state", okay, func(context.Context) error {
		return writeFileCommand(root, fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: review.ID, Command: "restore-private-state", State: "reaped", Parent: parent, Supervisor: parent, WaitECHILD: true})
	}); err != nil {
		t.Fatal(err)
	}
	a.stopCheck = func(context.Context, string) (bool, error) { return true, nil }
	a.admission = func(context.Context, string, string, uint64, string, string, func() error) error {
		t.Fatal("settlement started an effect")
		return ErrFileProtocol
	}
	authority := SelfUpdateStoppedSettlementAuthority{
		Check: func(ctx context.Context, id, installation string, sequence, revision uint64) error {
			if id != review.ID || installation != review.AuthorityInstallationID || sequence != review.AuthoritySequence || revision != review.Revision {
				return ErrFileProtocol
			}
			return ctx.Err()
		},
		AdmitReaders: func(ctx context.Context, id string, wanted int) error {
			return a.CheckRetainedJournalReaders(ctx, id, wanted)
		},
	}
	return a, u, review, authority
}

func TestStoppedAdapterSettlesWithoutStartOrLiveAndInspects(t *testing.T) {
	a, _, review, authority := stoppedAdapterFixture(t)
	if err := a.CheckRetainedJournalReaders(context.Background(), review.ID, 3); err != nil {
		t.Fatal("pre-settlement reader check", err)
	}
	if err := a.SettleStoppedRollback(context.Background(), review.ID, authority); err != nil {
		t.Fatal(err)
	}
	if err := a.Inspect(context.Background(), review.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.Finish(context.Background(), review.ID, true); err == nil {
		t.Fatal("live Finish accepted stopped data")
	}
	if err := a.SettleStoppedRollback(context.Background(), review.ID, authority); err != nil {
		t.Fatal("retry", err)
	}
	record, err := readAdapterRecord(a.directory, review.ID)
	if err != nil || record.Job.State != stoppedRollbackState || record.Job.CanApply || record.Job.CanCancel {
		t.Fatal(record.Job, err)
	}
	version, err := a.requiredJournalReadVersion(context.Background())
	if err != nil || version != 3 {
		t.Fatal(version, err)
	}
}

func TestStoppedAdapterRefusesMissingOrChangedEvidence(t *testing.T) {
	for _, test := range []string{"missing-check", "missing-admission", "running", "wrong-stop", "reader2", "missing-proof", "corrupt-control", "missing-echild", "unknown", "parent-mismatch", "old-panel-live", "runtime-live", "private-drift", "pidfile", "future-reader"} {
		t.Run(test, func(t *testing.T) {
			a, u, review, authority := stoppedAdapterFixture(t)
			switch test {
			case "missing-check":
				authority.Check = nil
			case "missing-admission":
				authority.AdmitReaders = nil
			case "running":
				a.stopCheck = func(context.Context, string) (bool, error) { return false, nil }
			case "wrong-stop":
				authority.Check = func(context.Context, string, string, uint64, uint64) error { return ErrFileProtocol }
			case "reader2":
				review.JournalReaders.Controllers[0].ReadVersion = 2
				saveStoppedReview(t, a, u, review)
			case "future-reader":
				review.JournalReaders.Controllers[0].ReadVersion = 4
				saveStoppedReview(t, a, u, review)
			case "missing-proof":
				review.JournalReaders = nil
				saveStoppedReview(t, a, u, review)
			case "corrupt-control":
				_ = os.WriteFile(filepath.Join(a.directory, review.ID, "control.bin"), []byte("foreign"), 0700)
			case "old-panel-live":
				a.processInactive = func(context.Context, fileProcess) error { return ErrFileProtocol }
			case "runtime-live":
				a.runtimeInactive = func(context.Context, string) error { return ErrFileProtocol }
			case "private-drift":
				_ = os.WriteFile(filepath.Join(a.installation, "etc/razvilka/admin.token"), []byte("foreign"), 0600)
			case "pidfile":
				_ = os.WriteFile(filepath.Join(a.installation, "razvilka/run/razvilka.pid"), []byte("23\n"), 0600)
			case "unknown":
				store, err := selfupdatejournal.Open(a.installation, a.fileJournal)
				if err != nil {
					t.Fatal(err)
				}
				_ = store.Execute(context.Background(), review.ID, "start-candidate-panel", func(context.Context) error { return nil }, func(context.Context) error { return ErrFileProtocol })
				store.Close()
			case "missing-echild", "parent-mismatch":
				root, _ := a.commandRoot(review.ID)
				r, err := readFileCommand(root, review.ID, "quiesce-old-runtime")
				if err != nil {
					t.Fatal(err)
				}
				if test == "missing-echild" {
					r.State, r.WaitECHILD, r.Reaped = "running", false, 0
				} else {
					r.Parent.PID++
				}
				if err := writeFileCommand(root, r); err != nil {
					t.Fatal(err)
				}
				root.Close()
			}
			before, _ := os.ReadFile(filepath.Join(a.fileJournal, review.ID, "receipt.json"))
			err := a.SettleStoppedRollback(context.Background(), review.ID, authority)
			if err == nil {
				t.Fatal("evidence admitted", test)
			}
			if test == "unknown" && !errors.Is(err, selfupdatejournal.ErrUnknown) {
				t.Fatal("unknown became known", err)
			}
			after, _ := os.ReadFile(filepath.Join(a.fileJournal, review.ID, "receipt.json"))
			if string(before) != string(after) {
				t.Fatal("refusal changed terminal receipt")
			}
		})
	}
}
