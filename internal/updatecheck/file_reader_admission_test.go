package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func TestJournalReaderSealRejectsDowngradeFutureAndDrift(t *testing.T) {
	for _, test := range []string{"reader1", "reader2", "future", "authority", "hash-drift", "unrecognized-job", "inventory-addition"} {
		t.Run(test, func(t *testing.T) {
			a, _, review, _ := stoppedAdapterFixture(t)
			ready := func(context.Context, string) (SelfUpdateAuthority, error) {
				value := SelfUpdateAuthority{review.AuthorityInstallationID, review.AuthoritySequence}
				if test == "authority" {
					value.Sequence++
				}
				return value, nil
			}
			calls := 0
			probe := func(ctx context.Context, r fileReview, image selfupdatejournal.BinaryImage) (int, error) {
				calls++
				switch test {
				case "reader1":
					return 1, nil
				case "reader2":
					return 2, nil
				case "future":
					return 4, nil
				case "hash-drift":
					_ = os.WriteFile(image.Path, []byte("changed during probe"), 0600)
				case "unrecognized-job":
					_ = os.Mkdir(filepath.Join(a.directory, "foreign"), 0700)
				case "inventory-addition":
					_ = os.Mkdir(filepath.Join(a.directory, "fedcba9876543210fedcba9876543210"), 0700)
				}
				return 3, nil
			}
			if _, err := a.sealJournalReadersWithProbe(context.Background(), review, ready, probe); err == nil {
				t.Fatal("reader proof admitted", test)
			}
			if test == "authority" && calls != 0 {
				t.Fatal("stale authority reached probe")
			}
		})
	}
}

func TestJournalReaderAdmissionIsReadOnlyAndFencesUnknownFleet(t *testing.T) {
	for _, test := range []string{"candidate", "old", "control", "unknown-job", "legacy-no-hash", "future-file-schema", "future-helper-identity", "unknown-process", "copied-helper-archive"} {
		t.Run(test, func(t *testing.T) {
			a, _, review, _ := stoppedAdapterFixture(t)
			path := ""
			switch test {
			case "candidate":
				path = review.Files[0].Candidate
			case "old":
				path = filepath.Join(a.fileJournal, review.ID, "old-0")
			case "control":
				path = filepath.Join(a.directory, review.ID, "control.bin")
			case "unknown-process":
				path = filepath.Join(a.directory, review.ID, "future-command.process.json")
			case "copied-helper-archive":
				path = filepath.Join(a.directory, review.ID, "retained-helper.json")
			case "unknown-job":
				_ = os.Mkdir(filepath.Join(a.directory, "fedcba9876543210fedcba9876543210"), 0700)
			case "legacy-no-hash":
				path = filepath.Join(filepath.Dir(a.directory), "update-backups/retained/razvilka.bin")
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
			case "future-file-schema":
				path = filepath.Join(a.fileJournal, review.ID, "receipt.json")
				data, _ := os.ReadFile(path)
				var receipt map[string]any
				_ = json.Unmarshal(data, &receipt)
				receipt["schema"] = 4
				data, _ = json.Marshal(receipt)
				_ = os.WriteFile(path, data, 0600)
				path = ""
			case "future-helper-identity":
				path = filepath.Join(a.directory, review.ID, "helper.identity.json")
				data, _ := os.ReadFile(path)
				var identity fileHelperIdentity
				_ = json.Unmarshal(data, &identity)
				identity.Schema = 4
				data, _ = json.Marshal(identity)
				_ = os.WriteFile(path, data, 0600)
				path = ""
			}
			if path != "" {
				if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(filepath.Join(a.fileJournal, review.ID, "receipt.json"))
			if test == "future-helper-identity" {
				if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
					t.Fatal("future identity read")
				}
			} else if err := a.CheckRetainedJournalReaders(context.Background(), review.ID, 3); err == nil {
				t.Fatal("fleet admitted", test)
			}
			after, _ := os.ReadFile(filepath.Join(a.fileJournal, review.ID, "receipt.json"))
			if string(before) != string(after) {
				t.Fatal("reader guard mutated retained receipt")
			}
		})
	}
}

func TestLegacyReviewStaysReadableButCannotSettleStopped(t *testing.T) {
	a, u, review, authority := stoppedAdapterFixture(t)
	review.JournalReaders = nil
	saveStoppedReview(t, a, u, review)
	if _, _, err := a.load(context.Background(), review.ID); err != nil {
		t.Fatal("legacy protocol2 review became unreadable", err)
	}
	if version, err := a.requiredJournalReadVersion(context.Background()); err != nil || version != 2 {
		t.Fatal(version, err)
	}
	before, _ := os.ReadFile(filepath.Join(a.fileJournal, review.ID, "receipt.json"))
	if err := a.SettleStoppedRollback(context.Background(), review.ID, authority); !errors.Is(err, ErrStoppedSettlementIneligible) {
		t.Fatal("legacy review auto-adopted reader3")
	}
	after, _ := os.ReadFile(filepath.Join(a.fileJournal, review.ID, "receipt.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("ineligible stopped review wrote terminal3")
	}
	if SelfUpdateReadVersion != 3 || selfUpdateProtocolSchema != 2 {
		t.Fatal("reader capability coupled to replacement/private protocol")
	}
}

func TestJournalReaderProofIncludesEveryRetainedController(t *testing.T) {
	a, u, oldReview, stoppedAuthority := stoppedAdapterFixture(t)
	ctx := context.Background()
	if err := a.SettleStoppedRollback(ctx, oldReview.ID, stoppedAuthority); err != nil {
		t.Fatal(err)
	}
	newID := "fedcba9876543210fedcba9876543210"
	job := filepath.Join(a.directory, newID)
	if err := os.CopyFS(job, os.DirFS(filepath.Join(a.directory, oldReview.ID))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(job, "retained-helper.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"helper.identity.json", "private-snapshot.json", "private-snapshot.sha256", "stop-old-panel.process.json", "prepare-private-state.process.json", "quiesce-old-runtime.process.json", "restore-private-state.process.json"} {
		if err := os.Remove(filepath.Join(job, name)); err != nil {
			t.Fatal(err)
		}
	}
	u.record.Job.ID, u.record.Job.State = newID, "ready"
	review := oldReview
	review.ID, review.JournalReaders = newID, nil
	review.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
	saveStoppedReview(t, a, u, review)
	ready := func(context.Context, string) (SelfUpdateAuthority, error) {
		return SelfUpdateAuthority{review.AuthorityInstallationID, review.AuthoritySequence}, nil
	}
	retainedPath := filepath.Join(a.fileJournal, oldReview.ID, "old-0")
	retainedObserved := false
	probe := func(ctx context.Context, review fileReview, image selfupdatejournal.BinaryImage) (int, error) {
		if image.Path == retainedPath {
			retainedObserved = true
			return 2, nil
		}
		return 3, nil
	}
	if _, err := a.sealJournalReadersWithProbe(ctx, review, ready, probe); err == nil || !retainedObserved {
		t.Fatal("retained reader2 escaped inventory", retainedObserved, err)
	}
	proof, err := a.sealJournalReadersWithProbe(ctx, review, ready, func(context.Context, fileReview, selfupdatejournal.BinaryImage) (int, error) { return 3, nil })
	if err != nil || len(proof.Controllers) != 7 {
		t.Fatal("incomplete retained controller set", proof, err)
	}
	review.JournalReaders = proof
	saveStoppedReview(t, a, u, review)
	if err := a.CheckRetainedJournalReaders(ctx, newID, 3); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a.directory, oldReview.ID, "control.bin")); err != nil {
		t.Fatal(err)
	}
	if err := a.CheckRetainedJournalReaders(ctx, newID, 3); err == nil {
		t.Fatal("missing retained helper controller was silently dropped")
	}
}

func TestReader2To3OrdinarySchema2PrepareStaysStoppedIneligible(t *testing.T) {
	a, u, review, _ := stoppedAdapterFixture(t)
	ctx := context.Background()
	a.stopCheck = func(context.Context, string) (bool, error) { return false, nil } // ordinary running model, no control reset
	ready := func(context.Context, string) (SelfUpdateAuthority, error) {
		return SelfUpdateAuthority{review.AuthorityInstallationID, review.AuthoritySequence}, nil
	}
	observed := 0
	proof, err := a.sealOptionalJournalReadersWithProbe(ctx, review, ready, func(ctx context.Context, review fileReview, image selfupdatejournal.BinaryImage) (int, error) {
		observed++
		if image.Path == review.Files[0].Candidate {
			return 3, nil
		} // reader2 -> reader3 candidate
		return 2, nil
	})
	if err != nil || proof != nil || observed != 3 {
		t.Fatal("ordinary reader2 upgrade refused or granted reader3", proof, observed, err)
	}
	review.JournalReaders = proof
	saveStoppedReview(t, a, u, review)
	data, _ := os.ReadFile(filepath.Join(a.directory, review.ID, "file-review.json"))
	if bytes.Contains(data, []byte("journal_readers")) {
		t.Fatal("ineligible review changed the old strict schema2 wire format")
	}
	if eligible, err := a.StoppedSettlementEligibility(ctx, review.ID); err != nil || eligible {
		t.Fatal("reader2 silently eligible", eligible, err)
	}
	if err := a.CheckRetainedJournalReaders(ctx, review.ID, 3); !errors.Is(err, ErrStoppedSettlementIneligible) {
		t.Fatal("reader2 gained stopped terminal", err)
	}
	// The existing ordinary live acceptance model still upgrades the six
	// files and writes accepted/schema2. Its trusted live callback is separate
	// from stopped eligibility; no fake idle live callback is introduced.
	store, err := selfupdatejournal.Open(a.installation, a.fileJournal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	okay := func(context.Context) error { return nil }
	ordinary := func(ctx context.Context) error { return a.Authority(ctx, review.ID, review.Revision) }
	// Close the fixture's prior ordinary rollback and prepare a fresh upgrade
	// in the same journal. No pending rollback is reinterpreted as an install.
	if err := store.Accept(ctx, review.ID, true, ordinary, okay); err != nil {
		t.Fatal(err)
	}
	u.record.Job.State, u.record.Job.CanApply, u.record.Job.CanCancel = "rolled-back", false, false
	if err := archiveHelperRecord(a.directory, u.record); err != nil {
		t.Fatal(err)
	}
	oldJob := filepath.Join(a.directory, review.ID)
	newID := "fedcba9876543210fedcba9876543210"
	newJob := filepath.Join(a.directory, newID)
	if err := os.CopyFS(newJob, os.DirFS(oldJob)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"retained-helper.json", "helper.identity.json", "private-snapshot.json", "private-snapshot.sha256", "stop-old-panel.process.json", "prepare-private-state.process.json", "quiesce-old-runtime.process.json", "restore-private-state.process.json"} {
		if err := os.Remove(filepath.Join(newJob, name)); err != nil {
			t.Fatal(err)
		}
	}
	review.ID, u.record.Job.ID, u.record.Job.State = newID, newID, "ready"
	review.Files = reviewedFileList(newJob, *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
	saveStoppedReview(t, a, u, review)
	proof, err = a.sealOptionalJournalReadersWithProbe(ctx, review, ready, func(ctx context.Context, review fileReview, image selfupdatejournal.BinaryImage) (int, error) {
		if image.Path == review.Files[0].Candidate {
			return 3, nil
		}
		return 2, nil
	})
	if err != nil || proof != nil {
		t.Fatal("fresh reader2 -> reader3 Prepare refused", proof, err)
	}
	review.JournalReaders = proof
	saveStoppedReview(t, a, u, review)
	if err := store.Prepare(ctx, newID, review.Files, ordinary, okay); err != nil {
		t.Fatal("fresh ordinary prepare", err)
	}
	if err := store.Install(ctx, review.ID, ordinary, okay); err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(ctx, review.ID, false, ordinary, okay); err != nil {
		t.Fatal("ordinary live accepted refused", err)
	}
	r, present, err := store.Current()
	if err != nil || !present || r.Schema != 2 || r.Phase != "accepted" || r.Stopped != nil {
		t.Fatal("ordinary acceptance evolved into stopped format", r, err)
	}
	if err := store.VerifyInstallation(ctx, review.ID, false); err != nil {
		t.Fatal(err)
	}
}

func TestOptionalReaderProofNeverFallsBackOnUnknownOrFuture(t *testing.T) {
	for _, test := range []string{"future", "reader1", "probe-error", "drift"} {
		t.Run(test, func(t *testing.T) {
			a, _, review, _ := stoppedAdapterFixture(t)
			ready := func(context.Context, string) (SelfUpdateAuthority, error) {
				return SelfUpdateAuthority{review.AuthorityInstallationID, review.AuthoritySequence}, nil
			}
			calls := 0
			proof, err := a.sealOptionalJournalReadersWithProbe(context.Background(), review, ready, func(ctx context.Context, review fileReview, image selfupdatejournal.BinaryImage) (int, error) {
				calls++
				if calls == 1 {
					return 2, nil
				}
				switch test {
				case "future":
					return 4, nil
				case "reader1":
					return 1, nil
				case "probe-error":
					return 0, ErrFileProtocol
				case "drift":
					_ = os.WriteFile(image.Path, []byte("changed after known reader2"), 0600)
				}
				return 3, nil
			})
			if err == nil || proof != nil || calls < 2 {
				t.Fatal("legacy2 hid untrusted future/drift", proof, calls, err)
			}
		})
	}
}
