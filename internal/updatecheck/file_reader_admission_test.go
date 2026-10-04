package updatecheck

import (
	"context"
	"encoding/json"
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
	if err := a.SettleStoppedRollback(context.Background(), review.ID, authority); err == nil {
		t.Fatal("legacy review auto-adopted reader3")
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
