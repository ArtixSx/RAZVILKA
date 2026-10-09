package updatecheck

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func preparingReaderFixture(t *testing.T) (*SelfUpdateFileAdapter, *Updater, fileReview) {
	t.Helper()
	a, u, review := fileAdapterFixture(t)
	if err := os.Remove(filepath.Join(a.directory, review.ID, "file-review.json")); err != nil {
		t.Fatal(err)
	}
	u.record.FileReviewSHA256, u.record.ExecutableHash, u.record.Files = "", "", nil
	u.record.ParentPID, u.record.Job.HelperPID = os.Getpid(), 0
	u.record.Job.State, u.record.Job.Stage, u.record.Job.Channel = "preparing", "preflight", "stable"
	u.record.Job.CanApply, u.record.Job.CanCancel, u.record.Job.ReviewToken = false, true, ""
	u.record.ConfigFingerprint = ConfigFingerprint(config.Config{Revision: review.Revision})
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	return a, u, review
}

func TestPreparingHelperObservesFormatsWithoutSealedReviewOrFleetGrant(t *testing.T) {
	a, u, review := preparingReaderFixture(t)
	ctx := context.Background()
	before, err := os.ReadFile(filepath.Join(a.directory, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	if required, err := a.requiredJournalReadVersion(ctx); err != nil || required != selfUpdateProtocolSchema {
		t.Fatal("preflight metadata demanded an unpublished review", required, err)
	}
	if a.Ready(ctx, review.ID) == nil {
		t.Fatal("preparing header supplied ready/effect authority")
	}
	if _, _, err := a.load(ctx, review.ID); err == nil {
		t.Fatal("preparing header substituted for the immutable review")
	}
	after, err := os.ReadFile(filepath.Join(a.directory, "current.json"))
	if err != nil || string(before) != string(after) || u.record.FileReviewSHA256 != "" {
		t.Fatal("format observation published or changed preparation", err)
	}
}

func TestPreparingHelperRefusesUncommittedRecoveryAndUnknownHeaders(t *testing.T) {
	for _, kind := range []string{"sealed-review", "process", "retained-helper", "foreign", "helper-pid", "can-apply", "published-digest", "unknown-stage", "file-map"} {
		t.Run(kind, func(t *testing.T) {
			a, u, review := preparingReaderFixture(t)
			name := ""
			switch kind {
			case "sealed-review":
				name = "file-review.json"
			case "process":
				name = "stop-old-panel.process.json"
			case "retained-helper":
				name = "retained-helper.json"
			case "foreign":
				name = "foreign-evidence"
			case "helper-pid":
				u.record.Job.HelperPID = 20
			case "can-apply":
				u.record.Job.CanApply = true
			case "published-digest":
				u.record.FileReviewSHA256 = digestBytes([]byte("uncommitted"))
			case "unknown-stage":
				u.record.Job.Stage = "future-preparing"
			case "file-map":
				u.record.Files = map[string]string{}
			}
			if name != "" {
				if err := os.WriteFile(filepath.Join(a.directory, review.ID, name), []byte("preserve unknown evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := u.persistLocked(); err != nil {
				t.Fatal(err)
			}
			if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
				t.Fatal("uncommitted or unknown preparation supplied format readiness")
			}
		})
	}
}

func TestPreparingHeaderPublicationBeforeJobDirectoryIsReadOnly(t *testing.T) {
	a, u, review := preparingReaderFixture(t)
	job := filepath.Join(a.directory, review.ID)
	if err := os.Rename(job, filepath.Join(t.TempDir(), "preserved-preparation")); err != nil {
		t.Fatal(err)
	}
	u.record.Job.Stage, u.record.Job.Release = "metadata", nil
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.requiredJournalReadVersion(context.Background()); err != nil {
		t.Fatal("known header-before-directory publication was unreadable", err)
	}
	if _, err := os.Lstat(job); !os.IsNotExist(err) {
		t.Fatal("metadata reader created a preparation directory", err)
	}
	u.record.Job.Stage = "preflight"
	data, _ := json.Marshal(u.record)
	if err := os.WriteFile(filepath.Join(a.directory, "current.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
		t.Fatal("missing preflight job was treated as the initial header cut")
	}
}
