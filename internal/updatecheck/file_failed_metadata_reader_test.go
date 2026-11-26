package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func failedMetadataReaderFixture(t *testing.T) (*SelfUpdateFileAdapter, *Updater, fileReview) {
	t.Helper()
	a, u, review := preparingReaderFixture(t)
	if err := os.RemoveAll(filepath.Join(a.directory, review.ID)); err != nil {
		t.Fatal(err)
	}
	u.record.Job.State, u.record.Job.Stage, u.record.Job.Code = "failed", "metadata", "release-url-refused"
	u.record.Job.CanApply, u.record.Job.CanCancel, u.record.Job.Release = false, false, nil
	u.record.Job.Downloaded = 0
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	return a, u, review
}

func TestFailedMetadataHeaderReadCompatibilityPreservesBytesWithoutAuthority(t *testing.T) {
	a, u, review := failedMetadataReaderFixture(t)
	ctx := context.Background()
	path := filepath.Join(a.directory, "current.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if required, err := a.requiredJournalReadVersion(ctx); err != nil || required != 1 {
		t.Fatal("known pre-effect metadata required nonexistent review", required, err)
	}
	if a.Ready(ctx, review.ID) == nil {
		t.Fatal("metadata failure granted ready/effect authority")
	}
	if _, _, err := a.load(ctx, review.ID); err == nil {
		t.Fatal("metadata failure substituted immutable review")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("reader changed retained failed header", err)
	}
	if _, err := os.Lstat(filepath.Join(a.directory, review.ID)); !os.IsNotExist(err) {
		t.Fatal("reader created effect directory", err)
	}
	if u.record.Job.State != "failed" {
		t.Fatal("reader settled terminal state")
	}
	images, err := retainedControllerImagesWithAdapter(ctx, a.installation, filepath.Dir(a.directory), a)
	if err != nil || len(images) != 0 {
		t.Fatal("effect-free discovery header blocked shared node/controller inventory", images, err)
	}
	legacy := filepath.Join(filepath.Dir(a.directory), "update-backups", "older")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "razvilka.bin"), []byte("older-controller"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "razvilka.sha256"), []byte(digestBytes([]byte("older-controller"))), 0600); err != nil {
		t.Fatal(err)
	}
	images, err = retainedControllerImagesWithAdapter(ctx, a.installation, filepath.Dir(a.directory), a)
	if err != nil || len(images) != 1 || images[0].Path != filepath.Join(legacy, "razvilka.bin") {
		t.Fatal("metadata shortcut omitted another rollback controller", images, err)
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("controller inventory rewrote header", err)
	}
}

func TestFailedMetadataHeaderReaderKeepsUnknownAndEffectCutsFenced(t *testing.T) {
	for _, mode := range []string{"unknown-code", "unknown-state", "unknown-stage", "release", "bytes", "helper", "can-apply", "can-cancel", "token", "attested", "verification", "fingerprint", "parent", "version", "time", "digest", "executable", "files", "empty-job-directory", "review", "foreign-entry", "unsafe-layout", "unknown-json"} {
		t.Run(mode, func(t *testing.T) {
			a, u, review := failedMetadataReaderFixture(t)
			layout := a.layout
			switch mode {
			case "unknown-code":
				u.record.Job.Code = "future-metadata-failure"
			case "unknown-state":
				u.record.Job.State = "future-failed"
			case "unknown-stage":
				u.record.Job.Stage = "handoff"
			case "release":
				u.record.Job.Release = &Release{ID: 1}
			case "bytes":
				u.record.Job.Downloaded = 1
			case "helper":
				u.record.Job.HelperPID = 2
			case "can-apply":
				u.record.Job.CanApply = true
			case "can-cancel":
				u.record.Job.CanCancel = true
			case "token":
				u.record.Job.ReviewToken = "future"
			case "attested":
				u.record.Job.Attestation = true
			case "verification":
				u.record.Job.Verification = "future"
			case "fingerprint":
				u.record.ConfigFingerprint = "unknown"
			case "parent":
				u.record.ParentPID = 0
			case "version":
				u.record.CurrentVersion = "unknown"
			case "time":
				u.record.Job.UpdatedAt = u.record.Job.StartedAt.Add(-1)
			case "digest":
				u.record.FileReviewSHA256 = digestBytes([]byte("future"))
			case "executable":
				u.record.ExecutableHash = digestBytes([]byte("future"))
			case "files":
				u.record.Files = map[string]string{}
			case "empty-job-directory", "review":
				if err := os.Mkdir(filepath.Join(a.directory, review.ID), 0700); err != nil {
					t.Fatal(err)
				}
				if mode == "review" {
					if err := os.WriteFile(filepath.Join(a.directory, review.ID, "file-review.json"), []byte("retained"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "foreign-entry":
				if err := os.WriteFile(filepath.Join(a.directory, "future-format"), []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-layout":
				a.layout = func(Deployment) error { return ErrFileProtocol }
			}
			if err := u.persistLocked(); err != nil {
				t.Fatal(err)
			}
			if mode == "unknown-json" {
				raw, _ := json.Marshal(u.record)
				raw = append(raw[:len(raw)-1], []byte(",\"future\":true}")...)
				if err := os.WriteFile(filepath.Join(a.directory, "current.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
				t.Fatal("unknown/effect-bearing header became readable")
			}
			if _, err := retainedControllerImagesWithAdapter(context.Background(), a.installation, filepath.Dir(a.directory), a); err == nil {
				t.Fatal("unknown/effect-bearing header bypassed controller inventory")
			}
			a.layout = layout
		})
	}
}

func TestFailedMetadataKnownProducerErrorsRemainReadOnly(t *testing.T) {
	for _, code := range []string{"release-url-refused", "official-release-unavailable", "official-release-http-404", "official-release-http-429", "release-not-an-upgrade", "release-channel-empty", "release-asset-invalid", "prepare-timeout", "prepare-cancelled"} {
		t.Run(code, func(t *testing.T) {
			a, u, review := failedMetadataReaderFixture(t)
			u.record.Job.Code = code
			if code == "prepare-cancelled" {
				u.record.Job.State = "cancelled"
			}
			if err := u.persistLocked(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(a.directory, "current.json"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.requiredJournalReadVersion(context.Background()); err != nil {
				t.Fatal("known effect-free metadata failure fenced cold reader", err)
			}
			after, err := os.ReadFile(filepath.Join(a.directory, "current.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("reader rewrote failed metadata", err)
			}
			if a.Ready(context.Background(), review.ID) == nil {
				t.Fatal("metadata error supplied effect authority")
			}
			if _, err := retainedControllerImagesWithAdapter(context.Background(), a.installation, filepath.Dir(a.directory), a); err != nil {
				t.Fatal("known metadata error blocked node/controller inventory", err)
			}
		})
	}
	for _, code := range []string{"unknown-future-metadata", "helper-launch-failed", "official-release-http-0", "official-release-http-099", "official-release-http-200", "official-release-http-600", "official-release-http-0404", "official-release-http-404-extra"} {
		if knownMetadataFailure("failed", code) {
			t.Fatal("unknown metadata code accepted", code)
		}
	}
	if knownMetadataFailure("failed", "prepare-cancelled") || knownMetadataFailure("cancelled", "prepare-timeout") {
		t.Fatal("mismatched cancellation producer accepted")
	}
}
