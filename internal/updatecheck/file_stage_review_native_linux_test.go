//go:build linux

package updatecheck

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestNativeStageFileReviewBeforeCurrentReviewPublication(t *testing.T) {
	a, u, _ := preparingReaderFixture(t)
	type originalScopeKey struct{}
	originalScope := new(int)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), originalScopeKey{}, originalScope), time.Minute)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	sha := digestBytes(program)
	job := filepath.Join(a.directory, u.record.Job.ID)
	for _, path := range []string{filepath.Join(a.installation, "bin"), filepath.Join(a.installation, "etc/init.d"), filepath.Join(a.installation, "etc/razvilka"), filepath.Join(a.installation, "var/lib/razvilka")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	oldConfig, err := os.ReadFile(u.record.Deployment.Paths["config"])
	if err != nil {
		t.Fatal(err)
	}
	u.record.Deployment.Executable = filepath.Join(a.installation, "bin/razvilka")
	u.record.Deployment.Paths["config"] = filepath.Join(a.installation, "etc/razvilka/config.json")
	u.Deployment = u.record.Deployment
	if err := os.WriteFile(u.record.Deployment.Paths["config"], oldConfig, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.installation, "etc/init.d/S99razvilka"), []byte("trusted prior fixture init\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(u.record.Deployment.Executable, program, 0700); err != nil {
		t.Fatal(err)
	}
	binaryName := "dist/" + u.record.Job.Release.Binary.Name
	if err := os.WriteFile(filepath.Join(job, "bundle", filepath.FromSlash(binaryName)), program, 0700); err != nil {
		t.Fatal(err)
	}
	checksums := []byte(sha + "  " + u.record.Job.Release.Binary.Name + "\n")
	if err := os.WriteFile(filepath.Join(job, "bundle/dist/SHA256SUMS"), checksums, 0600); err != nil {
		t.Fatal(err)
	}
	u.record.Job.Release.Binary.Digest, u.record.Job.Release.Binary.Size = "sha256:"+sha, int64(len(program))
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(a.directory, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Exactly as Updater.prepare: extracted file hashes and executable hash
	// are supplied in memory; the durable current header is still preparing.
	record := u.record
	record.Files = make(map[string]string)
	for name := range requiredInstallFiles(*record.Job.Release) {
		data, err := os.ReadFile(filepath.Join(job, "bundle", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		record.Files[name] = digestBytes(data)
	}
	record.ExecutableHash = sha
	controlPath := filepath.Join(t.TempDir(), "control")
	control, err := operationgate.InitializeSelfUpdateControl(ctx, controlPath)
	if err != nil {
		t.Fatal(err)
	}
	authority := func(c context.Context, id string) (SelfUpdateAuthority, error) {
		if c != ctx || id != record.Job.ID {
			return SelfUpdateAuthority{}, ErrFileProtocol
		}
		return SelfUpdateAuthority{control.InstallationID, control.Sequence}, nil
	}
	starts := 0
	a.admission = func(c context.Context, id, installation string, sequence uint64, action, effect string, begin func() error) error {
		deadline, finite := c.Deadline()
		originalDeadline, _ := ctx.Deadline()
		if c.Value(originalScopeKey{}) != originalScope || !finite || deadline.After(originalDeadline) || ctx.Err() != nil || action != "start/live" || effect != journalReaderProbeEffect {
			return ErrFileProtocol
		}
		return operationgate.WithSelfUpdateEffectAdmission(c, controlPath, id, installation, sequence, effect, func() error { starts++; return begin() })
	}
	shaReview, err := a.stageFileReview(ctx, record, authority)
	if err != nil || !validDigest("sha256:"+shaReview) || starts == 0 {
		t.Fatal("actual staging producer demanded a prepublished review", starts, err)
	}
	data, err := os.ReadFile(filepath.Join(job, "file-review.json"))
	var review fileReview
	if err != nil || digestBytes(data) != shaReview || decodeFileProtocol(data, &review) != nil || !validJournalReaderProof(review.JournalReaders) || review.JournalReaders.RequiredReader != SelfUpdateReadVersion {
		t.Fatal("actual ELF producer did not seal its observed readers", err)
	}
	after, err := os.ReadFile(filepath.Join(a.directory, "current.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("producer changed the current header before its owner published", err)
	}
	if _, err := a.requiredJournalReadVersion(ctx); err == nil {
		t.Fatal("uncommitted review publication cut supplied metadata readiness")
	}
	record.FileReviewSHA256 = shaReview
	record.Job.State, record.Job.Stage = "ready", "ready"
	record.Job.CanApply, record.Job.CanCancel, record.Job.ReviewToken = true, false, "source-review-token"
	u.record = record
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	bound, loaded, err := a.load(ctx, record.Job.ID)
	if err != nil || bound.FileReviewSHA256 != shaReview || !reflect.DeepEqual(review, loaded) {
		t.Fatal("owner publication did not bind the producer output", err)
	}
	if required, err := a.requiredJournalReadVersion(ctx); err != nil || required != SelfUpdateReadVersion {
		t.Fatal("published reader4 proof was unreadable", required, err)
	}
	var decoded updateRecord
	if json.Unmarshal(before, &decoded) != nil || decoded.FileReviewSHA256 != "" || decoded.Files != nil || decoded.ExecutableHash != "" {
		t.Fatal("fixture did not exercise the real unpublished producer state")
	}
}
