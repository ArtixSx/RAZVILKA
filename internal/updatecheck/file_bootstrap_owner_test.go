package updatecheck

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func bootstrapOwnerFixture(t *testing.T) (*SelfUpdateFileAdapter, *Updater, fileReview) {
	t.Helper()
	a, u, review := fileAdapterFixture(t)
	review.Schema = selfupdatejournal.PairedSchema
	review.JournalReaders = nil
	review.OldVersion, u.record.CurrentVersion = "0.19.3", "0.19.3"
	u.record.Job.Release.Archive.Digest = "sha256:" + strings.Repeat("a", 64)
	review.Bootstrap = &fileBootstrapBinding{Role: externalOld193InstallerRole, HelperSHA256: strings.TrimPrefix(u.record.Job.Release.Binary.Digest, "sha256:"), ArchivePath: filepath.Join(t.TempDir(), "release.tar.gz"), ArchiveSHA256: strings.Repeat("a", 64)}
	newProgram, err := os.ReadFile(filepath.Join(a.directory, review.ID, "bundle/dist", u.record.Job.Release.Binary.Name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "control.bin"), newProgram, 0700); err != nil {
		t.Fatal(err)
	}
	saveStoppedReview(t, a, u, review)
	return a, u, review
}

func TestBootstrapReviewBindsCandidateHelperWithoutAdoptingOldSource(t *testing.T) {
	a, u, review := bootstrapOwnerFixture(t)
	ctx := context.Background()
	_, loaded, err := a.load(ctx, review.ID)
	if err != nil || loaded.OldExecutableSHA256 != u.record.ExecutableHash || reviewedHelperSHA(loaded) == loaded.OldExecutableSHA256 {
		t.Fatal("candidate helper erased or adopted the old source identity", err)
	}
	if required, err := a.requiredJournalReadVersion(ctx); err != nil || required != selfupdatejournal.PairedSchema {
		t.Fatal("bootstrap review was disguised as ordinary format2", required, err)
	}
	u.record.Job.HelperPID, u.record.ParentPID = 20, 21
	saveStoppedReview(t, a, u, review)
	helper := fileProcess{Boot: "01234567-89ab-cdef-0123-456789abcdef", PID: 20, Start: "10", ExecutableSHA256: reviewedHelperSHA(review), Device: 1, Inode: 2}
	panel := helper
	panel.PID, panel.ExecutableSHA256 = 21, review.OldExecutableSHA256
	data, _ := json.Marshal(fileHelperIdentity{selfUpdateProtocolSchema, review.ID, helper, panel})
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "helper.identity.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.helperIdentity(review.ID, review); err != nil || a.checkHelperProcessFormats(ctx, u.record, review) != nil {
		t.Fatal("different real helper/panel image bindings were conflated", err)
	}
	helper.ExecutableSHA256 = review.OldExecutableSHA256
	data, _ = json.Marshal(fileHelperIdentity{selfUpdateProtocolSchema, review.ID, helper, panel})
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "helper.identity.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.helperIdentity(review.ID, review); err == nil || a.checkHelperProcessFormats(ctx, u.record, review) == nil {
		t.Fatal("old source was accepted as the candidate helper")
	}
}

func TestBootstrapOwnerCannotBeBorrowedByOtherFormatOrRelease(t *testing.T) {
	for _, kind := range []string{"ordinary2", "missing-owner", "old-owner", "other-owner", "wrong-asset", "stopped-proof", "role", "archive", "source-version"} {
		t.Run(kind, func(t *testing.T) {
			a, u, review := bootstrapOwnerFixture(t)
			switch kind {
			case "ordinary2":
				review.Schema = selfUpdateProtocolSchema
			case "missing-owner":
				review.Bootstrap = nil
			case "old-owner":
				review.Bootstrap.HelperSHA256 = review.OldExecutableSHA256
			case "other-owner":
				review.Bootstrap.HelperSHA256 = strings.Repeat("e", 64)
			case "wrong-asset":
				u.record.Files["dist/"+u.record.Job.Release.Binary.Name] = strings.Repeat("e", 64)
			case "stopped-proof":
				review.JournalReaders = &journalReaderProof{}
			case "role":
				review.Bootstrap.Role = "controller"
			case "archive":
				review.Bootstrap.ArchiveSHA256 = strings.Repeat("b", 64)
			case "source-version":
				review.OldVersion, u.record.CurrentVersion = "0.20.0", "0.20.0"
			}
			saveStoppedReview(t, a, u, review)
			if _, _, err := a.load(context.Background(), review.ID); err == nil {
				t.Fatal("bootstrap owner was borrowed from incompatible evidence")
			}
		})
	}
}
