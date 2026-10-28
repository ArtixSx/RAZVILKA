package updatecheck

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// OrdinaryInstallerControllerReview selects the verifier from the actual
// immutable review. It grants no role, effect or inactivity result. false,nil
// means an explicitly bound bootstrap review; malformed ordinary reviews fail
// and cannot select the bootstrap verifier. Each selected verifier must still
// prove the complete current native controller group.
func (a *SelfUpdateFileAdapter) OrdinaryInstallerControllerReview(ctx context.Context, id string) (bool, error) {
	if a == nil || ctx == nil || !jobIDPattern.MatchString(id) {
		return false, ErrOrdinaryInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if !finite || !deadline.After(time.Now()) || ctx.Err() != nil {
		return false, errors.Join(ErrOrdinaryInstallerControllerRole, ctx.Err())
	}
	return a.ordinaryInstallerControllerReview(ctx, id)
}

func ordinaryInstallerReviewKind(review fileReview, record updateRecord) (bool, error) {
	if !validFileReviewOwner(review, record) || record.Owner != updaterOwner || review.ID != record.Job.ID ||
		record.Job.Release == nil || review.ReleaseID != record.Job.Release.ID || review.Revision != record.Job.ConfigRevision ||
		review.OldVersion != record.CurrentVersion || review.NewVersion != record.Job.Release.Version || review.OldExecutableSHA256 != record.ExecutableHash {
		return false, ErrOrdinaryInstallerControllerRole
	}
	if review.Bootstrap != nil {
		return false, nil
	}
	if !ordinaryFutureVersions(review.OldVersion, review.NewVersion) ||
		!validJournalReaderProof(review.JournalReaders) || review.JournalReaders.RequiredReader != selfupdatejournal.PairedSchema {
		return false, ErrOrdinaryInstallerControllerRole
	}
	return true, nil
}
