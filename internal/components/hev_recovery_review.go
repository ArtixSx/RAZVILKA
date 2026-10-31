package components

import (
	"context"
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type HEVReleaseRecoveryReview struct {
	Identity string `json:"identity"`
	Pending  bool   `json:"pending"`
}

// InspectHEVReleaseRecovery creates no file or writer marker. It takes the
// original journal lease only to snapshot its actual typed document. Current
// binary/receipt corruption cannot hide that journal from the recovery panel.
func (m *Manager) InspectHEVReleaseRecovery(ctx context.Context) (review HEVReleaseRecoveryReview, err error) {
	if m == nil || ctx == nil {
		return review, restorejournal.ErrUnavailable
	}
	if !m.mu.TryLock() {
		return review, restorejournal.ErrBusy
	}
	defer m.mu.Unlock()
	root, scope, paths, err := m.hevReleaseLayout()
	if err != nil {
		return review, err
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return review, ctx.Err()
	}
	targets := map[string]restorejournal.Target{}
	for id := range paths {
		targets[id] = hevIdleTarget{}
	}
	journal, err := restorejournal.OpenExisting(root, scope, targets)
	if err != nil {
		return review, err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	review.Identity, review.Pending, err = journal.RecoveryIdentity(ctx)
	return review, err
}

// RecoverHEVReleaseReviewed refuses a changed transaction under the actual
// same original journal lease that will perform the recovery. Client input can
// select neither a target path nor a different retained transaction to undo.
func (m *Manager) RecoverHEVReleaseReviewed(ctx context.Context, expectedIdentity string) (out restorejournal.Outcome, err error) {
	if m == nil || ctx == nil || !bundleHash(expectedIdentity, 64) {
		return restorejournal.Blocked, restorejournal.ErrInvalid
	}
	if !m.mu.TryLock() {
		return restorejournal.Blocked, restorejournal.ErrBusy
	}
	defer m.mu.Unlock()
	session, err := m.openHEVRelease(false)
	if err != nil {
		return restorejournal.Blocked, err
	}
	defer func() { err = errors.Join(err, session.close()) }()
	identity, _, err := session.j.RecoveryIdentity(ctx)
	if err != nil {
		return restorejournal.Blocked, err
	}
	if identity != expectedIdentity {
		return restorejournal.Blocked, restorejournal.ErrConflict
	}
	out, err = session.j.Recover(ctx)
	return out, errors.Join(err, errors.Join(session.failures...))
}
