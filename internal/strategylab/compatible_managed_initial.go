package strategylab

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// InitializeManagedCompatibilitySource is an explicit Install POST write by
// this configured Manager, under the actual original operation/control owner.
// It creates only the canonical initial closed source when this Manager read
// no source/history. Existing sources are observed and never overwritten.
// Success grants no inactivity, component, runtime or kernel permission: the
// caller must subsequently acquire the separate actual inactive review.
func (m *Manager) InitializeManagedCompatibilitySource(ctx context.Context, control *operationgate.ControlEpochReview) error {
	if m == nil || control == nil || selectedReviewContext(ctx) != nil {
		return ErrSelectedCandidateChanged
	}
	if err := control.Current(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	path := m.Path
	if !compatibilityCleanPath(path) || m.nativeRunning || m.compatibilityUnknownLocked() || m.writeBlocked {
		return ErrSelectedCandidateChanged
	}
	// This does not create a directory, repair modes or follow an untrusted
	// ancestor. The ordinary configured source parent must already be private.
	if err := errors.Join(compatibilityProtectedPath(path, !m.image.Exists), compatibilityPrivateStateParent(path)); err != nil {
		return err
	}
	parent, err := selectedReviewFileIdentity(filepath.Dir(path))
	if err != nil {
		return err
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return err
	}
	defer target.Close()
	current, err := target.Read(ctx)
	if err != nil || !compatibilityImageEqual(current, m.image) {
		return errors.Join(restorejournal.ErrConflict, err)
	}
	if current.Exists {
		// A real existing source is deliberately not adopted or initialized.
		// Its separate inactive review checks schema, history and producer proof.
		return control.Current(ctx)
	}
	if err := m.managedCompatibilityInitialStateLocked(control); err != nil {
		return err
	}
	data, err := json.MarshalIndent(emptyState(), "", "  ")
	if err != nil {
		return err
	}
	after := restorejournal.Image{Exists: true, Data: append(data, '\n')}
	err = target.CompareAndSwapWithRenameAdmission(ctx, m.image, after,
		func(original context.Context, rename func() error) error {
			if original != ctx {
				return ErrSelectedCandidateChanged
			}
			return control.WithRename(original, rename)
		}, func() error {
			if m.compatibilityPublicationHook != nil {
				m.compatibilityPublicationHook("initial-source-prepared")
			}
			closing, err := selectedReviewFileIdentity(filepath.Dir(path))
			if err != nil || m.Path != path || !os.SameFile(parent, closing) {
				return ErrSelectedCandidateChanged
			}
			if err := errors.Join(compatibilityProtectedPath(path, true), compatibilityPrivateStateParent(path), m.managedCompatibilityInitialStateLocked(control)); err != nil {
				return err
			}
			return control.Current(ctx)
		})
	if err != nil {
		if errors.Is(err, restorejournal.ErrRecovery) {
			// An attempted rename/unretired stage is not silently adopted. The
			// owner refuses later writes; no process or native proof was issued.
			m.writeBlocked = true
		}
		return err
	}
	// The primitive already confirmed directory sync and exact readback. Keep
	// its actual image even if a subsequent Stop revokes installation admission.
	m.image = compatibilityImageCopy(after)
	if m.compatibilityPublicationHook != nil {
		m.compatibilityPublicationHook("initial-source-written")
	}
	closing, err := selectedReviewFileIdentity(filepath.Dir(path))
	if err != nil || m.Path != path || !os.SameFile(parent, closing) {
		m.writeBlocked = true
		return ErrSelectedCandidateChanged
	}
	return errors.Join(compatibilityProtectedPath(path, false), control.Current(ctx))
}

// Pure original-state check; it issues no source or inactivity capability.
func (m *Manager) managedCompatibilityInitialStateLocked(control *operationgate.ControlEpochReview) error {
	if m == nil || m.image.Exists || len(m.image.Data) != 0 || !compatibilityJSONEqual(m.state, emptyState()) {
		return ErrSelectedCandidateChanged
	}
	_, _, err := managedCompatibilityInactiveStateLocked(m, control)
	return err
}
