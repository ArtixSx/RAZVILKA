package strategylab

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var errManagedCompatibilityRefused = errors.New("managed compatibility validation was not published")

type managedCompatibilityRefusal struct {
	before, proposed, after restorejournal.Image
	state                   State
}

// Caller holds Manager.mu. A settled Stop/cancel/source-publication refusal
// revokes validation and clears only this producer's finalizing record. It
// never awards compatibility or writes over a third image.
func (m *Manager) publishManagedCompatibilityValidationLocked(parent context.Context, candidate Candidate, p *SupervisedCompatibilityProvider, i *managedCompatibilityInvocation) (resultErr error) {
	ctx, cancel := compatibilityPublicationContext(parent, compatibilityActiveInvocation(m.state.CompatibilitySession))
	defer cancel()
	endTiming := i.beginTiming(ctx, "guarded-publication", "publication")
	defer func() { endTiming(resultErr) }()
	current, exists := m.state.Candidates[candidate.ID]
	bound := candidate
	bound.Validation = current.Validation
	if !exists || !compatibilityJSONEqual(bound, current) || !i.phasesKnown() || m.compatibilityRetainedUnknownLocked() || m.writeBlocked {
		m.compatibilityUnknown = true
		return ErrCompatibilityQuiescenceUnknown
	}
	beforeState, copyErr := compatibilityStateCopy(m.state)
	if copyErr != nil {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, copyErr)
	}
	before := compatibilityImageCopy(m.image)
	if err := m.prepareCompatibilityPublicationLocked(ctx, candidate.Validation); err != nil {
		return m.refuseManagedCompatibilityLocked(i, nil, beforeState, before, restorejournal.Image{}, candidate, err)
	}
	next, err := compatibilityStateCopy(beforeState)
	if err != nil {
		return m.refuseManagedCompatibilityLocked(i, nil, beforeState, before, restorejournal.Image{}, candidate, err)
	}
	next.Candidates[candidate.ID], next.CompatibilityFinalizing = candidate, false
	after, err := compatibilityStateImage(next)
	if err != nil {
		return m.refuseManagedCompatibilityLocked(i, nil, beforeState, before, restorejournal.Image{}, candidate, err)
	}
	target, err := restorejournal.OpenFileTarget(m.Path)
	if err != nil {
		return m.refuseManagedCompatibilityLocked(i, nil, beforeState, before, after, candidate, err)
	}
	defer target.Close()
	casTiming := i.beginTiming(ctx, "publication-cas", "publication")
	writeErr := target.CompareAndSwapWithRenameAdmission(ctx, before, after,
		func(original context.Context, rename func() error) error {
			if original != ctx {
				return errAdaptiveManagedValidator
			}
			return p.managedControl.WithRename(original, rename)
		}, func() error {
			if m.compatibilityPublicationHook != nil {
				m.compatibilityPublicationHook("prepared")
			}
			return m.prepareCompatibilityPublicationLocked(ctx, candidate.Validation)
		})
	casTiming(writeErr)
	if writeErr != nil {
		if errors.Is(writeErr, ownedfs.ErrStagedCleanup) {
			// An unretired stage is still physically uncertain even if bytes match.
			m.compatibilityUnknown, m.writeBlocked = true, true
			i.stageUnknown = true
			return errors.Join(ErrCompatibilityQuiescenceUnknown, writeErr)
		}
		return m.refuseManagedCompatibilityLocked(i, target, beforeState, before, after, candidate, writeErr)
	}
	m.state, m.image = next, after
	if m.compatibilityPublicationHook != nil {
		m.compatibilityPublicationHook("written")
	}
	if err := m.preparePublishedCompatibilityResultLocked(ctx, candidate.Validation); err != nil {
		return m.refuseManagedCompatibilityLocked(i, target, beforeState, before, after, candidate, err)
	}
	return nil
}

func compatibilityKnownRefusal(validation Validation) Validation {
	validation.OK, validation.Native, validation.LuaChecked, validation.QuiescenceUnknown = false, false, false, false
	validation.Code = "VALIDATION_CANCELLED"
	return validation
}

func (m *Manager) refuseManagedCompatibilityLocked(i *managedCompatibilityInvocation, target *restorejournal.FileTarget, state State, before, proposed restorejournal.Image, candidate Candidate, cause error) error {
	if !i.phasesKnown() || state.CompatibilitySession == nil || compatibilitySessionUnknown(*state.CompatibilitySession) {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, cause)
	}
	next, err := compatibilityStateCopy(state)
	if err != nil {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	candidate.Validation = compatibilityKnownRefusal(candidate.Validation)
	next.Candidates[candidate.ID], next.CompatibilityFinalizing = candidate, false
	after, err := compatibilityStateImage(next)
	if err != nil {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	frozen, err := compatibilityStateCopy(next)
	if err != nil {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	i.refusal = &managedCompatibilityRefusal{before: compatibilityImageCopy(before), proposed: compatibilityImageCopy(proposed), after: compatibilityImageCopy(after), state: frozen}
	err = i.withCleanup(func(ctx context.Context) error {
		if target == nil {
			var err error
			target, err = restorejournal.OpenFileTarget(m.Path)
			if err != nil {
				return err
			}
			defer target.Close()
		}
		current, err := target.Read(ctx)
		if err != nil {
			return err
		}
		if !compatibilityImageEqual(current, before) && (!proposed.Exists || !compatibilityImageEqual(current, proposed)) {
			return restorejournal.ErrConflict
		}
		if err := target.CompareAndSwap(ctx, current, after); err != nil {
			return err
		}
		confirmed, err := target.Read(ctx)
		if err != nil || !compatibilityImageEqual(confirmed, after) {
			return errors.Join(restorejournal.ErrRecovery, err)
		}
		m.state, m.image = next, after
		return nil
	})
	if err != nil {
		m.compatibilityUnknown, m.writeBlocked = true, true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, cause, err)
	}
	// Actual tree proof + exact known refusal CAS, including directory sync and
	// readback, settled this original operation. Stop stays latched in control.
	m.compatibilityUnknown, m.writeBlocked = false, false
	knownCause := parentRefusalCause(cause)
	return errors.Join(errManagedCompatibilityRefused, knownCause)
}

func parentRefusalCause(cause error) error {
	if errors.Is(cause, operationgate.ErrSelfUpdateStopped) {
		return operationgate.ErrSelfUpdateStopped
	}
	if errors.Is(cause, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}
