package strategylab

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Caller owns Manager.mu and the existing validation admission. Serialize the
// complete image and open its existing CAS lease before the final ctx/epoch
// check. Neither this operation nor its repair uses the Start-only Stop lock.
// A CORE atomic-rename admission is still required for serial publication with
// Stop; pre/post checks cannot remove the crash interval between rename and
// re-fencing. Production capability must remain closed until that is wired.
func (m *Manager) publishCompatibilityValidationLocked(parent context.Context, candidate Candidate) error {
	current, exists := m.state.Candidates[candidate.ID]
	bound := candidate
	bound.Validation = current.Validation
	if !exists || !compatibilityJSONEqual(bound, current) {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, errors.New("validated candidate changed before publication"))
	}
	if err := m.prepareCompatibilityPublicationLocked(parent, candidate.Validation); err != nil {
		m.compatibilityUnknown = true
		return err
	}
	active := compatibilityActiveInvocation(m.state.CompatibilitySession)
	ctx, cancel := context.WithDeadline(parent, active.Command.Deadline)
	defer cancel()
	beforeState, before := m.state, m.image
	next := m.state
	next.Candidates = make(map[string]Candidate, len(m.state.Candidates))
	for id, existing := range m.state.Candidates {
		next.Candidates[id] = existing
	}
	next.Candidates[candidate.ID] = candidate
	next.CompatibilityFinalizing = false
	after, err := compatibilityStateImage(next)
	if err != nil {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	target, err := restorejournal.OpenFileTarget(m.Path)
	if err != nil {
		m.compatibilityUnknown = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	defer target.Close()
	if m.compatibilityPublicationHook != nil {
		m.compatibilityPublicationHook("prepared")
	}
	if err := m.prepareCompatibilityPublicationLocked(ctx, candidate.Validation); err != nil {
		m.compatibilityUnknown = true
		return err
	}
	writeErr := target.CompareAndSwap(ctx, before, after)
	if writeErr != nil {
		m.compatibilityUnknown, m.writeBlocked = true, true
		// A failed fsync can be after rename. Inspect only through our still
		// held exact descriptor, and repair only our exact proposed image.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), compatibilityCleanupWait)
		defer cleanupCancel()
		current, readErr := target.Read(cleanupCtx)
		if readErr == nil && current.Exists == after.Exists && bytes.Equal(current.Data, after.Data) {
			return m.retainCompatibilityPublicationUnknownLocked(target, next, after, candidate.ID, errors.Join(writeErr, ctx.Err()))
		}
		m.state, m.image = beforeState, before
		return errors.Join(ErrCompatibilityQuiescenceUnknown, writeErr, readErr)
	}
	m.state, m.image = next, after
	if m.compatibilityPublicationHook != nil {
		m.compatibilityPublicationHook("written")
	}
	if err := m.preparePublishedCompatibilityResultLocked(ctx, candidate.Validation); err != nil {
		return m.retainCompatibilityPublicationUnknownLocked(target, next, after, candidate.ID, err)
	}
	return nil
}

func (m *Manager) preparePublishedCompatibilityResultLocked(ctx context.Context, validation Validation) error {
	if ctx.Err() != nil || validation.QuiescenceUnknown || m.compatibilityRetainedUnknownLocked() || m.state.CompatibilitySession == nil {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, ctx.Err())
	}
	if !time.Now().Before(compatibilityActiveInvocation(m.state.CompatibilitySession).Command.Deadline) {
		return ErrCompatibilityQuiescenceUnknown
	}
	if err := compatibilityControlCurrent(ctx, compatibilityActiveInvocation(m.state.CompatibilitySession).Command.Review); err != nil {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	if ctx.Err() != nil {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, ctx.Err())
	}
	return nil
}

func (m *Manager) retainCompatibilityPublicationUnknownLocked(target *restorejournal.FileTarget, published State, image restorejournal.Image, candidateID string, cause error) error {
	m.compatibilityUnknown = true
	retained := published
	retained.CompatibilityFinalizing = true
	session := *published.CompatibilitySession
	session.Unknown = true
	retained.CompatibilitySession = &session
	retained.Candidates = make(map[string]Candidate, len(published.Candidates))
	for id, candidate := range published.Candidates {
		retained.Candidates[id] = candidate
	}
	// Keep unrelated accepted evidence; revoke only the final validation that
	// was published by this invocation, with its exact candidate argv.
	candidate := retained.Candidates[candidateID]
	candidate.Validation = compatibilityPublicationUnknown(candidate.Validation)
	retained.Candidates[candidateID] = candidate
	after, err := compatibilityStateImage(retained)
	if err == nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		err = target.CompareAndSwap(cleanupCtx, image, after)
		cancel()
	}
	m.state = retained
	if err != nil {
		m.writeBlocked = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, cause, err)
	}
	m.image = after
	return errors.Join(ErrCompatibilityQuiescenceUnknown, cause)
}

func compatibilityPublicationUnknown(validation Validation) Validation {
	validation.QuiescenceUnknown = true
	validation.OK, validation.Native, validation.LuaChecked = false, false, false
	validation.Code = "QUIESCENCE_UNKNOWN"
	return validation
}
