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
// check. Actual managed publication admits only the prepared rename through
// its retained CORE control owner. Payload/directory sync and known-image
// unknown repair remain outside that admission. Legacy/native-QA publication
// retains its previous source-only behavior and cannot issue a managed review.
func (m *Manager) publishCompatibilityValidationLocked(parent context.Context, candidate Candidate) error {
	if parent != nil {
		if i, ok := parent.Value(managedCompatibilityContextKey{}).(*managedCompatibilityInvocation); ok && i != nil && i.manager == m && managedCompatibilityRun(parent, i.provider) {
			return m.publishManagedCompatibilityValidationLocked(parent, candidate, i.provider, i)
		}
	}
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
	prepare := func() error {
		if m.compatibilityPublicationHook != nil {
			m.compatibilityPublicationHook("prepared")
		}
		if err := m.prepareCompatibilityPublicationLocked(ctx, candidate.Validation); err != nil {
			m.compatibilityUnknown = true
			return err
		}
		return nil
	}
	if err := prepare(); err != nil {
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
