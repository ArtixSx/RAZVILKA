package strategylab

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Retry belongs to this original completed invocation only. It can observe a
// late exact ACK or confirm our exact no-start/refusal CAS; it cannot adopt a
// historical session, accept a third image or resume either native phase.
func (i *managedCompatibilityInvocation) recoverOriginal(ctx context.Context) error {
	if i == nil || i.cleanup == nil || !i.finished || i.stageUnknown || len(i.phases) == 0 {
		return ErrCompatibilityQuiescenceUnknown
	}
	return i.cleanup.WithCurrent(ctx, func() error {
		if err := i.cleanupCurrent(ctx); err != nil {
			return err
		}
		m, provider := i.manager, i.provider
		m.mu.Lock()
		defer m.mu.Unlock()
		provider.mu.Lock()
		defer provider.mu.Unlock()
		if provider.managedInvocation != i || provider.running || m.nativeRunning {
			return ErrCompatibilityQuiescenceUnknown
		}
		target, err := restorejournal.OpenFileTarget(m.Path)
		if err != nil {
			return err
		}
		defer target.Close()
		current, err := target.Read(ctx)
		if err != nil {
			return err
		}
		phase := i.phases[len(i.phases)-1]
		if !phase.rolledBack && !phase.acknowledged {
			if !phase.launched {
				if !compatibilityImageEqual(current, phase.beforeImage) {
					if !compatibilityImageEqual(current, phase.intentImage) {
						return restorejournal.ErrConflict
					}
					if err := target.CompareAndSwap(ctx, current, phase.beforeImage); err != nil {
						return err
					}
				}
				current = compatibilityImageCopy(phase.beforeImage)
				m.state, m.image, phase.rolledBack = phase.before, current, true
			} else {
				if !phase.joined {
					return ErrCompatibilityQuiescenceUnknown
				}
				intent, err := decodeCompatibilityState(phase.intentImage)
				if err != nil {
					return err
				}
				actual, err := decodeCompatibilityState(current)
				if err != nil {
					return err
				}
				active := compatibilityActiveInvocation(actual.CompatibilitySession)
				if active == nil || !compatibilityHelperMatches(active.Receipt, phase.helper) || !compatibilityReceiptTerminal(active.Receipt) {
					return ErrCompatibilityQuiescenceUnknown
				}
				if active.Acknowledged {
					if !phase.ackImage.Exists || !compatibilityImageEqual(current, phase.ackImage) {
						return ErrCompatibilityQuiescenceUnknown
					}
				} else {
					if !compatibilityResultMatches(intent, actual) {
						return ErrCompatibilityQuiescenceUnknown
					}
					active.Acknowledged = true
					ack, err := compatibilityStateImage(actual)
					if err != nil {
						return err
					}
					phase.ackImage = compatibilityImageCopy(ack)
					if err := target.CompareAndSwap(ctx, current, ack); err != nil {
						return err
					}
					current = ack
				}
				m.state, m.image, phase.acknowledged = actual, current, true
				provider.session = actual.CompatibilitySession
			}
		}
		if !i.phasesKnown() {
			return ErrCompatibilityQuiescenceUnknown
		}
		if i.refusal == nil {
			// A real phase/rollback was recovered. Clear its finalizing marker
			// only with a durable known rejection of the original candidate.
			expected := phase.ackImage
			if phase.rolledBack {
				expected = phase.beforeImage
			}
			if !compatibilityImageEqual(current, expected) {
				return restorejournal.ErrConflict
			}
			var state State
			if !current.Exists || json.Unmarshal(current.Data, &state) != nil {
				return ErrCompatibilityQuiescenceUnknown
			}
			candidate, exists := state.Candidates[i.binding.candidate.ID]
			if !exists || !adaptiveCandidateIdentityEqual(candidate, i.binding.candidate) {
				return errAdaptiveCandidateChanged
			}
			candidate.Validation = compatibilityKnownRefusal(candidate.Validation)
			state.Candidates[candidate.ID], state.CompatibilityFinalizing = candidate, false
			data, err := json.MarshalIndent(state, "", "  ")
			if err != nil {
				return err
			}
			i.refusal = &managedCompatibilityRefusal{before: compatibilityImageCopy(current), after: restorejournal.Image{Exists: true, Data: append(data, '\n')}, state: state}
		}
		refusal := i.refusal
		if !compatibilityImageEqual(current, refusal.after) {
			if !compatibilityImageEqual(current, refusal.before) && (!refusal.proposed.Exists || !compatibilityImageEqual(current, refusal.proposed)) {
				return restorejournal.ErrConflict
			}
			if err := target.CompareAndSwap(ctx, current, refusal.after); err != nil {
				return err
			}
		}
		confirmed, err := target.Read(ctx)
		if err != nil || !compatibilityImageEqual(confirmed, refusal.after) {
			return errors.Join(restorejournal.ErrRecovery, err)
		}
		file, err := selectedReviewFileIdentity(m.Path)
		if err != nil {
			return err
		}
		parent, err := selectedReviewFileIdentity(filepath.Dir(m.Path))
		if err != nil {
			return err
		}
		if err := i.cleanupCurrent(ctx); err != nil {
			return err
		}
		frozen, err := compatibilityStateCopy(refusal.state)
		if err != nil {
			return err
		}
		m.state, m.image = frozen, compatibilityImageCopy(refusal.after)
		m.compatibilityUnknown, m.writeBlocked, provider.unknown = false, false, false
		i.file, i.parent, i.image, i.settled = file, parent, compatibilityImageCopy(confirmed), true
		return nil
	})
}
