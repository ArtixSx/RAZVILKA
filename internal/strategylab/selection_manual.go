package strategylab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const (
	manualSelectionUncheckedStatus = "manual-unchecked"
	manualSelectionUncheckedReason = "стратегия выбрана вручную; проверка здоровья ещё не выполнена"
)

// SelectManual saves an explicit frozen choice after the original managed
// native compatibility owner has completed and retired. It does not run a
// probe, award health, create evidence or grant launch permission. The caller
// retains its actual App operation and this same component lease through the
// call and its closing checks. Select continues to require eligible evidence.
func (m *Manager) SelectManual(ctx context.Context, serviceID, protocol, family, candidateID string, runtime *components.ManagedNFQWSRuntimeLease) (Selection, error) {
	if m == nil || runtime == nil || selectedReviewContext(ctx) != nil || !selectedReviewKeyValid(serviceID, protocol, family) {
		return Selection{}, errors.Join(ErrSelectedCandidateChanged, selectedReviewContext(ctx))
	}
	if err := runtime.Check(ctx); err != nil {
		return Selection{}, errors.Join(ErrSelectedCandidateChanged, err)
	}
	foundation, err := newManagerAdaptiveFoundation(m)
	if err != nil {
		return Selection{}, err
	}
	m.mu.RLock()
	candidate, exists := m.state.Candidates[candidateID]
	validator, validatorErr := adaptiveManagedValidatorLocked(m)
	m.mu.RUnlock()
	if !exists || validatorErr != nil {
		return Selection{}, errors.Join(ErrSelectedCandidateChanged, validatorErr)
	}
	binding, err := foundation.bind(adaptiveCandidateDetached(candidate))
	if err != nil {
		return Selection{}, err
	}
	provider := validator.(CompatibleValidator).Provider.(*SupervisedCompatibilityProvider)
	if provider.self != provider || provider.managedControl == nil {
		return Selection{}, ErrSelectedCandidateChanged
	}
	// This is the original provider's actual control, under the caller's fresh
	// exclusive operation. The bounded rename below uses this same owner.
	if err := provider.managedControl.Current(ctx); err != nil {
		return Selection{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := selectionKey(serviceID, protocol, family)
	selection := manualSelection(serviceID, protocol, family, candidateID, m.state.Selections[key], m.now())
	r := &SelectedCandidateReview{binding: binding, selection: selection, runtime: runtime, descriptor: runtime.Descriptor()}
	// This private comparison object is never returned as a public review.
	if err := r.retainSourceLocked(); err != nil {
		return Selection{}, err
	}
	if r.provider != provider {
		return Selection{}, ErrSelectedCandidateChanged
	}
	if err := r.manualChoiceCurrentLocked(ctx); err != nil {
		return Selection{}, err
	}
	next, err := compatibilityStateCopy(m.state)
	if err != nil {
		return Selection{}, err
	}
	next.Selections[key] = selection
	next.SchemaVersion = compatibilitySupervisedSchema
	after, err := compatibilityStateImage(next)
	if err != nil {
		return Selection{}, err
	}
	target, err := restorejournal.OpenFileTarget(r.path)
	if err != nil {
		return Selection{}, err
	}
	defer target.Close()
	err = target.CompareAndSwapWithRenameAdmission(ctx, r.image, after,
		func(original context.Context, rename func() error) error {
			if original != ctx {
				return ErrSelectedCandidateChanged
			}
			return provider.managedControl.WithRename(original, rename)
		}, func() error {
			if m.compatibilityPublicationHook != nil {
				m.compatibilityPublicationHook("manual-selection-prepared")
			}
			return r.manualChoiceCurrentLocked(ctx)
		})
	if err != nil {
		if errors.Is(err, restorejournal.ErrRecovery) || errors.Is(err, restorejournal.ErrConflict) {
			m.writeBlocked = true
		}
		return Selection{}, err
	}
	// The actual CAS already synced and read back this exact image. Keep that
	// known result even if a subsequent Stop revokes the closing observation.
	m.state, m.image = next, compatibilityImageCopy(after)
	r.image = compatibilityImageCopy(after)
	r.file, err = selectedReviewFileIdentity(r.path)
	if err != nil {
		m.writeBlocked = true
		return Selection{}, err
	}
	parent, err := selectedReviewFileIdentity(filepath.Dir(r.path))
	if err != nil || !os.SameFile(r.parent, parent) {
		m.writeBlocked = true
		return Selection{}, errors.Join(ErrSelectedCandidateChanged, err)
	}
	if err := r.currentLocked(ctx); err != nil {
		return Selection{}, err
	}
	if err := r.manualChoiceCurrentLocked(ctx); err != nil {
		return Selection{}, err
	}
	return selection, nil
}

func manualSelection(serviceID, protocol, family, candidateID string, previous Selection, now time.Time) Selection {
	selection := Selection{ServiceID: serviceID, Protocol: protocol, IPFamily: family, CandidateID: candidateID,
		Mode: ModeManual, Frozen: true, SelectedAt: now.UTC().Format(time.RFC3339),
		Status: manualSelectionUncheckedStatus, Reason: manualSelectionUncheckedReason}
	if previous.CandidateID != "" && previous.CandidateID != candidateID {
		selection.PreviousCandidateID = previous.CandidateID
	}
	return selection
}

// Caller holds Manager.mu. Saved receipts cannot supply this original
// process-lifetime retirement proof; only RetireKnown writes its source.
func (r *SelectedCandidateReview) manualChoiceCurrentLocked(ctx context.Context) error {
	if err := r.materialCurrentLocked(ctx); err != nil {
		return err
	}
	arguments, err := parseArguments(r.binding.candidate.Arguments)
	if err != nil {
		return err
	}
	if _, err := selectedCandidateTraffic(r.selection, arguments); err != nil {
		return err
	}
	p := r.provider
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.managedInvocation != nil || p.managedRetiredSession == nil || p.managedRetiredSession != p.session || !compatibilityJSONEqual(p.managedRetiredSession, r.binding.manager.state.CompatibilitySession) {
		return ErrSelectedCandidateChanged
	}
	return selectedReviewContext(ctx)
}

func manualSelectionHasEvidence(state State, selection Selection, now time.Time) bool {
	key := selectionKey(selection.ServiceID, selection.Protocol, selection.IPFamily)
	candidate := state.Candidates[selection.CandidateID]
	for _, item := range state.Evidence {
		if item.CandidateID != selection.CandidateID || selectionKey(item.ServiceID, item.Protocol, item.IPFamily) != key {
			continue
		}
		checked, err := time.Parse(time.RFC3339, item.CheckedAt)
		if err == nil && !checked.After(now) && normalizeEvidence(&item) == nil && reputationEvidence(item) && evidenceMatchesCandidate(item, candidate) {
			return true
		}
	}
	return false
}
