package strategylab

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var (
	errAdaptiveCandidateChanged = errors.New("adaptive candidate identity or provenance changed")
	errAdaptiveManagedValidator = errors.New("adaptive bound validation requires the same Manager's reviewed supervised validator")
	errAdaptivePackBinding      = errors.New("adaptive pack candidate membership is not recorded")
)

// This is candidate/validation plumbing only. It offers no probe consumer,
// production readiness, runtime lease or CORE publication admission. In
// particular it never adopts Manager.Executor, including custom executors.
type managerAdaptiveFoundation struct{ manager *Manager }

// Bindings are process-local snapshots of an existing Manager record. They are
// neither arguments-to-ID lookups nor transferable proof of runtime readiness.
type adaptiveCandidateBinding struct {
	manager   *Manager
	candidate Candidate
}

func newManagerAdaptiveFoundation(manager *Manager) (*managerAdaptiveFoundation, error) {
	if manager == nil {
		return nil, errors.New("adaptive candidate foundation requires a Manager")
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if manager.compatibilityUnknownLocked() || manager.writeBlocked {
		return nil, ErrCompatibilityQuiescenceUnknown
	}
	return &managerAdaptiveFoundation{manager: manager}, nil
}

func (f *managerAdaptiveFoundation) bind(expected Candidate) (adaptiveCandidateBinding, error) {
	if f == nil || f.manager == nil {
		return adaptiveCandidateBinding{}, errAdaptiveCandidateChanged
	}
	m := f.manager
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.compatibilityUnknownLocked() || m.writeBlocked || expected.Validation.QuiescenceUnknown {
		return adaptiveCandidateBinding{}, ErrCompatibilityQuiescenceUnknown
	}
	current, exists := m.state.Candidates[expected.ID]
	if !exists || !adaptiveCandidateIdentityEqual(current, expected) {
		return adaptiveCandidateBinding{}, errAdaptiveCandidateChanged
	}
	// Origin is a label, and PackReceipts binds only a whole reviewed payload.
	// Neither proves which payload contained this candidate. Do not manufacture
	// automatic pack authority until that actual membership is recorded.
	if strings.HasPrefix(current.Origin, "pack:") {
		return adaptiveCandidateBinding{}, errAdaptivePackBinding
	}
	return adaptiveCandidateBinding{manager: m, candidate: adaptiveCandidateDetached(current)}, nil
}

func (f *managerAdaptiveFoundation) validateBound(ctx context.Context, binding adaptiveCandidateBinding) (Candidate, error) {
	if f == nil || f.manager == nil || binding.manager != f.manager {
		return Candidate{}, errAdaptiveCandidateChanged
	}
	return f.manager.validateCandidate(ctx, binding.candidate.ID, &binding)
}

func adaptiveCandidateIdentityEqual(a, b Candidate) bool {
	return a.ID == b.ID && a.PoolID == b.PoolID && a.Name == b.Name && a.Arguments == b.Arguments && a.Origin == b.Origin && a.CreatedAt == b.CreatedAt
}

func adaptiveCandidateDetached(candidate Candidate) Candidate {
	candidate.Validation.Arguments = slices.Clone(candidate.Validation.Arguments)
	return candidate
}

// Caller holds Manager.mu. A result can become unknown after its candidate was
// deleted or rebound. Schema 2 itself retains that fence; schema 3 instead must
// retain it in the existing session without inventing a new invocation receipt
// or changing the newer candidate. Ordinary saveLocked cannot advance this
// fenced session, so use its same exact file image and bounded CAS cleanup path.
func (m *Manager) retainAdaptiveValidationUnknownLocked() error {
	if m.state.SchemaVersion != compatibilitySupervisedSchema {
		return m.saveLocked()
	}
	retained := m.state
	if retained.CompatibilitySession == nil {
		m.writeBlocked = true
		return ErrCompatibilityQuiescenceUnknown
	}
	session := *retained.CompatibilitySession
	session.Unknown = true
	retained.CompatibilitySession = &session
	retained.CompatibilityFinalizing = true
	m.state = retained
	after, err := compatibilityStateImage(retained)
	if err != nil {
		m.writeBlocked = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	target, err := restorejournal.OpenFileTarget(m.Path)
	if err != nil {
		m.writeBlocked = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	defer target.Close()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := target.CompareAndSwap(cleanupCtx, m.image, after); err != nil {
		m.writeBlocked = true
		return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	m.image = after
	return nil
}

// Caller holds Manager.mu. This recognizes only the existing concrete reviewed
// validator/provider pairing; an interface marker or a custom provider cannot
// create it. Acceptance here still grants no live probe/production capability.
func adaptiveManagedValidatorLocked(m *Manager) (Validator, error) {
	var validator CompatibleValidator
	switch configured := m.Validator.(type) {
	case CompatibleValidator:
		validator = configured
	case *CompatibleValidator:
		if configured == nil {
			return nil, errAdaptiveManagedValidator
		}
		validator = *configured
	default:
		return nil, errAdaptiveManagedValidator
	}
	provider, ok := validator.Provider.(*SupervisedCompatibilityProvider)
	if !ok || provider == nil || provider.manager != m || !validator.TrustedAssets || validator.Binary != provider.review.Binary.Path || !slices.Equal(validator.BaseArguments, provider.review.BaseArguments) || validateCompatibilityReview(provider.review) != nil {
		return nil, errAdaptiveManagedValidator
	}
	validator.BaseArguments = slices.Clone(validator.BaseArguments)
	return validator, nil
}
