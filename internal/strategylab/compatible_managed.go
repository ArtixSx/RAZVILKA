package strategylab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// The bootstrap lease proves installation material during this construction,
// then stays owned by the caller. Only the concrete control owner and detached
// descriptor are retained. Each validation needs a fresh actual runtime lease.
func NewManagedSupervisedCompatibilityProvider(ctx context.Context, manager *Manager, runtime *components.ManagedNFQWSRuntimeLease, control *operationgate.ControlEpochReview, controlRoot string) (*SupervisedCompatibilityProvider, CompatibleValidator, error) {
	if manager == nil || runtime == nil || control == nil || selectedReviewContext(ctx) != nil || !control.MatchesControlRoot(controlRoot) {
		return nil, CompatibleValidator{}, errAdaptiveManagedValidator
	}
	if err := errors.Join(control.Current(ctx), runtime.Check(ctx)); err != nil {
		return nil, CompatibleValidator{}, err
	}
	descriptor := runtime.Descriptor()
	approval, err := managedCompatibilityApproval(descriptor, controlRoot, control.Reference())
	if err != nil {
		return nil, CompatibleValidator{}, err
	}
	p, err := NewSupervisedCompatibilityProvider(manager, approval)
	if err != nil {
		return nil, CompatibleValidator{}, err
	}
	if err := errors.Join(control.Current(ctx), runtime.Check(ctx)); err != nil || !control.MatchesControlRoot(controlRoot) || !compatibilityJSONEqual(runtime.Descriptor(), descriptor) {
		return nil, CompatibleValidator{}, errors.Join(errAdaptiveManagedValidator, err)
	}
	p.managedControl, p.managedDescriptor = control, descriptor
	validator := CompatibleValidator{Binary: approval.BinaryPath, BaseArguments: slices.Clone(approval.BaseArguments), TrustedAssets: true, Timeout: 8 * time.Second, Provider: p}
	return p, validator, nil
}

type managedCompatibilityContextKey struct{}
type managedCompatibilityInvocation struct {
	manager       *Manager
	provider      *SupervisedCompatibilityProvider
	runtime       *components.ManagedNFQWSRuntimeLease
	binding       adaptiveCandidateBinding
	cleanup       *operationgate.ExclusiveCleanupReview
	phases        []*managedCompatibilityPhase
	finished      bool
	settled       bool
	image         restorejournal.Image
	file, parent  os.FileInfo
	runtimeClosed bool
	stageUnknown  bool
	refusal       *managedCompatibilityRefusal
	timing        *managedCompatibilityTiming
	forward       context.Context
}

// ManagedCompatibilityCompletion is issued only by this actual synchronous
// validation. It cannot be adopted, copied or reconstructed from a receipt.
// The original App admission stays held until RetireKnown succeeds.
type ManagedCompatibilityCompletion struct {
	self       *ManagedCompatibilityCompletion
	mu         sync.Mutex
	invocation *managedCompatibilityInvocation
	retired    bool
}

func (*ManagedCompatibilityCompletion) String() string {
	return "[private managed compatibility completion]"
}
func (*ManagedCompatibilityCompletion) GoString() string {
	return "[private managed compatibility completion]"
}

// ValidateManagedCandidate binds an existing candidate through this Manager;
// no caller Candidate, argument DTO, custom validator or generic callback can
// issue its private operation context. The caller retains the lease and original
// operation until the synchronous managed Run and sole helper Wait have joined.
// An unknown ECHILD/publication outcome retains the owner's fence and lease;
// returning a timeout or unknown is not permission to close those resources.
func (m *Manager) ValidateManagedCandidate(ctx context.Context, candidateID string, runtime *components.ManagedNFQWSRuntimeLease) (Candidate, *ManagedCompatibilityCompletion, error) {
	if m == nil || runtime == nil || selectedReviewContext(ctx) != nil {
		return Candidate{}, nil, errors.Join(errAdaptiveManagedValidator, selectedReviewContext(ctx))
	}
	foundation, err := newManagerAdaptiveFoundation(m)
	if err != nil {
		return Candidate{}, nil, err
	}
	m.mu.RLock()
	candidate, exists := m.state.Candidates[candidateID]
	validator, validatorErr := adaptiveManagedValidatorLocked(m)
	m.mu.RUnlock()
	if !exists || validatorErr != nil {
		return Candidate{}, nil, errors.Join(errAdaptiveCandidateChanged, validatorErr)
	}
	p := validator.(CompatibleValidator).Provider.(*SupervisedCompatibilityProvider)
	binding, err := foundation.bind(adaptiveCandidateDetached(candidate))
	if err != nil {
		return Candidate{}, nil, err
	}
	if p.managedControl == nil {
		return Candidate{}, nil, errAdaptiveManagedValidator
	}
	cleanup, err := p.managedControl.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return Candidate{}, nil, err
	}
	invocation := &managedCompatibilityInvocation{manager: m, provider: p, runtime: runtime, binding: binding, timing: &managedCompatibilityTiming{started: time.Now()}}
	invocation.cleanup = cleanup
	ctx = context.WithValue(ctx, managedCompatibilityContextKey{}, invocation)
	p.mu.Lock()
	if !p.running && p.managedInvocation == nil {
		p.managedTiming = invocation.timing
	}
	p.mu.Unlock()
	preflightTiming := invocation.timing.begin(ctx, "admission-material", "admission")
	preflightErr := p.managedMaterialCurrent(ctx)
	preflightTiming(preflightErr)
	if preflightErr != nil {
		return Candidate{}, nil, preflightErr
	}
	p.mu.Lock()
	if p.managedInvocation != nil || p.running || p.unknown {
		p.mu.Unlock()
		return Candidate{}, nil, errCompatibilityBusy
	}
	p.managedInvocation = invocation
	p.managedTiming = invocation.timing
	p.mu.Unlock()
	completion := &ManagedCompatibilityCompletion{invocation: invocation}
	completion.self = completion
	validationTiming := invocation.timing.begin(ctx, "validate-bound", "validation")
	candidate, err = foundation.validateBound(ctx, binding)
	validationTiming(err)
	finishTiming := invocation.timing.begin(ctx, "invocation-finish", "cleanup")
	settleErr := invocation.finish()
	finishTiming(settleErr)
	return candidate, completion, errors.Join(err, settleErr)
}

// No Manager reentry: this is also called under Manager.mu by final publication.
func (p *SupervisedCompatibilityProvider) managedMaterialCurrent(ctx context.Context) error {
	if p == nil || p.self != p || p.managedControl == nil || selectedReviewContext(ctx) != nil {
		return errAdaptiveManagedValidator
	}
	invocation, ok := ctx.Value(managedCompatibilityContextKey{}).(*managedCompatibilityInvocation)
	if !ok || invocation == nil || invocation.manager != p.manager || invocation.provider != p || invocation.runtime == nil || invocation.binding.manager != p.manager || !p.managedControl.MatchesControlRoot(p.review.ControlPath) {
		return errAdaptiveManagedValidator
	}
	ref := p.managedControl.Reference()
	if ref.InstallationID != p.review.InstallationID || ref.Sequence != p.review.Sequence {
		return errAdaptiveManagedValidator
	}
	if err := p.managedControl.Current(ctx); err != nil {
		return err
	}
	if err := invocation.runtime.Check(ctx); err != nil {
		return err
	}
	if !compatibilityJSONEqual(invocation.runtime.Descriptor(), p.managedDescriptor) || selectedReviewMaterial(p.review, p.managedDescriptor) != nil {
		return errAdaptiveManagedValidator
	}
	return nil
}

func managedCompatibilityRun(ctx context.Context, p *SupervisedCompatibilityProvider) bool {
	if ctx == nil || p == nil || p.self != p || p.managedControl == nil {
		return false
	}
	invocation, ok := ctx.Value(managedCompatibilityContextKey{}).(*managedCompatibilityInvocation)
	return ok && invocation != nil && invocation.provider == p && invocation.manager == p.manager
}

// This maps already checked owner material to the existing compatibility
// declaration. The declaration alone is comparison data, never admission.
func managedCompatibilityApproval(d components.NFQWSRuntimeDescriptor, controlPath string, ref operationgate.ControlEpochReference) (CompatibilityApproval, error) {
	if !compatibilityHex(d.ReceiptID, 32) || !compatibilityHex(d.ManifestSHA256, 64) || !compatibilityCleanPath(d.GenerationPath) || !compatibilityCleanPath(controlPath) || !compatibilityHex(ref.InstallationID, 32) || ref.Sequence == 0 || len(d.Lua) != 3 || len(d.Blobs) != 2 {
		return CompatibilityApproval{}, errors.New("managed compatibility requires the exact current owner material")
	}
	approval := CompatibilityApproval{BinaryPath: d.Executable.Path, BinarySHA256: d.Executable.SHA256,
		ControlPath: controlPath, InstallationID: ref.InstallationID, Sequence: ref.Sequence}
	if !managedCompatibilityAsset(d.GenerationPath, d.Executable.Path, d.Executable.SHA256) {
		return CompatibilityApproval{}, ErrSelectedCandidateChanged
	}
	for _, asset := range d.Lua {
		if !managedCompatibilityAsset(d.GenerationPath, asset.Path, asset.SHA256) {
			return CompatibilityApproval{}, ErrSelectedCandidateChanged
		}
		approval.Assets = append(approval.Assets, CompatibilityApprovedAsset{Path: asset.Path, SHA256: asset.SHA256})
		approval.BaseArguments = append(approval.BaseArguments, "--lua-init=@"+asset.Path)
	}
	for i, blob := range d.Blobs {
		expected := "quic_initial"
		if i == 1 {
			expected = "tls_clienthello"
		}
		if blob.Alias != expected || !managedCompatibilityAsset(d.GenerationPath, blob.Path, blob.SHA256) {
			return CompatibilityApproval{}, ErrSelectedCandidateChanged
		}
		approval.Assets = append(approval.Assets, CompatibilityApprovedAsset{Path: blob.Path, SHA256: blob.SHA256})
		approval.BaseArguments = append(approval.BaseArguments, "--blob="+blob.Alias+":@"+blob.Path)
	}
	return approval, nil
}

func managedCompatibilityAsset(generation, path, digest string) bool {
	if !compatibilityCleanPath(path) || !compatibilityHex(digest, 64) {
		return false
	}
	relative, err := filepath.Rel(generation, path)
	return err == nil && relative != "." && filepath.IsLocal(relative)
}
