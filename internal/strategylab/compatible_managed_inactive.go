package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// ManagedCompatibilityInactiveReview observes this actual source owner only.
// The installer must separately hold the SAME component writer lease and
// original App admission. This is no kernel-wide/stock-process inactivity proof.
type ManagedCompatibilityInactiveReview struct {
	self          *ManagedCompatibilityInactiveReview
	mu            sync.Mutex
	closed        bool
	manager       *Manager
	control       *operationgate.ControlEpochReview
	cleanup       *operationgate.ExclusiveCleanupReview
	path          string
	image         restorejournal.Image
	file, parent  os.FileInfo
	provider      *SupervisedCompatibilityProvider
	validatorKind string
}

func (*ManagedCompatibilityInactiveReview) String() string {
	return "[private managed compatibility inactive source]"
}
func (*ManagedCompatibilityInactiveReview) GoString() string {
	return "[private managed compatibility inactive source]"
}

// This readonly issuer creates neither a source file nor an empty proof.
// It must run before InstallManagedBundle; Current never reenters Components.
func (m *Manager) ReviewManagedCompatibilityInactive(ctx context.Context, control *operationgate.ControlEpochReview) (*ManagedCompatibilityInactiveReview, error) {
	if m == nil || control == nil || selectedReviewContext(ctx) != nil {
		return nil, ErrCompatibilityQuiescenceUnknown
	}
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, err
	}
	r := &ManagedCompatibilityInactiveReview{manager: m, control: control, cleanup: cleanup}
	r.self = r
	m.mu.RLock()
	r.path, r.image = m.Path, compatibilityImageCopy(m.image)
	r.provider, r.validatorKind, err = managedCompatibilityInactiveStateLocked(m, control)
	m.mu.RUnlock()
	if err != nil || !r.image.Exists || !compatibilityCleanPath(r.path) {
		return nil, errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	r.file, err = selectedReviewFileIdentity(r.path)
	if err == nil {
		r.parent, err = selectedReviewFileIdentity(filepath.Dir(r.path))
	}
	if err != nil {
		return nil, err
	}
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *ManagedCompatibilityInactiveReview) Current(ctx context.Context) error {
	if r == nil || r.self != r || selectedReviewContext(ctx) != nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.manager == nil || r.control == nil || r.cleanup == nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	return r.cleanup.WithCurrent(ctx, func() error {
		if err := r.control.Current(ctx); err != nil {
			return err
		}
		m := r.manager
		m.mu.RLock()
		defer m.mu.RUnlock()
		provider, kind, err := managedCompatibilityInactiveStateLocked(m, r.control)
		if err != nil || provider != r.provider || kind != r.validatorKind || m.Path != r.path || !compatibilityImageEqual(m.image, r.image) {
			return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
		}
		if err := errors.Join(compatibilityProtectedPath(r.path, false), compatibilityPrivateStateParent(r.path)); err != nil {
			return err
		}
		file, err := selectedReviewFileIdentity(r.path)
		parent, parentErr := selectedReviewFileIdentity(filepath.Dir(r.path))
		if err != nil || parentErr != nil || !os.SameFile(file, r.file) || !os.SameFile(parent, r.parent) {
			return ErrCompatibilityQuiescenceUnknown
		}
		image, err := restorejournal.ReadFileImage(ctx, r.path)
		var actual State
		decoder := json.NewDecoder(bytes.NewReader(image.Data))
		decoder.DisallowUnknownFields()
		if err != nil || !compatibilityImageEqual(image, r.image) || compatibilityJSONUnique(image.Data) != nil || decoder.Decode(&actual) != nil || decoder.Decode(new(any)) != io.EOF || !compatibilityJSONEqual(actual, m.state) {
			return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
		}
		file, err = selectedReviewFileIdentity(r.path)
		parent, parentErr = selectedReviewFileIdentity(filepath.Dir(r.path))
		if err != nil || parentErr != nil || !os.SameFile(file, r.file) || !os.SameFile(parent, r.parent) {
			return ErrCompatibilityQuiescenceUnknown
		}
		return r.control.Current(ctx)
	})
}

func (r *ManagedCompatibilityInactiveReview) Close() error {
	if r == nil {
		return nil
	}
	if r.self != r {
		return ErrCompatibilityQuiescenceUnknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// Source-only predicate for portable model refusal tests. Passing it never
// issues the public review; protected source and original control are required.
func managedCompatibilityInactiveStateLocked(m *Manager, control *operationgate.ControlEpochReview) (*SupervisedCompatibilityProvider, string, error) {
	if m == nil || m.Executor != nil || m.nativeRunning || m.writeBlocked || m.compatibilityUnknownLocked() {
		return nil, "", ErrCompatibilityQuiescenceUnknown
	}
	var provider *SupervisedCompatibilityProvider
	kind := ""
	switch configured := m.Validator.(type) {
	case nil:
		kind = "unconfigured"
	case ExecValidator:
		if configured != (ExecValidator{}) {
			return nil, "", errAdaptiveManagedValidator
		}
		kind = "initial"
	case CompatibleValidator, *CompatibleValidator:
		var disabled CompatibleValidator
		switch value := configured.(type) {
		case CompatibleValidator:
			disabled = value
		case *CompatibleValidator:
			if value == nil {
				return nil, "", errAdaptiveManagedValidator
			}
			disabled = *value
		}
		if disabled.Binary == "" && len(disabled.BaseArguments) == 0 && !disabled.TrustedAssets && disabled.Timeout == 0 && disabled.Provider == nil {
			kind = "disabled-compatible"
			break
		}
		validator, err := adaptiveManagedValidatorLocked(m)
		if err != nil {
			return nil, "", err
		}
		provider = validator.(CompatibleValidator).Provider.(*SupervisedCompatibilityProvider)
		if provider.self != provider || provider.managedControl == nil || provider.managedControl != control {
			return nil, "", errAdaptiveManagedValidator
		}
		kind = "managed"
	default:
		return nil, "", errAdaptiveManagedValidator
	}
	if provider != nil {
		provider.mu.Lock()
		defer provider.mu.Unlock()
		if provider.running || provider.unknown || provider.managedInvocation != nil {
			return nil, "", ErrCompatibilityQuiescenceUnknown
		}
	}
	if m.state.CompatibilitySession == nil {
		if m.state.SchemaVersion != SchemaVersion || m.state.CompatibilityFinalizing || provider != nil && (provider.session != nil || provider.managedRetiredSession != nil) {
			return nil, "", ErrCompatibilityQuiescenceUnknown
		}
		for _, candidate := range m.state.Candidates {
			if candidate.Validation.Native || candidate.Validation.LuaChecked || candidate.Validation.QuiescenceUnknown {
				return nil, "", ErrCompatibilityQuiescenceUnknown
			}
		}
		return provider, kind, nil
	}
	if m.state.SchemaVersion != compatibilitySupervisedSchema || provider == nil || provider.managedRetiredSession == nil || !compatibilityJSONEqual(provider.session, m.state.CompatibilitySession) || !compatibilityJSONEqual(provider.managedRetiredSession, m.state.CompatibilitySession) || compatibilitySessionUnknown(*m.state.CompatibilitySession) {
		return nil, "", ErrCompatibilityQuiescenceUnknown
	}
	return provider, kind, nil
}
