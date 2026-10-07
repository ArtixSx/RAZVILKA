package dataplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrScopedDNSRuntimeInactive = errors.New("fresh scoped DNS runtime inactivity proof is unavailable")

var _ RuntimeInactivityObserver = (*ScopedDNSAdapter)(nil)

type scopedDNSInactiveProof struct {
	procRoot       string
	netRoot        string
	threadNetRoot  func() string
	stage          *string // private ROOT dependency QA: fixed labels only, no callback
	selfPID        int
	readlink       func(string) (string, error)
	sameExecutable func(string, string) (bool, error)
	withCurrent    func(context.Context, func(context.Context, netidentity.Identity) error) error
}

// VerifyRuntimeInactive performs no effects, cancellation, migration or cleanup.
// Manager owns the operation/recovery gates. Missing startup coordinates or the
// trusted common complete-inventory consumer always refuse, including first use.
func (a *ScopedDNSAdapter) VerifyRuntimeInactive(ctx context.Context) error {
	if a == nil || a.InactivityIdentity == nil {
		return ErrScopedDNSRuntimeInactive
	}
	proof, err := scopedDNSInactivePlatformProof()
	if err != nil {
		return errors.Join(ErrScopedDNSRuntimeInactive, err)
	}
	proof.withCurrent = a.InactivityIdentity.WithCurrent
	return a.verifyDNSRuntimeInactive(ctx, proof)
}

func (a *ScopedDNSAdapter) verifyDNSRuntimeInactive(parent context.Context, proof scopedDNSInactiveProof) error {
	if parent == nil || a == nil || proof.withCurrent == nil || proof.readlink == nil || proof.sameExecutable == nil || proof.selfPID < 1 ||
		!scopedDNSInactivePath(a.StateRoot) || filepath.Base(a.StateRoot) != scopedDNSAdapterID ||
		!scopedDNSInactivePath(a.InactivitySettingsPath) || a.InactivityKernelCheck == nil || !scopedDNSInactivePath(proof.procRoot) {
		return ErrScopedDNSRuntimeInactive
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	root, settings, identity, kernel, manager := a.StateRoot, a.InactivitySettingsPath, a.InactivityIdentity, a.InactivityKernelCheck, a.DNS
	kernelPC := reflect.ValueOf(kernel).Pointer()
	checkLocal := func() (uint64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if !a.mu.TryLock() {
			return 0, ErrScopedDNSRuntimeInactive
		}
		live := a.live
		a.mu.Unlock()
		if live != nil || a.StateRoot != root || a.InactivitySettingsPath != settings || a.InactivityIdentity != identity || a.DNS != manager ||
			a.InactivityKernelCheck == nil || reflect.ValueOf(a.InactivityKernelCheck).Pointer() != kernelPC || manager != nil && manager.Path != settings {
			return 0, ErrScopedDNSRuntimeInactive
		}
		return scopedDNSInactiveEpoch(root)
	}
	var opening map[string]scopedDNSInactiveImage
	var openingEpoch uint64
	err := proof.withCurrent(ctx, func(c context.Context, scope netidentity.Identity) error {
		if err := scope.Validate(); err != nil {
			return err
		}
		epoch, err := checkLocal()
		if err != nil {
			return err
		}
		before, ports, err := scopedDNSInactiveFiles(c, root, settings)
		if err != nil {
			return fmt.Errorf("saved intent: %w", err)
		}
		opening, openingEpoch = before, epoch
		if err := scopedDNSInactiveProc(c, proof, root, settings, ports); err != nil {
			return fmt.Errorf("process/socket inventory: %w", err)
		}
		if err := kernel(c, scope); err != nil {
			return fmt.Errorf("complete backend inventory: %w", err)
		}
		if err := scopedDNSInactiveProc(c, proof, root, settings, ports); err != nil {
			return err
		}
		after, _, err := scopedDNSInactiveFiles(c, root, settings)
		if err != nil || !scopedDNSInactiveSameFiles(before, after) {
			return errors.Join(ErrScopedDNSRuntimeInactive, err)
		}
		current, err := checkLocal()
		if err != nil || current != epoch {
			return errors.Join(ErrScopedDNSRuntimeInactive, err)
		}
		return c.Err()
	})
	if err != nil || ctx.Err() != nil {
		return errors.Join(ErrScopedDNSRuntimeInactive, err, ctx.Err())
	}
	// The provider's closing identity observation is itself a slow boundary.
	// Finish with callback-free local/file bookends after it has returned.
	closing, _, err := scopedDNSInactiveFiles(ctx, root, settings)
	epoch, localErr := checkLocal()
	if opening == nil || err != nil || localErr != nil || epoch != openingEpoch || !scopedDNSInactiveSameFiles(opening, closing) {
		return errors.Join(ErrScopedDNSRuntimeInactive, err, localErr)
	}
	return nil
}

func scopedDNSInactivePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != filepath.VolumeName(path)+string(filepath.Separator)
}
