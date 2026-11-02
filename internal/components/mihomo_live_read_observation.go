package components

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// MihomoLiveObservation exists only inside one synchronous read callback.
// It cannot start, stop, transfer or expose the retained child. Full source
// and child byte comparisons bookend the callback; every nested Current checks
// the original native child, control, held executable fingerprint and sealed
// profile. No source/native byte observation survives this pure read callback.
type MihomoLiveObservation struct {
	mu          sync.Mutex
	self        *MihomoLiveObservation
	child       *MihomoLiveProcess
	source      *MihomoLiveSource
	ctx         context.Context
	open        bool
	fingerprint *mihomoLiveReadFingerprint
}

type mihomoLiveObservationKey struct{}

func (p *MihomoLiveProcess) WithReadObservation(ctx context.Context, read func(context.Context, *MihomoLiveObservation) error) (result error) {
	if read == nil {
		return ErrMihomoLiveOwner
	}
	fingerprint, err := p.openReadFingerprint(ctx, nil)
	if err != nil {
		return err
	}
	v := &MihomoLiveObservation{child: p, source: p.source, open: true, fingerprint: fingerprint}
	v.self = v
	v.ctx = context.WithValue(ctx, mihomoLiveObservationKey{}, v)
	defer func() {
		// Revoke and join in-flight comparisons before the full closing read,
		// including callback error and panic. A retained view is never reusable.
		v.mu.Lock()
		v.open = false
		v.mu.Unlock()
		result = errors.Join(result, p.closeReadFingerprint(ctx, nil, fingerprint))
	}()
	return read(v.ctx, v)
}

func (v *MihomoLiveObservation) validLocked(ctx context.Context) bool {
	if v == nil || v.self != v || !v.open || v.child == nil || v.source == nil || v.ctx == nil || mihomoLiveFinite(v.ctx) != nil || mihomoLiveFinite(ctx) != nil || ctx.Value(mihomoLiveObservationKey{}) != v {
		return false
	}
	original, _ := v.ctx.Deadline()
	deadline, _ := ctx.Deadline()
	return !deadline.After(original)
}

func (v *MihomoLiveObservation) Current(ctx context.Context) error {
	return v.current(ctx, nil)
}

func (v *MihomoLiveObservation) current(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if v == nil {
		return ErrMihomoLiveOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.validLocked(ctx) {
		var callerErr, originalErr error
		if ctx != nil {
			callerErr = ctx.Err()
		}
		if v.ctx != nil {
			originalErr = v.ctx.Err()
		}
		return errors.Join(ErrMihomoLiveOwner, callerErr, originalErr)
	}
	p := v.child
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || p.source != v.source || p.closed || p.closeErr != nil || p.native == nil || p.profile == nil {
		return ErrMihomoLiveOwner
	}
	s := v.source
	s.mu.Lock()
	profile := p.profile
	valid := s.self == s && !s.closed && s.closeErr == nil && s.manager != nil && s.session != nil && s.origin != nil &&
		s.reference.ParentOrigin == s.origin.reference() && s.children[p] && s.profiles[profile] &&
		profile.self == profile && profile.source == s && digest(profile.config) == profile.configSHA
	s.mu.Unlock()
	if !valid {
		return ErrMihomoLiveOwner
	}
	if v.fingerprint == nil || v.fingerprint.child != p || v.fingerprint.native != p.native {
		return ErrMihomoLiveOwner
	}
	return p.native.currentRead(ctx, cleanup, v.fingerprint)
}

// BoundTo compares only the original handles; it supplies no fresh verdict.
func (v *MihomoLiveObservation) BoundTo(child *MihomoLiveProcess, source *MihomoLiveSource) bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.validLocked(v.ctx) && v.child == child && v.source == source
}

func (v *MihomoLiveObservation) ProfileReference(ctx context.Context) (MihomoLiveProfileReference, error) {
	if err := v.Current(ctx); err != nil {
		return MihomoLiveProfileReference{}, err
	}
	return v.profileReferenceRead(ctx)
}

func (v *MihomoLiveObservation) profileReferenceRead(ctx context.Context) (MihomoLiveProfileReference, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.validLocked(ctx) {
		return MihomoLiveProfileReference{}, ErrMihomoLiveOwner
	}
	p := v.child
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr != nil || p.profile == nil || p.source != v.source {
		return MihomoLiveProfileReference{}, ErrMihomoLiveOwner
	}
	return MihomoLiveProfileReference{ConfigSHA256: p.profile.configSHA, SOCKSPort: p.profile.port}, nil
}

func (v *MihomoLiveObservation) PID() int {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.validLocked(v.ctx) {
		return 0
	}
	return v.child.PID()
}

func (v *MihomoLiveObservation) MatchesFile(kind string, info os.FileInfo) bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.validLocked(v.ctx) && v.child.MatchesFile(kind, info)
}
