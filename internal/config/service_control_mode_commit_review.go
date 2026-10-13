package config

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const (
	serviceModeCommitted = uint32(1)
	serviceModeAccepted  = uint32(2)
	serviceModeRestored  = uint32(3)
)

// Issued only after this actual Store's durable mode-only writer succeeds.
// This comparison receipt grants no runtime, source, physical or Gate owner.
type ServiceModeCommitReview struct {
	self          *ServiceModeCommitReview
	store         *Store
	before, after Config
	phase         atomic.Uint32
}

func (*ServiceModeCommitReview) String() string   { return "[original service mode Store commit]" }
func (*ServiceModeCommitReview) GoString() string { return "[original service mode Store commit]" }

func (r *ServiceModeCommitReview) MatchesStore(store *Store) bool {
	return r != nil && r.self == r && store != nil && r.store == store
}

func (r *ServiceModeCommitReview) PendingAcceptance() bool {
	return r != nil && r.self == r && r.store != nil && r.phase.Load() == serviceModeCommitted
}

func serviceModeCommitImage(before Config) (Config, error) {
	if before.Revision == ^uint64(0) || before.ServiceControl.Mode != "manual" || before.SafeMode || before.ServiceControl.Stopped {
		return Config{}, ErrRevisionChanged
	}
	after := cloneConfig(before)
	after.ServiceControl.Mode = "auto"
	after.Revision++
	return after, nil
}

func (r *ServiceModeCommitReview) CommittedImages(ctx context.Context) (Config, Config, error) {
	return r.images(ctx, false)
}

func (r *ServiceModeCommitReview) RestoredImages(ctx context.Context) (Config, Config, error) {
	return r.images(ctx, true)
}

func (r *ServiceModeCommitReview) images(ctx context.Context, restored bool) (Config, Config, error) {
	if r == nil || r.self != r || r.store == nil || ctx == nil || ctx.Err() != nil {
		return Config{}, Config{}, ErrRevisionChanged
	}
	if _, finite := ctx.Deadline(); !finite {
		return Config{}, Config{}, ErrRevisionChanged
	}
	predicted, err := serviceModeCommitImage(r.before)
	if err != nil || !reflect.DeepEqual(predicted, r.after) {
		return Config{}, Config{}, ErrRevisionChanged
	}
	phase := r.phase.Load()
	from, to := r.before, r.after
	if restored {
		if phase != serviceModeRestored {
			return Config{}, Config{}, ErrRevisionChanged
		}
		from, to = r.after, r.before
	} else if phase != serviceModeCommitted && phase != serviceModeAccepted {
		return Config{}, Config{}, ErrRevisionChanged
	}
	err = r.store.WithResourceExclusionObservation(ctx, to, func(EffectiveExclusionSet) error {
		if r.phase.Load() != phase {
			return ErrRevisionChanged
		}
		return nil
	})
	if err != nil || r.phase.Load() != phase {
		return Config{}, Config{}, ErrRevisionChanged
	}
	return cloneConfig(from), cloneConfig(to), nil
}

// Only one acceptance can complete. It does not replace the caller's own
// native/control/physical bookends, or permit a second comparison adoption.
func (r *ServiceModeCommitReview) Accept(ctx context.Context) error {
	if _, _, err := r.CommittedImages(ctx); err != nil {
		return err
	}
	if !r.phase.CompareAndSwap(serviceModeCommitted, serviceModeAccepted) {
		return ErrRevisionChanged
	}
	_, _, err := r.CommittedImages(ctx)
	return err
}

func (s *Store) UpdateManualToAutoReviewed(ctx context.Context, revision uint64) (func() error, *ServiceModeCommitReview, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrRevisionChanged
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, nil, ErrRevisionChanged
	}
	s.mu.RLock()
	uncertain := s.writeUncertain
	s.mu.RUnlock()
	if uncertain {
		return nil, nil, restorejournal.ErrRecovery
	}
	before := s.Get()
	after, err := serviceModeCommitImage(before)
	if err != nil || before.Revision != revision {
		return nil, nil, ErrRevisionChanged
	}
	if err := s.WithResourceExclusionObservation(ctx, before, func(EffectiveExclusionSet) error { return nil }); err != nil {
		s.mu.RLock()
		uncertain := s.writeUncertain
		s.mu.RUnlock()
		if uncertain {
			return nil, nil, errors.Join(err, restorejournal.ErrRecovery)
		}
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || !reflect.DeepEqual(s.cfg, before) {
		return nil, nil, ErrRevisionChanged
	}
	mode := "auto"
	if err := s.updateServiceControlLocked(&mode, nil, revision); err != nil {
		return nil, nil, err
	}
	// Both images are exact, including fields unrelated to service mode.
	if !reflect.DeepEqual(s.cfg, after) {
		s.writeUncertain = true
		return nil, nil, restorejournal.ErrRecovery
	}
	receipt := &ServiceModeCommitReview{store: s, before: before, after: cloneConfig(after)}
	receipt.self = receipt
	receipt.phase.Store(serviceModeCommitted)
	undo := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if receipt.phase.Load() == serviceModeRestored {
			return nil
		}
		if !reflect.DeepEqual(s.cfg, after) {
			return ErrRevisionChanged
		}
		s.cfg = cloneConfig(before)
		if err := s.saveLocked(); err != nil {
			s.cfg = cloneConfig(after)
			return err
		}
		receipt.phase.Store(serviceModeRestored)
		return nil
	}
	return undo, receipt, nil
}
