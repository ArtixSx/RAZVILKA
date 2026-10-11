package config

import (
	"context"
	"reflect"
	"sync/atomic"
	"time"
)

const (
	autonomyRouteCommitted = uint32(1)
	autonomyRouteRestored  = uint32(2)
)

// Only the actual Store writer issues this receipt. Copied receipts and pure
// config images cannot establish a commit or its original successful undo.
// It owns no effect, command, transport or physical review.
type AutonomyRouteCommitReview struct {
	self              *AutonomyRouteCommitReview
	store             *Store
	before, after     Config
	id, route         string
	sources           []string
	started, finished time.Time
	phase             atomic.Uint32
}

func (*AutonomyRouteCommitReview) String() string   { return "[original autonomous Store commit]" }
func (*AutonomyRouteCommitReview) GoString() string { return "[original autonomous Store commit]" }

func (r *AutonomyRouteCommitReview) MatchesStore(s *Store) bool {
	return r != nil && r.self == r && s != nil && r.store == s
}

// Images are detached comparison data. Each read checks the full actual same
// Store and its current file image. The Store leaf is pure; Gate, control,
// physical and source bookends belong outside it to the original caller.
func (r *AutonomyRouteCommitReview) CommittedImages(ctx context.Context) (Config, Config, error) {
	return r.images(ctx, false)
}

func (r *AutonomyRouteCommitReview) RestoredImages(ctx context.Context) (Config, Config, error) {
	return r.images(ctx, true)
}

func (r *AutonomyRouteCommitReview) images(ctx context.Context, restored bool) (Config, Config, error) {
	if r == nil || r.self != r || r.store == nil || ctx == nil || ctx.Err() != nil {
		return Config{}, Config{}, ErrRevisionChanged
	}
	if _, finite := ctx.Deadline(); !finite {
		return Config{}, Config{}, ErrRevisionChanged
	}
	at, err := time.Parse(time.RFC3339, r.after.LastAppliedAt)
	if err != nil || r.started.IsZero() || r.finished.Before(r.started) || at.Before(r.started.Truncate(time.Second)) || at.After(r.finished) {
		return Config{}, Config{}, ErrRevisionChanged
	}
	predicted, err := ReviewedAutonomyRouteCommitImage(r.before, r.id, r.route, r.sources, at)
	if err != nil || !reflect.DeepEqual(predicted, r.after) {
		return Config{}, Config{}, ErrRevisionChanged
	}
	phase, from, to := autonomyRouteCommitted, r.before, r.after
	if restored {
		phase, from, to = autonomyRouteRestored, r.after, r.before
	}
	if r.phase.Load() != phase {
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
