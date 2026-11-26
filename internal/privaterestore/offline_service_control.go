package privaterestore

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// OpenForOfflineServiceControl requires an existing private root and original
// initialized marker. It takes the same real lifetime lease as normal startup,
// but never creates a directory/marker, recovers a journal or opens a target.
// The caller must retain every deployment generation, not just the newest one.
func OpenForOfflineServiceControl(ctx context.Context, layout Layout) (*Coordinator, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, restorejournal.ErrInvalid
	}
	if !reflect.TypeOf(ctx).Comparable() {
		return nil, restorejournal.ErrInvalid
	}
	c, _, err := openCoordinatorMode(ctx, layout, false, true)
	if err == nil {
		c.offlineServiceControlContext = ctx
	}
	return c, err
}

// WithOfflineServiceControl keeps this original, idle generation leased across
// one bounded callback. It does not grant native effects or recovery authority.
// The callback must use the real Store CAS and must not reenter this coordinator
// or acquire a second lease for the same config file. The original opening
// context cannot be renewed or replaced. Its failure never causes
// replay, a reverse write, or runtime handover.
func (c *Coordinator) WithOfflineServiceControl(ctx context.Context, configPath string, callback func(context.Context) error) error {
	if c == nil || ctx == nil || ctx.Err() != nil || callback == nil || !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath {
		return restorejournal.ErrInvalid
	}
	if _, finite := ctx.Deadline(); !finite {
		return restorejournal.ErrInvalid
	}
	if !c.mu.TryLock() {
		return restorejournal.ErrBusy
	}
	defer c.mu.Unlock()
	if !c.offlineServiceControl || c.offlineServiceControlContext == nil || c.offlineServiceControlContext != ctx || c.offlineServiceControlContext.Err() != nil || c.closed || c.blocked || c.runtimeStarted || c.journal == nil || c.layout.Config != configPath {
		return restorejournal.ErrRecovery
	}
	if err := c.journal.RequireIdle(ctx); err != nil {
		return err
	}
	err := callback(c.offlineServiceControlContext)
	closing := c.journal.RequireIdle(ctx)
	if closing != nil {
		c.blocked = true
	}
	return errors.Join(err, closing, ctx.Err())
}
