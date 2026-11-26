package privaterestore

import (
	"context"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// WithOfflineNFQWS2Stop retains the already acquired private-recovery lifetime
// lease while the installed offline coordinator uses the real Store writer.
// It cannot be used after HTTP/workers receive runtime handover, and does not
// acquire a Store-file lease that would deadlock the Store's own disk CAS.
func (c *Coordinator) WithOfflineNFQWS2Stop(ctx context.Context, configPath string, stop func(context.Context) error) error {
	if c == nil || ctx == nil || ctx.Err() != nil || stop == nil || !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath {
		return restorejournal.ErrInvalid
	}
	if _, finite := ctx.Deadline(); !finite {
		return restorejournal.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.blocked || c.runtimeStarted || c.journal == nil || c.layout.Config != configPath {
		return restorejournal.ErrRecovery
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.journal.RequireIdle(ctx); err != nil {
		return err
	}
	return stop(ctx)
}
