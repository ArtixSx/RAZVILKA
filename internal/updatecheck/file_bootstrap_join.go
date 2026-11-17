package updatecheck

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

type bootstrapQuiesceJoinKey struct{}

// Issued only by the original command worker after direct exit zero and ECHILD.
// The running receipt identifies the original operation; it cannot prove Wait.
type bootstrapQuiesceJoin struct {
	self     *bootstrapQuiesceJoin
	adapter  *SelfUpdateFileAdapter
	original context.Context
	deadline time.Time
	command  fileCommandReceipt
	reaped   int
	active   atomic.Bool
}

func bootstrapJoinedQuiesceContext(a *SelfUpdateFileAdapter, ctx context.Context, launched fileCommandReceipt, reaped int) (context.Context, func()) {
	if ctx == nil {
		return nil, func() {}
	}
	deadline, finite := ctx.Deadline()
	if a == nil || !finite || ctx.Err() != nil || !deadline.After(time.Now()) || reaped <= 0 || !validFileCommandReceipt(launched) || launched.Command != "quiesce-old-runtime" || launched.State != "running" ||
		ctx.Value(bootstrapQuiesceJoinKey{}) != nil || ctx.Value(ordinaryQuiesceJoinKey{}) != nil || ctx.Value(ordinaryInstallerJoinKey{}) != nil {
		return ctx, func() {}
	}
	c := &bootstrapQuiesceJoin{adapter: a, original: ctx, deadline: deadline, command: launched, reaped: reaped}
	c.self = c
	c.active.Store(true)
	return context.WithValue(ctx, bootstrapQuiesceJoinKey{}, c), func() { c.active.Store(false) }
}

func bootstrapQuiesceJoinFor(ctx context.Context, a *SelfUpdateFileAdapter, command fileCommandReceipt, caller int) (*bootstrapQuiesceJoin, error) {
	if ctx == nil {
		return nil, ErrInstallerControllerRole
	}
	value := ctx.Value(bootstrapQuiesceJoinKey{})
	if value == nil {
		return nil, nil
	}
	c, ok := value.(*bootstrapQuiesceJoin)
	deadline, finite := ctx.Deadline()
	if !ok || c == nil || c.self != c || c.adapter != a || !c.active.Load() || c.reaped <= 0 || c.original == nil || c.original.Err() != nil || ctx.Err() != nil ||
		!finite || deadline.After(c.deadline) || !c.deadline.After(time.Now()) || command != c.command || caller != command.Supervisor.PID ||
		ctx.Value(ordinaryQuiesceJoinKey{}) != nil || ctx.Value(ordinaryInstallerJoinKey{}) != nil {
		return nil, errors.Join(ErrInstallerControllerRole, ctx.Err())
	}
	return c, nil
}

// OriginalBootstrapInstallerControllerAdapter returns only the original worker
// adapter during its synchronous post-Wait inactivity observation. Missing
// witness is not authority; present-invalid witness must never fall back.
func OriginalBootstrapInstallerControllerAdapter(ctx context.Context, id string) (*SelfUpdateFileAdapter, error) {
	if ctx == nil || !jobIDPattern.MatchString(id) {
		return nil, ErrInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if !finite || !deadline.After(time.Now()) || ctx.Err() != nil {
		return nil, errors.Join(ErrInstallerControllerRole, ctx.Err())
	}
	if ctx.Value(bootstrapQuiesceJoinKey{}) == nil {
		return nil, nil
	}
	return originalBootstrapInstallerControllerAdapter(ctx, id)
}
