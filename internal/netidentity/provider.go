package netidentity

import (
	"context"
	"errors"
	"runtime"
	"time"
)

// Provider has no caller-supplied runner, path, profile ID or observation cache.
// Its zero value cannot issue an observation.
type Provider struct {
	valid   bool
	profile *reviewedProfile
	read    func(context.Context) (observation, error)
	build   func(context.Context) (buildTuple, error)
}

// NewProcProvider permits only the actual process-and-thread inode path.
func NewProcProvider() *Provider {
	return &Provider{valid: true, read: readObservation, build: readBuild}
}

// NewReviewedStockNC1812Provider is the explicit trusted startup factory for
// the one accepted stock profile. Selection freshly verifies the actual tuple;
// construction success is not a reusable observation or a mutation grant.
func NewReviewedStockNC1812Provider(ctx context.Context) (*Provider, error) {
	p := NewProcProvider()
	profile := nc1812Profile()
	p.profile = &profile
	if _, err := p.Observe(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func operationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrUnknown
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, errors.Join(ErrUnknown, err)
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, nil, ErrUnknown
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	return bounded, cancel, nil
}

// Observe locks the calling goroutine to its current OS thread. A consumer
// holding its own LockOSThread retains that lock after return. Otherwise use
// WithCurrent to cover namespace-sensitive work and a closing observation.
func (p *Provider) Observe(ctx context.Context) (Identity, error) {
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return Identity{}, err
	}
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return p.observeLocked(c)
}
func (p *Provider) observeLocked(ctx context.Context) (Identity, error) {
	if ctx == nil || ctx.Err() != nil {
		return Identity{}, ErrUnknown
	}
	if p == nil || !p.valid || p.read == nil || p.build == nil {
		return Identity{}, ErrUnknown
	}
	o, err := p.read(ctx)
	if err != nil {
		return Identity{}, errors.Join(ErrUnknown, err)
	}
	identity, err := identityFromObservation(o, p.profile)
	if err != nil {
		return Identity{}, err
	}
	if p.profile != nil {
		// The actual uname/boot/procfs scope brackets encompass both metadata
		// commands, not merely a cached tuple or a boot-only marker.
		if o.KernelRelease != p.profile.KernelRelease || o.Machine != p.profile.Machine {
			return Identity{}, ErrUnknown
		}
		before, err := p.build(ctx)
		if err != nil || before != p.profile.Build {
			return Identity{}, errors.Join(ErrUnknown, err)
		}
		after, err := p.build(ctx)
		if err != nil || after != before {
			return Identity{}, errors.Join(ErrUnknown, err)
		}
		closing, err := p.read(ctx)
		if err != nil {
			return Identity{}, errors.Join(ErrUnknown, err)
		}
		closed, err := identityFromObservation(closing, p.profile)
		if err != nil || closed != identity || closing.KernelRelease != o.KernelRelease || closing.Machine != o.Machine {
			return Identity{}, ErrUnknown
		}
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, errors.Join(ErrUnknown, err)
	}
	return identity, nil
}

// WithCurrent brackets the existing caller operation on the same OS thread.
// A changed identity or cancellation refuses even when use returns nil. The
// caller still owns all resource/queue/process/backend/effect checks.
func (p *Provider) WithCurrent(ctx context.Context, use func(context.Context, Identity) error) error {
	if use == nil {
		return ErrUnknown
	}
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := p.observeLocked(c)
	if err != nil {
		return err
	}
	if err := use(c, before); err != nil {
		return err
	}
	after, err := p.observeLocked(c)
	if err != nil || after != before || c.Err() != nil {
		return errors.Join(ErrUnknown, err, c.Err())
	}
	return nil
}
