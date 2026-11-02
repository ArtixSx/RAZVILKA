package components

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// MihomoLiveProcess is reserved before any Start. The native implementation
// keeps its exact Cmd, held files and sole Wait; no serialized PID can mint it.
type MihomoLiveProcess struct {
	mu        sync.Mutex
	self      *MihomoLiveProcess
	source    *MihomoLiveSource
	profile   *MihomoLiveProfile
	control   *operationgate.ControlEpochReview
	native    mihomoLiveNative
	closed    bool
	closeErr  error
	startUsed bool
}

func (*MihomoLiveProcess) String() string   { return "[private original live Mihomo child]" }
func (*MihomoLiveProcess) GoString() string { return "[private original live Mihomo child]" }

type mihomoLiveNative interface {
	start(context.Context, func(context.Context, func() error) error) error
	current(context.Context) error
	currentForCleanup(context.Context, *operationgate.ExclusiveCleanupReview) error
	cleanup(context.Context, *operationgate.ExclusiveCleanupReview) error
	pid() int
	file(string, os.FileInfo) bool
	homeReference(context.Context) (MihomoLiveHomeReference, error)
}

// ReserveLiveChild transfers the dedicated control handle and creates only an
// opaque original owner. No process, descriptor or temporary directory is
// created yet. The COMMON participant retains this handle before Start.
func (s *MihomoLiveSource) ReserveLiveChild(ctx context.Context, profile *MihomoLiveProfile, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview) (*MihomoLiveProcess, error) {
	if s == nil || profile == nil || control == nil || cleanup == nil {
		return nil, ErrMihomoLiveOwner
	}
	if err := mihomoLiveFinite(ctx); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if time.Until(deadline) > 2*time.Minute {
		return nil, ErrMihomoLiveOwner
	}
	if err := errors.Join(control.Current(ctx), control.CurrentForCleanupOperation(ctx, cleanup)); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if err := s.currentLocked(ctx); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if profile.self != profile || profile.source != s || digest(profile.config) != profile.configSHA || len(s.children) >= 2 {
		s.mu.Unlock()
		return nil, ErrMihomoLiveOwner
	}
	for child := range s.children {
		if child.control == control {
			s.mu.Unlock()
			return nil, ErrMihomoLiveOwner
		}
	}
	p := &MihomoLiveProcess{source: s, profile: profile, control: control}
	p.self = p
	s.children[p] = true
	s.mu.Unlock()
	return p, nil
}

// StartAdmitted uses the original COMMON owner's synchronous Start barrier.
// The caller already retains this reserved handle, including during panic.
// A successful Start never retains the caller's Apply gate or deadline.
func (p *MihomoLiveProcess) StartAdmitted(ctx context.Context, admission func(context.Context, func() error) error) error {
	if p == nil || p.self != p || admission == nil {
		return ErrMihomoLiveOwner
	}
	if err := mihomoLiveFinite(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	if p.closed || p.startUsed {
		p.mu.Unlock()
		return ErrMihomoLiveOwner
	}
	p.startUsed = true
	native := p.native
	var err error
	if native == nil {
		native, err = newMihomoLiveNative(ctx, p)
		p.native = native
	}
	p.mu.Unlock()
	if err != nil {
		return err
	}
	if err := native.start(ctx, admission); err != nil {
		return err
	}
	return p.Current(ctx)
}

func (p *MihomoLiveProcess) Current(ctx context.Context) error {
	if p == nil || p.self != p {
		return ErrMihomoLiveOwner
	}
	if err := mihomoLiveFinite(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr != nil || p.native == nil {
		return ErrMihomoLiveOwner
	}
	if err := p.source.Current(ctx); err != nil {
		return err
	}
	return p.native.current(ctx)
}

// CurrentForCleanup is a read-only comparison of this same retained child,
// bound to a fresh genuine cleanup operation. It cannot earn service evidence,
// revive forward health or issue Start after durable Stop.
func (p *MihomoLiveProcess) CurrentForCleanup(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if p == nil || p.self != p || cleanup == nil {
		return ErrMihomoLiveOwner
	}
	if err := mihomoLiveFinite(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr != nil || p.native == nil {
		return ErrMihomoLiveOwner
	}
	if err := p.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	if err := p.source.Current(ctx); err != nil {
		return err
	}
	return p.native.currentForCleanup(ctx, cleanup)
}
func (p *MihomoLiveProcess) PID() int {
	if p == nil || p.self != p {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil || p.closed {
		return 0
	}
	return p.native.pid()
}
func (p *MihomoLiveProcess) MatchesFile(kind string, actual os.FileInfo) bool {
	if p == nil || p.self != p {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.native != nil && p.native.file(kind, actual)
}
func (p *MihomoLiveProcess) Cleanup(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if p == nil || p.self != p {
		return ErrMihomoLiveOwner
	}
	if err := mihomoLiveFinite(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if p.closeErr != nil {
		return errors.Join(ErrMihomoLiveOwner, p.closeErr)
	}
	if err := p.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	if p.native != nil {
		if err := p.native.cleanup(ctx, cleanup); err != nil {
			return err
		}
	}
	if err := p.control.Close(); err != nil {
		p.closeErr = err
		return errors.Join(ErrMihomoLiveOwner, err)
	}
	p.source.mu.Lock()
	defer p.source.mu.Unlock()
	if p.source.self != p.source || !p.source.children[p] {
		p.closeErr = ErrMihomoLiveOwner
		return p.closeErr
	}
	delete(p.source.children, p)
	p.closed = true
	return nil
}
