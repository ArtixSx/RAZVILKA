package components

import (
	"context"
	"errors"
	"os"
	"sync"
)

var ErrMihomoProbePending = errors.New("original Mihomo probe process or cleanup remains pending")

// This original in-memory owner is never reconstructed from its PID or files.
// Its observations do not grant route, service, Start or cleanup authority.
type MihomoProbeProcess struct {
	self    *MihomoProbeProcess
	source  *MihomoProbeSource
	mu      sync.Mutex
	native  mihomoProbeNative
	running bool
}

type mihomoProbeNative interface {
	current(context.Context) error
	pid() int
	file(string, os.FileInfo) bool
	cleanup(context.Context) error
}

func (*MihomoProbeProcess) String() string   { return "[original Mihomo probe process]" }
func (*MihomoProbeProcess) GoString() string { return "[original Mihomo probe process]" }

func (p *MihomoProbeProcess) PID() int {
	if p == nil || p.self != p {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil {
		return 0
	}
	return p.native.pid()
}

func (p *MihomoProbeProcess) Current(ctx context.Context) error {
	if p == nil || p.self != p || p.source == nil {
		return ErrMihomoProbePending
	}
	if err := p.source.Current(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil {
		return ErrMihomoProbePending
	}
	return p.native.current(ctx)
}

// MatchesFile compares an actual procfs readback with the SAME original held
// binary/config/home. It returns no descriptors or executable path.
func (p *MihomoProbeProcess) MatchesFile(kind string, actual os.FileInfo) bool {
	if p == nil || p.self != p || actual == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.native != nil && p.native.file(kind, actual)
}

// Cleanup retries only this original child's pending cleanup. The native
// implementation retains its pre-issued control and cleanup operation.
func (p *MihomoProbeProcess) Cleanup(ctx context.Context) error {
	if p == nil || p.self != p || p.source == nil || ctx == nil {
		return ErrMihomoProbePending
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return ErrMihomoProbePending
	}
	if p.native == nil {
		return nil
	}
	if err := p.native.cleanup(ctx); err != nil {
		return err
	}
	p.native = nil
	p.source.mu.Lock()
	defer p.source.mu.Unlock()
	if p.source.probe != p {
		return ErrMihomoProbePending
	}
	p.source.probe = nil
	return nil
}

// CleanupProbe preserves reachability after a panic or unconfirmed native
// cleanup. An active RunProbe cannot be raced by a second cleanup caller.
func (s *MihomoProbeSource) CleanupProbe(ctx context.Context) error {
	if s == nil || s.self != s {
		return ErrMihomoProbePending
	}
	s.mu.Lock()
	p := s.probe
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	return p.Cleanup(ctx)
}
