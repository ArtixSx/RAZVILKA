package dataplane

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

type scopedDNSInactiveResources struct {
	udp       *net.UDPConn
	tcp       *net.TCPListener
	cancelled atomic.Bool
}

// This is process-local lifecycle accounting, not a lease or execution journal.
// A cold observer in this process must see sessions owned by every adapter.
var scopedDNSInactiveLifecycle = struct {
	sync.Mutex
	roots map[string]*scopedDNSInactiveRoot
}{roots: make(map[string]*scopedDNSInactiveRoot)}

type scopedDNSInactiveRoot struct {
	epoch    uint64
	pending  int
	sessions map[*scopedDNSSession]bool
}

func scopedDNSInactiveRootLocked(root string) *scopedDNSInactiveRoot {
	r := scopedDNSInactiveLifecycle.roots[root]
	if r == nil {
		r = &scopedDNSInactiveRoot{sessions: make(map[*scopedDNSSession]bool)}
		scopedDNSInactiveLifecycle.roots[root] = r
	}
	return r
}

func scopedDNSInactiveMutation(root string) func() {
	scopedDNSInactiveLifecycle.Lock()
	r := scopedDNSInactiveRootLocked(root)
	r.pending++
	r.epoch++
	scopedDNSInactiveLifecycle.Unlock()
	return func() {
		scopedDNSInactiveLifecycle.Lock()
		r.pending--
		r.epoch++
		scopedDNSInactiveLifecycle.Unlock()
	}
}

func scopedDNSInactivePublish(root string, s *scopedDNSSession) {
	scopedDNSInactiveLifecycle.Lock()
	defer scopedDNSInactiveLifecycle.Unlock()
	r := scopedDNSInactiveRootLocked(root)
	r.sessions[s] = true
	r.epoch++
}

func (s *scopedDNSSession) serve(ctx context.Context) {
	// Serve joins its reader/connection/query workers on normal completion.
	// These explicit closes also cover its validation errors before that loop.
	defer close(s.done)
	defer s.resources.udp.Close()
	defer s.resources.tcp.Close()
	_ = s.resolver.Serve(ctx, s.resources.udp, s.resources.tcp)
}

func (s *scopedDNSSession) inactiveJoined() error {
	if s == nil || !s.resources.cancelled.Load() || s.resources.udp == nil || s.resources.tcp == nil || s.done == nil {
		return ErrScopedDNSRuntimeInactive
	}
	select {
	case <-s.done:
	default:
		return ErrScopedDNSRuntimeInactive
	}
	u, e1 := s.resources.udp.SyscallConn()
	t, e2 := s.resources.tcp.SyscallConn()
	if e1 != nil || e2 != nil || !errors.Is(u.Control(func(uintptr) {}), net.ErrClosed) || !errors.Is(t.Control(func(uintptr) {}), net.ErrClosed) {
		return ErrScopedDNSRuntimeInactive
	}
	return nil
}

func scopedDNSInactiveRetire(root string, s *scopedDNSSession) error {
	if err := s.inactiveJoined(); err != nil {
		return err
	}
	scopedDNSInactiveLifecycle.Lock()
	defer scopedDNSInactiveLifecycle.Unlock()
	r := scopedDNSInactiveRootLocked(root)
	if !r.sessions[s] {
		return ErrScopedDNSRuntimeInactive
	}
	delete(r.sessions, s)
	r.epoch++
	return nil
}

func scopedDNSInactiveEpoch(root string) (uint64, error) {
	scopedDNSInactiveLifecycle.Lock()
	defer scopedDNSInactiveLifecycle.Unlock()
	r := scopedDNSInactiveLifecycle.roots[root]
	if r == nil {
		return 0, nil
	}
	if r.pending != 0 || len(r.sessions) != 0 {
		return 0, ErrScopedDNSRuntimeInactive
	}
	return r.epoch, nil
}
