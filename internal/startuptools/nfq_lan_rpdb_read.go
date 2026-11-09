package startuptools

import (
	"context"
	"errors"
	"sync"
)

type nfqLANRPDBKey struct{}
type nfqLANRPDBScope struct {
	self   *nfqLANRPDBScope
	runner *policyRunner
	lease  *Lease
	ctx    context.Context
	mu     sync.Mutex
	active bool
	next   int
	users  sync.WaitGroup
}

func nfqLANRPDBMarker(ctx context.Context) (*nfqLANRPDBScope, bool) {
	if ctx == nil {
		return nil, false
	}
	v := ctx.Value(nfqLANRPDBKey{})
	if v == nil {
		return nil, false
	}
	s, _ := v.(*nfqLANRPDBScope)
	return s, true
}
func (s *nfqLANRPDBScope) currentLocked(ctx context.Context, r *policyRunner) error {
	if s == nil || s.self != s || !s.active || r == nil || s.runner != r || r.lease != s.lease || s.ctx == nil || s.ctx.Err() != nil || ctx == nil || ctx.Err() != nil || ctx.Value(nfqLANRPDBKey{}) != s {
		return at("NFQ_LAN_RPDB_SCOPE", nil)
	}
	if _, present := readObservationMarker(ctx); !present {
		return at("NFQ_LAN_RPDB_SCOPE", nil)
	}
	return r.lease.readObservationCurrent(ctx)
}

// The only producer is the original policy runner inside an already-held
// readonly tool observation. No context grant is returned to the caller.
// Stock iproute2's distinct numeric adapter retains its existing full path.
func (r *policyRunner) WithOriginalNFQWSLANRPDB(ctx context.Context, use func(context.Context) error) (result error) {
	if r == nil || r.lease == nil || ctx == nil || use == nil {
		return at("NFQ_LAN_RPDB_SCOPE", nil)
	}
	if _, present := nfqLANRPDBMarker(ctx); present {
		return at("NFQ_LAN_RPDB_SCOPE", nil)
	}
	if _, present := readObservationMarker(ctx); !present {
		return at("NFQ_LAN_RPDB_SCOPE", nil)
	}
	release, _, err := r.lease.registerReadObservation(ctx)
	if err != nil {
		return err
	}
	defer release()
	if r.lease.profile.stock {
		return use(ctx)
	}
	scoped, cancel := context.WithCancel(ctx)
	s := &nfqLANRPDBScope{runner: r, lease: r.lease, active: true}
	s.self = s
	scoped = context.WithValue(scoped, nfqLANRPDBKey{}, s)
	s.ctx = scoped
	defer func() {
		s.mu.Lock()
		s.active = false
		count := s.next
		s.mu.Unlock()
		cancel()
		s.users.Wait()
		if result == nil && count != 2 {
			result = at("NFQ_LAN_RPDB_SEQUENCE", nil)
		}
		result = errors.Join(result, r.lease.readObservationCurrent(ctx), ctx.Err())
	}()
	return use(scoped)
}
func (s *nfqLANRPDBScope) enter(ctx context.Context, r *policyRunner, name string, args []string) (func(), error) {
	if s == nil {
		return nil, at("NFQ_LAN_RPDB_SCOPE", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.currentLocked(ctx, r); err != nil {
		return nil, err
	}
	if name == r.lease.profile.ipAlias {
		if !ipReadArguments(args) || s.next >= 2 || args[0] != []string{"-4", "-6"}[s.next] {
			return nil, at("NFQ_LAN_RPDB_SEQUENCE", nil)
		}
		s.next++
	}
	s.users.Add(1)
	return s.users.Done, nil
}
