package dnscontrol

import (
	"context"
	"errors"
	"net/netip"
	"sync"
)

// Implemented by an original coordinator retaining its actual finite phase.
// The callback encloses admission/Reserve as well as publication, and must run
// exactly once and finish before return. This interface itself grants nothing:
// the resolver still authenticates its original Gate, source and control epoch.
type NetworkPolicyDNSSyntheticRequestPhaseOwner interface {
	WithSyntheticRequestPhase(context.Context, func(context.Context) error) error
}

func (s *NetworkPolicyDNSSyntheticResolver) withSyntheticRequestPhase(request context.Context, use func(context.Context) error) error {
	owner, present := s.publication.(NetworkPolicyDNSSyntheticRequestPhaseOwner)
	if !present {
		return use(request)
	}
	var mu sync.Mutex
	open, entered, misuse := true, false, false
	var revoke context.CancelFunc
	var callbackErr error
	done := make(chan struct{})
	ownerErr := owner.WithSyntheticRequestPhase(request, func(phase context.Context) error {
		mu.Lock()
		if !open || entered || phase == nil {
			misuse = true
			mu.Unlock()
			return ErrSyntheticDNSMapping
		}
		entered = true
		deadline, bounded := request.Deadline()
		phaseDeadline, finite := phase.Deadline()
		if !bounded || !finite || phaseDeadline.After(deadline) {
			misuse = true
			callbackErr = ErrSyntheticDNSMapping
			mu.Unlock()
			close(done)
			return callbackErr
		}
		life, cancel := context.WithDeadline(phase, deadline)
		revoke = cancel
		mu.Unlock()
		defer close(done)
		defer cancel()
		stop := context.AfterFunc(request, cancel)
		defer stop()
		if request.Err() != nil {
			cancel()
		}
		if life.Err() != nil {
			callbackErr = life.Err()
		} else {
			callbackErr = errors.Join(use(life), life.Err(), request.Err())
		}
		return callbackErr
	})
	mu.Lock()
	open = false
	didEnter, cancel := entered, revoke
	mu.Unlock()
	if didEnter {
		select {
		case <-done:
		default:
			mu.Lock()
			misuse = true
			mu.Unlock()
			if cancel != nil {
				cancel()
			}
			<-done
		}
	}
	mu.Lock()
	bad := misuse
	mu.Unlock()
	if !didEnter || bad {
		s.invalid.Store(true)
		s.cancel()
		return errors.Join(ErrSyntheticDNSMapping, ownerErr, callbackErr)
	}
	return errors.Join(ownerErr, callbackErr)
}

// Listener admission happens before Exchange/Publish, so it must enter the
// same original phase too. Factoring this keeps socket-free coverage possible.
func (s *NetworkPolicyDNSSyntheticResolver) admitSyntheticRequest(ctx context.Context, client netip.Addr) error {
	return s.withRequest(ctx, func(held context.Context) error {
		if err := s.current(held); err != nil {
			return err
		}
		_, err := s.resolver.admission(held, client, "")
		return err
	})
}
