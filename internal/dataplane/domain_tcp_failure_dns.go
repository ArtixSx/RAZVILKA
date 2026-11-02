package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// This closes only the SAME source's publication barrier and original socket
// session after the entire native phase returned. It does not remove a rule,
// expire a cached alias or manufacture a standby/keeper from an observation.
func (r *domainTCPFailureCleanup) closeOriginalDNS(ctx context.Context) (dnscontrol.SyntheticDNSMappingObservation, error) {
	var zero dnscontrol.SyntheticDNSMappingObservation
	if r == nil || r.resource == nil || r.local(ctx, r.resource) != nil {
		return zero, ErrPolicyAdditionUnknown
	}
	p := r.resource
	if !p.mu.TryLock() {
		return zero, ErrPolicyAdditionUnknown
	}
	err := p.failureNativeReturnedLocked()
	p.mu.Unlock()
	if err != nil {
		return zero, err
	}
	if p.child != nil {
		select {
		case <-p.child.done:
		default:
			return zero, ErrPolicyAdditionUnknown
		}
	}
	m := p.material
	s := p.scope
	s.mu.Lock()
	o := s.domainTCPOwner
	valid := o != nil && o.self == o && o.binding == m.binding && o.binding.scope == s
	s.mu.Unlock()
	if !valid || m.session == nil || m.dnsSource == nil || m.retirement == nil || m.mapping == nil {
		return zero, ErrDomainPolicyTCPConsumer
	}
	if err := r.control.CurrentForCleanupOperation(ctx, r.cleanup); err != nil {
		return zero, err
	}
	session, err := m.binding.originalSyntheticSession(r.control)
	if err != nil || session != m.session || session.synthetic == nil || session.synthetic.binding != m.binding || session.synthetic.control != r.control || session.synthetic.source != m.dnsSource {
		return zero, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	o.mu.Lock()
	if o.process != p {
		o.mu.Unlock()
		return zero, ErrDomainPolicyTCPConsumer
	}
	o.closed, o.publicationOpen = true, false
	if o.cancel != nil {
		o.cancel()
	}
	capture := o.capture
	o.mu.Unlock()
	// Close joins the exact source's in-flight sends before its original FD
	// closes. Its actual close failure stays sticky inside that source.
	if err := m.dnsSource.Close(); err != nil {
		return zero, err
	}
	session.resources.cancelled.Store(true)
	session.cancel()
	select {
	case <-session.done:
	case <-ctx.Done():
		return zero, ctx.Err()
	}
	if err := session.inactiveJoined(); err != nil {
		return zero, err
	}
	if capture != nil {
		if capture.self != capture || capture.owner != o || capture.xray == nil || capture.xray.resource != p || capture.retirement == nil {
			return zero, ErrDomainPolicyTCPConsumer
		}
		if err := capture.retirement.Joined(ctx); err != nil {
			return zero, err
		}
	}
	// This read-only carrier belongs to the mapping reviewed BEFORE the
	// original process/capture effects. Fresh cleanup is proved separately.
	row, err := m.retirement.ObserveClosed(ctx)
	if err != nil || !syntheticSettlementCoordinatesEqual(row, m.observation) {
		return zero, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := errors.Join(r.control.CurrentForCleanupOperation(ctx, r.cleanup), r.local(ctx, p), session.inactiveJoined()); err != nil {
		return zero, err
	}
	return row, nil
}
