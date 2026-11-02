package dataplane

import (
	"context"
	"errors"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// StartDNS opens the existing adapter's SAME finite registered source. It is
// intentionally unpublished: Reserve can prepare one exact real answer, but
// this owner cannot synthesize/send it until Run binds original kernel proof.
func (o *DomainTCPOriginalScope) StartDNS(ctx context.Context, resolver *dnscontrol.NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview) error {
	if err := o.baseCurrent(ctx); err != nil {
		return err
	}
	if o.binding.scope.domainSuccessor != nil {
		return ErrDomainPolicyTCPConsumer
	}
	if resolver == nil || control == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if err := control.Current(ctx); err != nil {
		return err
	}
	a := o.binding.adapter
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.startSyntheticDNSLocked(ctx, o.binding, resolver, control, o)
}

// StartDNSContinuing consumes only the predecessor retained by this actual
// Manager successor cursor. The source constructor keeps the immutable old
// ledger prefix reserved and admits only new addresses after that prefix.
func (o *DomainTCPOriginalScope) StartDNSContinuing(ctx context.Context, resolver *dnscontrol.NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview, prior *DomainTCPDetachedStandby) error {
	if o == nil || o.self != o || o.binding == nil || o.binding.scope == nil || prior == nil || prior.self != prior || resolver == nil || control == nil {
		return ErrDomainPolicyTCPConsumer
	}
	c := o.binding.scope.domainSuccessor
	if c == nil || c.scope != o.binding.scope || c.forwardCurrent() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	entries, err := c.pool.originals()
	if err != nil || len(entries) == 0 || entries[len(entries)-1].detached != prior || prior.continuation == nil {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := errors.Join(o.baseCurrent(ctx), c.comparePrior(ctx, true), control.Current(ctx)); err != nil {
		return err
	}
	a := o.binding.adapter
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.startSyntheticDNSContinuingLocked(ctx, o.binding, resolver, control, o, prior.continuation)
}

func (o *DomainTCPOriginalScope) Reserve(ctx context.Context, client netip.Addr, query []byte) (*dnscontrol.SyntheticDNSMapping, error) {
	if err := o.baseCurrent(ctx); err != nil {
		return nil, err
	}
	control, err := o.binding.baselineControl()
	if err != nil {
		return nil, err
	}
	session, err := o.binding.originalSyntheticSession(control)
	if err != nil || session == nil || session.synthetic == nil || session.synthetic.source == nil {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return session.synthetic.source.Reserve(ctx, client, query)
}
