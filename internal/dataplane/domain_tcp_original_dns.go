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
