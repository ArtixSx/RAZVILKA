package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// This producer runs INSIDE the original WithNative callback, after the
// actual serve defer has joined all capture handlers. Do not call phase.Close
// here: it would wait on this very native callback. The outer Manager owns
// that phase join after this function returns.
func (o *DomainTCPOriginalScope) finishCapture(ctx context.Context, process *XrayDomainTCPExecutionResource) error {
	if o == nil || o.self != o || process == nil || process.material == nil || process.material.binding != o.binding {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	if o.process != process {
		o.mu.Unlock()
		return ErrDomainPolicyTCPConsumer
	}
	o.closed = true
	if o.cancel != nil {
		o.cancel()
	}
	capture, baseline, resource, kernel := o.capture, o.baseline, o.captureResource, o.kernel
	o.mu.Unlock()
	session, err := o.binding.originalSyntheticSession(process.material.control)
	if err != nil || session != process.material.session || session.synthetic.source != process.material.dnsSource {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	// Close joins the original publication barrier before DNS sockets retire.
	if err := session.synthetic.source.Close(); err != nil {
		return err
	}
	session.resources.cancelled.Store(true)
	session.cancel()
	select {
	case <-session.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := session.inactiveJoined(); err != nil {
		return err
	}
	if capture != nil {
		if err := capture.retirement.Joined(ctx); err != nil {
			return err
		}
	}
	if resource != nil {
		if err := resource.retire(ctx, baseline, kernel); err != nil {
			return err
		}
	}
	if baseline != nil {
		// Exact restorative DNAT remains owned and documented. Empty CT dumps
		// and TTL alone do not issue the missing client/late-SYN settlement.
		return dnscontrol.ErrSyntheticDNSTransitionPending
	}
	return nil
}
