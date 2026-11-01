package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Only after PrepareSyntheticCapture returned from actual COMMON effects.
// Reservation, mapping publication and watcher lifetime changes stay outside.
func (c *DomainPolicyTCPCapture) observePreparationClosing(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, use func(context.Context, *xrayDomainTCPFileObservation) error) error {
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil || use == nil {
		return ErrDomainPolicyTCPConsumer
	}
	o, original := c.owner.(*DomainTCPOriginalScope)
	if !original {
		return use(ctx, nil) // Existing owners retain every full original check.
	}
	if o == nil || o.self != o {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	r, p := o.captureResource, o.process
	valid := !o.closed && o.capture == c && r != nil && r.self == r && r.process == p && r.capture == c && r.mapping == mapping
	o.mu.Unlock()
	if !valid || p == nil || p.self != p {
		return ErrDomainPolicyTCPConsumer
	}
	return r.observeTools(ctx, func(observed context.Context) error {
		return p.withCurrentFileObservation(observed, func(files *xrayDomainTCPFileObservation) error {
			result := use(observed, files)
			o.mu.Lock()
			same := c.owner == o && !o.closed && o.capture == c && o.captureResource == r && o.process == p && r.self == r && r.process == p && r.capture == c && r.mapping == mapping
			o.mu.Unlock()
			if !same {
				return errors.Join(result, ErrDomainPolicyTCPConsumer)
			}
			return result
		})
	})
}
