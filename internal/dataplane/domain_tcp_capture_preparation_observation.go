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
	r, p, baseline := o.captureResource, o.process, o.baseline
	valid := !o.closed && o.capture == c && r != nil && r.self == r && r.process == p && r.capture == c && r.mapping == mapping
	o.mu.Unlock()
	if !valid || p == nil || p.self != p {
		return ErrDomainPolicyTCPConsumer
	}
	if ctx.Value(domainTCPGuardReadKey{}) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	compare := func(observed context.Context, files *xrayDomainTCPFileObservation) error {
		result := use(observed, files)
		o.mu.Lock()
		same := c.owner == o && !o.closed && o.capture == c && o.captureResource == r && o.process == p && r.self == r && r.process == p && r.capture == c && r.mapping == mapping
		o.mu.Unlock()
		if !same {
			return errors.Join(result, ErrDomainPolicyTCPConsumer)
		}
		return result
	}
	measurement := domainTCPMeasurePreparation(r, "capture-mapping-preparation-closing", -1)
	return measurement.end(r.observeTools(ctx, func(observed context.Context) error {
		if observed == nil {
			return ErrDomainPolicyTCPConsumer
		}
		// Each closing still opens its own complete process comparison and
		// reads all actual sources. Only the exact live successor may reuse
		// the enclosing held bytes for its nested predecessor listener.
		// The view closes before returning to mapping registration or phase
		// persistence. The next closing obtains another independent image.
		if baseline != nil && p.scope != nil && p.scope.domainSuccessor != nil &&
			observed.Value(domainTCPPreAddKey{}) == nil && observed.Value(domainTCPBaselineCleanupKey{}) == nil &&
			observed.Value(domainTCPCaptureCleanupKey{}) == nil && observed.Value(domainTCPFailureCleanupKey{}) == nil {
			return r.observeOriginalGuardFiles(observed, baseline, func(observed context.Context, files *xrayDomainTCPFileObservation) error {
				if observed.Value(domainTCPGuardReadKey{}) != nil {
					defer domainTCPMeasure("capture-mapping-preparation-closing-guard")(0)
				}
				if err := p.currentWithFiles(observed, files); err != nil {
					return err
				}
				result := compare(observed, files)
				return errors.Join(result, p.currentWithFiles(observed, files), observed.Err())
			})
		}
		return p.withCurrentFileObservation(observed, func(files *xrayDomainTCPFileObservation) error {
			return compare(observed, files)
		})
	}))
}
