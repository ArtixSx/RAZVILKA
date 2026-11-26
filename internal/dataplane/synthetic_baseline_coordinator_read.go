package dataplane

import (
	"context"
	"errors"
	"net"
	"reflect"
)

// Comparison-only frozen associations. This is never a Current/registration
// grant and is created only around the hardcoded coordinator read below.
type syntheticBaselineCoordinatorRead struct {
	coordinator *syntheticBaselineCoordinator
	frozen      syntheticBaselineCoordinator
	owner       *DomainTCPOriginalScope
	xray        *DomainPolicyTCPXray
	process     *XrayDomainTCPExecutionResource
	material    *XrayDomainTCPOperationMaterial
	listener    *net.TCPListener
	source      any
}

func (r *syntheticBaselineCoordinatorRead) association(ctx context.Context) error {
	if r == nil || r.coordinator == nil || r.owner == nil || r.owner.self != r.owner ||
		r.coordinator.self != r.frozen.self || r.coordinator.binding != r.frozen.binding ||
		r.coordinator.tools != r.frozen.tools || r.coordinator.backend != r.frozen.backend ||
		r.coordinator.capture != r.frozen.capture || r.coordinator.control != r.frozen.control ||
		r.coordinator.toolsFrozen.Provider != r.frozen.toolsFrozen.Provider ||
		!sameNetworkPolicyDependency(r.coordinator.toolsFrozen.Runner, r.frozen.toolsFrozen.Runner) ||
		!reflect.DeepEqual(r.coordinator.toolsFrozen, r.frozen.toolsFrozen) ||
		r.frozen.capture == nil || r.frozen.backend == nil ||
		r.frozen.tools != &r.owner.tools || r.frozen.backend != r.owner.backend ||
		r.frozen.binding != r.owner.binding || !sameNetworkPolicyDependency(r.owner.source, r.source) ||
		!sameNetworkPolicyDependency(r.frozen.backend.reader.Runner, r.source) ||
		!sameNetworkPolicyDependency(r.owner.tools.Runner, r.frozen.toolsFrozen.Runner) ||
		r.owner.tools.Provider != r.frozen.toolsFrozen.Provider ||
		!reflect.DeepEqual(r.owner.tools, r.frozen.toolsFrozen) {
		return ErrSyntheticBaselineTransition
	}
	return r.frozen.capture.originalReadAssociation(ctx, r.owner, r.xray, r.process, r.material, r.frozen.binding, r.listener)
}

func (c *syntheticBaselineCoordinator) observeOriginalCapturePair(ctx context.Context) error {
	// Current already completed local/binding/control checks. Custom producers
	// retain their exact old full-byte path, without a borrowed observation.
	owner, original := c.capture.owner.(*DomainTCPOriginalScope)
	if !original {
		return c.currentCapturePairWithFiles(ctx, nil)
	}
	if _, supported := c.backend.reader.Runner.(domainTCPToolObserver); !supported {
		return c.currentCapturePairWithFiles(ctx, nil)
	}
	if owner == nil || c.capture.xray == nil || c.capture.xray.resource == nil {
		return ErrSyntheticBaselineTransition
	}
	process := c.capture.xray.resource
	read := &syntheticBaselineCoordinatorRead{coordinator: c, frozen: *c, owner: owner,
		xray: c.capture.xray, process: process, material: process.material,
		listener: c.capture.listener, source: owner.source}
	if err := read.association(ctx); err != nil {
		return err
	}
	defer domainTCPMeasure("coordinator-original-read")(0)
	result := process.withFileObservation(ctx, func(files *xrayDomainTCPFileObservation) error {
		if err := read.association(ctx); err != nil {
			return err
		}
		result := c.currentCapturePairWithFiles(ctx, files)
		// Closing association runs even if a callback/Current refused. No mutex
		// is held while a callback executes, and no callback receives the view.
		return errors.Join(result, read.association(ctx), ctx.Err())
	})
	result = errors.Join(result, read.association(ctx), ctx.Err())
	if result == nil {
		domainTCPMeasure("coordinator-original-read-complete")(0)
	}
	return result
}
