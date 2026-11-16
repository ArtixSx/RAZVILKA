package dataplane

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// These are tentative local results until the original file/tool closing has
// completed. No file view or observed tool context escapes this reader.
type domainTCPAcceptedPrefix struct {
	// Generic owners keep the exact original accepted context identity. The
	// observed path fills this from the CALLER context only after closing.
	flowContext context.Context
	accepted    *domainAcceptedTCP
	lease       DomainPolicyTCPFlowLease
	flowID      string
	binding     *domainPolicyTCPSyntheticBinding
	flow        DomainPolicyTCPFlow
	kernel      *domainTCPBaselineKernelOwner
}

// Preserve the snapshots taken by handleTCP before its first owner callback.
type domainTCPAcceptedPrefixInput struct {
	spec   DomainPolicyTCPCaptureSpec
	owner  DomainPolicyTCPCaptureOwner
	xray   *DomainPolicyTCPXray
	policy *DomainPolicy
}

func (i domainTCPAcceptedPrefixInput) current(c *DomainPolicyTCPCapture) error {
	if c == nil || c.self != c || c.spec != i.spec || c.owner != i.owner || c.xray != i.xray || c.policy != i.policy {
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}

func (r domainTCPAcceptedPrefix) revoke() {
	if r.accepted != nil {
		r.accepted.open.Store(false)
	}
}

// A parent file view only replaces full-byte work. Unlike the lower
// currentSyntheticMappingWithFiles comparator, this preserves the standalone
// mapping reader's baseCurrent AND both complete process bookends.
func (o *DomainTCPOriginalScope) currentSyntheticMappingFrom(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, files *xrayDomainTCPFileObservation) error {
	if files == nil {
		return o.CurrentSyntheticMapping(ctx, mapping)
	}
	if o == nil || o.self != o || ctx == nil || ctx.Err() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	open, closed := o.publicationOpen, o.closed
	o.mu.Unlock()
	if !open || closed {
		return ErrDomainPolicyTCPConsumer
	}
	return o.compareSyntheticMappingFrom(ctx, mapping, files)
}

// Only initial-current, AdmitTCP and baseline selection run here. The accepted
// marker is created AFTER initial-current, exactly as on the ordinary path.
// Flow validation remains between admission and baseline selection. No sniff,
// guard of a later policy phase, WithFlow, Dial or effect enters this bracket.
func (c *DomainPolicyTCPCapture) readAcceptedPrefix(ctx context.Context, conn *net.TCPConn, socket DomainPolicyTCPSocket, mapping *dnscontrol.SyntheticDNSMapping, prepared *DomainPolicyTCPCaptureMapping, input domainTCPAcceptedPrefixInput, files *xrayDomainTCPFileObservation) (out domainTCPAcceptedPrefix, result error) {
	finishInitial := domainTCPMeasureAcceptedStage(ctx, "initial-current")
	currentErr := prepared.currentWithFiles(ctx, files)
	finishInitial(currentErr)
	if currentErr != nil {
		return out, currentErr
	}
	accepted := &domainAcceptedTCP{capture: c, conn: conn, socket: socket}
	accepted.self = accepted
	accepted.open.Store(true)
	complete := false
	defer func() {
		if !complete {
			accepted.open.Store(false)
		}
	}()
	parent := ctx
	ctx = context.WithValue(ctx, domainAcceptedTCPKey{}, accepted)
	if files != nil {
		child, closeChild, err := files.forOriginalToolRead(parent, ctx, files.resource)
		if err != nil {
			return out, err
		}
		defer closeChild()
		files = child
	}
	finishAdmit := domainTCPMeasureAcceptedStage(ctx, "admit")
	var lease DomainPolicyTCPFlowLease
	var err error
	if files != nil {
		original, ok := input.owner.(*DomainTCPOriginalScope)
		if !ok {
			finishAdmit(ErrDomainPolicyTCPConsumer)
			return out, ErrDomainPolicyTCPConsumer
		}
		lease, err = original.admitTCPFrom(ctx, socket, files)
	} else {
		lease, err = input.owner.AdmitTCP(ctx, socket)
	}
	if err != nil || lease == nil {
		finishAdmit(ErrDomainPolicyTCPConsumer)
		return out, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	finishAdmit(nil)
	leased, flowID := lease.Binding()
	if leased != mapping {
		return out, ErrDomainPolicyTCPConsumer
	}
	observation := prepared.flowComparison()
	binding := &domainPolicyTCPSyntheticBinding{mapping: observation, socket: socket, spec: input.spec.Xray}
	flow := DomainPolicyTCPFlow{Generation: observation.Generation, FlowID: flowID, Source: socket.Source, Destination: socket.OriginalDestination, Client: observation.Client, synthetic: binding}
	if observation.Client != input.spec.Client || !input.policy.validTCPFlow(flow) || !time.Now().Before(observation.ExpiresAt) || !input.xray.matches(input.spec.Xray) {
		return out, ErrDomainPolicyTCPConsumer
	}
	var kernel *domainTCPBaselineKernelOwner
	if original, ok := input.owner.(*DomainTCPOriginalScope); ok {
		finishBaseline := domainTCPMeasureAcceptedStage(ctx, "baseline")
		kernel, err = original.originalBaselineForCaptureFrom(ctx, c, leased, files)
		finishBaseline(err)
		if err != nil {
			return out, err
		}
	}
	var flowContext context.Context
	if files == nil {
		flowContext = ctx
	}
	complete = true
	return domainTCPAcceptedPrefix{flowContext: flowContext, accepted: accepted, lease: lease, flowID: flowID, binding: binding, flow: flow, kernel: kernel}, nil
}

func (c *DomainPolicyTCPCapture) acceptedPrefix(ctx context.Context, conn *net.TCPConn, socket DomainPolicyTCPSocket, mapping *dnscontrol.SyntheticDNSMapping, prepared *DomainPolicyTCPCaptureMapping, input domainTCPAcceptedPrefixInput) (out domainTCPAcceptedPrefix, result error) {
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil || prepared == nil || prepared.self != prepared || prepared.capture != c || prepared.source != mapping {
		return out, ErrDomainPolicyTCPConsumer
	}
	original, ok := input.owner.(*DomainTCPOriginalScope)
	if !ok {
		return c.readAcceptedPrefix(ctx, conn, socket, mapping, prepared, input, nil)
	}
	if original == nil || original.self != original {
		return out, ErrDomainPolicyTCPConsumer
	}
	original.mu.Lock()
	kernel := original.kernel
	original.mu.Unlock()
	if kernel == nil {
		return c.readAcceptedPrefix(ctx, conn, socket, mapping, prepared, input, nil)
	}
	baseline, eligible, err := kernel.originalCurrentSources(ctx)
	if err != nil {
		return out, err
	}
	if !eligible {
		return c.readAcceptedPrefix(ctx, conn, socket, mapping, prepared, input, nil)
	}
	sources := &domainTCPMappingReadSources{baseline: baseline, kernel: kernel, prepared: prepared}
	if err := errors.Join(sources.current(ctx, original, baseline.process, mapping), input.current(c)); err != nil {
		return out, err
	}
	out, result = domainTCPAcceptedPrefixObserved(ctx, baseline.resource.observeTools, func(observed context.Context) (domainTCPAcceptedPrefix, error) {
		var readResult domainTCPAcceptedPrefix
		returned := false
		defer func() {
			if !returned {
				readResult.revoke()
			}
		}()
		if err := domainTCPBaselineCurrentReadContext(ctx, observed); err != nil {
			return readResult, err
		}
		if err := errors.Join(sources.current(observed, original, baseline.process, mapping), input.current(c)); err != nil {
			return readResult, err
		}
		err := baseline.process.withFileObservation(observed, func(files *xrayDomainTCPFileObservation) error {
			var readErr error
			readResult, readErr = c.readAcceptedPrefix(observed, conn, socket, mapping, prepared, input, files)
			return errors.Join(readErr, sources.current(observed, original, baseline.process, mapping), input.current(c), domainTCPBaselineCurrentReadContext(ctx, observed))
		})
		returned = true
		return readResult, err
	})
	result = errors.Join(result, sources.current(ctx, original, baseline.process, mapping), input.current(c), ctx.Err())
	if result != nil || out.kernel != kernel {
		out.revoke()
		return domainTCPAcceptedPrefix{}, errors.Join(result, ErrDomainPolicyTCPConsumer)
	}
	out.flowContext = context.WithValue(ctx, domainAcceptedTCPKey{}, out.accepted)
	return out, nil
}

// Join/revoke the same existing observer lifetime, then publish only a complete
// result. It holds no capability or view and never calls a later flow phase.
func domainTCPAcceptedPrefixObserved(ctx context.Context, observe func(context.Context, func(context.Context) error) error, read func(context.Context) (domainTCPAcceptedPrefix, error)) (out domainTCPAcceptedPrefix, result error) {
	if ctx == nil || ctx.Err() != nil || observe == nil || read == nil {
		return out, ErrDomainPolicyTCPConsumer
	}
	complete, bodyComplete := false, false
	defer func() {
		if !complete {
			out.revoke()
			out = domainTCPAcceptedPrefix{}
		}
	}()
	result = domainTCPBaselineToolComparison(ctx, observe, func(observed context.Context) error {
		var err error
		out, err = read(observed)
		bodyComplete = true
		return err
	})
	result = errors.Join(result, ctx.Err())
	if result != nil || !bodyComplete || out.accepted == nil || out.lease == nil {
		return out, errors.Join(result, ErrDomainPolicyTCPConsumer)
	}
	complete = true
	return out, nil
}
