package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/autonomy"
)

func (r *domainTCPBaselineKernelOwner) guardFlow(ctx context.Context, flow DomainPolicyTCPFlow) error {
	return r.guardFlowFrom(ctx, flow, nil)
}

func (r *domainTCPBaselineKernelOwner) guardFlowFrom(ctx context.Context, flow DomainPolicyTCPFlow, files *xrayDomainTCPFileObservation) error {
	if r == nil || r.self != r || r.capture == nil || flow.synthetic == nil || !flow.synthetic.matches(flow) || flow.synthetic.mapping.PublicationID != r.capture.definition.Process.Mapping.PublicationID || flow.synthetic.mapping.RealIP != r.capture.definition.Process.Capture.Xray.RealIP {
		return ErrDomainTCPBaselineKernel
	}
	socket := DomainPolicyTCPSocket{Source: flow.Source, OriginalDestination: flow.Destination, Listener: r.capture.definition.Process.Capture.Listen}
	if _, err := originalDomainAcceptedTCP(ctx, r.capture.capture, socket); err != nil {
		return err
	}
	if err := r.capture.mapping.Current(ctx); err != nil {
		return err
	}
	if files == nil {
		return r.Current(ctx)
	}
	sources, observed, err := r.originalCurrentSources(ctx)
	if err != nil {
		return err
	}
	if !observed {
		return r.Current(ctx) // Modeled/custom sources use the original complete read.
	}
	if err := files.current(ctx, r.capture.process); err != nil {
		return errors.Join(ErrDomainTCPBaselineKernel, err)
	}
	result := r.currentWithFiles(ctx, files)
	return errors.Join(result, sources.current(ctx, r), files.current(ctx, r.capture.process), ctx.Err())
}

// Re-evaluated before and after the actual dial. Unknown/blocked/negative scope
// decisions are never converted into a positive route. The witnessed fallback
// keeps the native routed baseline, including its original numeric destination;
// it cannot send an opaque or mismatched name to the selected node/default.
func (p *DomainPolicy) decideTCPWithBaseline(ctx context.Context, flow DomainPolicyTCPFlow, question DomainPolicyFlow, scope autonomy.ScopeObservation, runtime DomainPolicyTCPRuntime) (DomainPolicyDecision, error) {
	return p.decideTCPWithBaselineFrom(ctx, flow, question, scope, runtime, nil)
}

func (p *DomainPolicy) decideTCPWithBaselineFrom(ctx context.Context, flow DomainPolicyTCPFlow, question DomainPolicyFlow, scope autonomy.ScopeObservation, runtime DomainPolicyTCPRuntime, files *xrayDomainTCPFileObservation) (DomainPolicyDecision, error) {
	d := p.DecideWithScope(question, scope, runtime.now())
	if flow.synthetic == nil || flow.synthetic.acceptsDecision(d) && question.NameState == DomainPolicyNameVisible && question.Name == flow.synthetic.mapping.Name && !question.Coalesced {
		return d, nil
	}
	if runtime.originalBaseline == nil || runtime.BaselineDial == nil {
		return d, nil
	}
	if d.Kind != "baseline" && d.Kind != "service" && d.Kind != "default" {
		return d, nil
	}
	if err := runtime.originalBaseline.guardFlowFrom(ctx, flow, files); err != nil {
		return d, err
	}
	if d.Kind != "baseline" {
		d.Kind, d.Route, d.ServiceID, d.Reason = "baseline", "direct", "", "SYNTHETIC_ORIGINAL_BASELINE"
	}
	return d, nil
}
