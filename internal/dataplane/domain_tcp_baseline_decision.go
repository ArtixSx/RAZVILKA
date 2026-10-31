package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/autonomy"
)

func (r *domainTCPBaselineKernelOwner) guardFlow(ctx context.Context, flow DomainPolicyTCPFlow) error {
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
	return r.Current(ctx)
}

// Re-evaluated before and after the actual dial. Unknown/blocked/negative scope
// decisions are never converted into a positive route. The witnessed fallback
// keeps the native routed baseline, including its original numeric destination;
// it cannot send an opaque or mismatched name to the selected node/default.
func (p *DomainPolicy) decideTCPWithBaseline(ctx context.Context, flow DomainPolicyTCPFlow, question DomainPolicyFlow, scope autonomy.ScopeObservation, runtime DomainPolicyTCPRuntime) (DomainPolicyDecision, error) {
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
	if err := runtime.originalBaseline.guardFlow(ctx, flow); err != nil {
		return d, err
	}
	if d.Kind != "baseline" {
		d.Kind, d.Route, d.ServiceID, d.Reason = "baseline", "direct", "", "SYNTHETIC_ORIGINAL_BASELINE"
	}
	return d, nil
}
