package dataplane

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Only the original failed preparation can retain this comparison. It proves
// no publication and no baseline-flow issuer; it cannot supply a kernel owner,
// publish DNS, admit a flow, or detach a published standby for continuation.
type domainTCPUnpublishedPreparation struct {
	self           *domainTCPUnpublishedPreparation
	owner          *DomainTCPOriginalScope
	cursor         *domainTCPFailureCleanup
	process        *XrayDomainTCPExecutionResource
	capture        *domainTCPCaptureExecutionResource
	baseline       *syntheticBaselineExecutionResource
	closed         *dnscontrol.SyntheticDNSRetirementReview
	materialClosed *dnscontrol.SyntheticDNSRetirementReview
	source         *dnscontrol.NetworkPolicyDNSSyntheticResolver
	control        *operationgate.ControlEpochReview
	row            dnscontrol.SyntheticDNSMappingObservation
}

// No failed forward context is revived. Callers removing effects also require
// the active original cleanup cursor and its fresh SAME-Gate review separately.
func (o *DomainTCPOriginalScope) unpublishedInputsCurrent(ctx context.Context, p *XrayDomainTCPExecutionResource, capture *domainTCPCaptureExecutionResource, baseline *syntheticBaselineExecutionResource) (dnscontrol.SyntheticDNSMappingObservation, error) {
	var zero dnscontrol.SyntheticDNSMappingObservation
	if o == nil || o.self != o || ctx == nil || ctx.Err() != nil || p == nil || p.self != p || p.scope == nil || p.material == nil || o.binding == nil || p.material.binding != o.binding || p.scope != o.binding.scope || capture == nil || capture.self != capture || capture.capture == nil || capture.process != p || baseline == nil || baseline.self != baseline || baseline.capture != capture.capture || baseline.mapping == nil || baseline.mapping != capture.mapping || baseline.retirement == nil || p.material.retirement == nil || baseline.binding != p.material.binding || baseline.mapping != p.material.mapping || baseline.control != p.material.control || baseline.inspector == nil || baseline.inspector.self != baseline.inspector {
		return zero, ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	same := o.process == p && o.captureResource == capture && o.baseline == baseline && o.capture == capture.capture && o.kernel == nil && o.closed && !o.publicationOpen
	o.mu.Unlock()
	if !same || p.child == nil || p.child.Joined(ctx) != nil || p.material.session == nil || p.material.session.inactiveJoined() != nil || capture.capture == nil || capture.capture.retirement == nil {
		return zero, ErrDomainPolicyTCPConsumer
	}
	if err := capture.capture.retirement.Joined(ctx); err != nil {
		return zero, err
	}
	s := p.scope
	s.mu.Lock()
	same = s.domainTCPOwner == o && s.domainTCPCaptures[filepath.Base(capture.relative)] == capture && s.syntheticBaselines[filepath.Base(baseline.relative)] == baseline && unpublishedDomainNoFlowLocked(s)
	s.mu.Unlock()
	if !same {
		return zero, ErrDomainPolicyTCPConsumer
	}
	// The two original producers independently reviewed this SAME live mapping.
	// Their opaque views are distinct allocations, not interchangeable owners.
	// Observe both actual closed ledgers and preserve both pointers below.
	row, err := baseline.retirement.ObserveClosed(ctx)
	if err != nil || row.PossiblyIssued || !syntheticSettlementCoordinatesEqual(row, p.material.observation) {
		return zero, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	materialRow, err := p.material.retirement.ObserveClosed(ctx)
	if err != nil || materialRow.PossiblyIssued || !syntheticSettlementCoordinatesEqual(materialRow, p.material.observation) || !syntheticSettlementCoordinatesEqual(row, materialRow) {
		return zero, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return row, ctx.Err()
}

func (r *domainTCPFailureCleanup) freezeUnpublishedPreparation(ctx context.Context, o *DomainTCPOriginalScope, capture *domainTCPCaptureExecutionResource, baseline *syntheticBaselineExecutionResource) error {
	if r == nil || r.local(ctx, r.resource) != nil || capture == nil || capture.self != capture || baseline == nil || baseline.self != baseline || baseline.inspector == nil || r.capture != capture || !r.captureDetached || !r.imageACK || r.imageStage != "capture" || o == nil {
		return ErrPolicyAdditionUnknown
	}
	if err := r.resource.records.current(ctx, true); err != nil {
		return err
	}
	capture.mu.Lock()
	detached := capture.retirementDetached && baseline.inspector.capture.Load() == nil
	capture.mu.Unlock()
	if !detached {
		return ErrPolicyAdditionUnknown
	}
	row, err := o.unpublishedInputsCurrent(ctx, r.resource, capture, baseline)
	if err != nil {
		return err
	}
	u := &domainTCPUnpublishedPreparation{owner: o, cursor: r, process: r.resource, capture: capture, baseline: baseline, closed: baseline.retirement, materialClosed: r.resource.material.retirement, source: r.resource.material.dnsSource, control: r.resource.material.control, row: row}
	u.self = u
	u.row.CNAMEChain = append([]string(nil), row.CNAMEChain...)
	o.mu.Lock()
	if o.unpublishedPreparation == nil {
		o.unpublishedPreparation = u
	}
	u = o.unpublishedPreparation
	o.mu.Unlock()
	return u.current(ctx, o)
}

func (u *domainTCPUnpublishedPreparation) current(ctx context.Context, o *DomainTCPOriginalScope) error {
	if u == nil || u.self != u || u.owner != o || o == nil || u.cursor == nil || u.cursor.self != u.cursor || u.cursor.cursor == nil || u.cursor.resource != u.process || u.capture == nil || u.cursor.capture != u.capture || u.process == nil || u.process.scope == nil || u.process.material == nil || u.source == nil || u.process.material.dnsSource != u.source || u.control == nil || u.process.material.control != u.control || u.closed == nil || u.materialClosed == nil || u.materialClosed != u.process.material.retirement || u.baseline == nil || u.baseline.inspector == nil || u.closed != u.baseline.retirement || u.row.PossiblyIssued {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	same := o.unpublishedPreparation == u
	o.mu.Unlock()
	if !same {
		return ErrDomainPolicyTCPConsumer
	}
	s := u.process.scope
	s.mu.Lock()
	same = s.domainSuccessor == u.cursor.cursor
	s.mu.Unlock()
	if !same {
		return ErrDomainPolicyTCPConsumer
	}
	u.capture.mu.Lock()
	detached := u.capture.retirementDetached && u.baseline.inspector.capture.Load() == nil
	u.capture.mu.Unlock()
	if !detached {
		return ErrDomainPolicyTCPConsumer
	}
	row, err := o.unpublishedInputsCurrent(ctx, u.process, u.capture, u.baseline)
	if err != nil || !syntheticSettlementCoordinatesEqual(row, u.row) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return nil
}

// Pure shape check under scope.mu only; this is not a receipt/native grant.
func unpublishedDomainNoFlowLocked(s *executionResourceScope) bool {
	if s == nil || s.execution == nil || len(s.domainTCPBaselines) != 0 {
		return false
	}
	for _, record := range s.execution.Resources {
		if record.Kind == "domain-tcp-baseline-flow" || record.DomainTCPBaseline != nil {
			return false
		}
	}
	return true
}
