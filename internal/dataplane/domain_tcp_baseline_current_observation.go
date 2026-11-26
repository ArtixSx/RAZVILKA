package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Local associations only, never a process, kernel or flow grant. The actual
// producer below still performs every original source and kernel observation.
type domainTCPBaselineCurrentSources struct {
	owner    *DomainTCPOriginalScope
	resource *domainTCPCaptureExecutionResource
	capture  *DomainPolicyTCPCapture
	xray     *DomainPolicyTCPXray
	baseline *syntheticBaselineExecutionResource
	process  *XrayDomainTCPExecutionResource
	material *XrayDomainTCPOperationMaterial
	binding  *SyntheticDNSExecutionBinding
	scope    *executionResourceScope
	mapping  *dnscontrol.SyntheticDNSMapping
	tools    *SyntheticDNSCommandTools
	backend  *BackendInventory
	reader   DomainTCPBaselineReader
	source   NFQWS2Runner
}

func (r *domainTCPBaselineKernelOwner) originalCurrentSources(ctx context.Context) (*domainTCPBaselineCurrentSources, bool, error) {
	// Cleanup (including malformed markers) retains its exact original path;
	// this byte loan cannot participate in compensation or effect admission.
	if ctx == nil || ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil || r == nil || r.capture == nil || r.capture.capture == nil {
		return nil, false, nil
	}
	owner, original := r.capture.capture.owner.(*DomainTCPOriginalScope)
	if !original {
		return nil, false, nil
	}
	if owner == nil || owner.self != owner || r.self != r || r.capture.process == nil || r.capture.process.material == nil || r.capture.backend == nil {
		return nil, true, ErrDomainTCPBaselineKernel
	}
	if _, observed := r.capture.backend.reader.Runner.(domainTCPToolObserver); !observed {
		return nil, false, nil // Existing modeled/custom source retains full reads.
	}
	c := r.capture
	s := &domainTCPBaselineCurrentSources{owner: owner, resource: c, capture: c.capture, xray: c.capture.xray, baseline: r.baseline, process: c.process, material: c.process.material, binding: c.process.material.binding, scope: c.process.scope, mapping: c.mapping, tools: c.tools, backend: c.backend, reader: r.reader, source: c.backend.reader.Runner}
	return s, true, s.current(ctx, r)
}

func (s *domainTCPBaselineCurrentSources) current(ctx context.Context, r *domainTCPBaselineKernelOwner) error {
	if s == nil || r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil || s.owner == nil || s.owner.self != s.owner || s.resource == nil || s.resource.self != s.resource || s.capture == nil || s.capture.self != s.capture || s.baseline == nil || s.baseline.self != s.baseline || s.process == nil || s.process.self != s.process || s.material == nil || s.material.self != s.material || s.binding == nil || s.binding.self != s.binding || s.tools == nil || s.backend == nil || s.reader == nil {
		return ErrDomainTCPBaselineKernel
	}
	c, p, b := s.resource, s.process, s.baseline
	if r.capture != c || r.baseline != b || !sameNetworkPolicyDependency(r.reader, s.reader) || !sameNetworkPolicyDependency(s.reader, s.tools.Runner) || !sameNetworkPolicyDependency(s.source, s.backend.reader.Runner) ||
		c.capture != s.capture || c.process != p || c.tools != s.tools || c.backend != s.backend || s.mapping == nil || c.mapping != s.mapping || c.mapping != s.material.mapping ||
		s.capture.owner != s.owner || s.xray == nil || s.capture.xray != s.xray || s.xray.resource != p || p.material != s.material || s.material.resource != p || s.material.binding != s.binding || s.scope == nil || p.scope != s.scope || s.binding.scope != s.scope ||
		b.capture != s.capture || b.mapping != c.mapping || b.binding != s.binding || b.tools != s.tools || b.backend != s.backend {
		return ErrDomainTCPBaselineKernel
	}
	o := s.owner
	o.mu.Lock()
	same := !o.closed && o.kernel == r && o.captureResource == c && o.capture == s.capture && o.process == p && o.baseline == b && o.binding == s.binding && sameNetworkPolicyDependency(o.source, s.source)
	o.mu.Unlock()
	if !same {
		return ErrDomainTCPBaselineKernel
	}
	return nil
}

func domainTCPBaselineCurrentReadContext(parent, child context.Context) error {
	if xraySelectedTCPFinite(parent) != nil || xraySelectedTCPFinite(child) != nil {
		return ErrDomainTCPBaselineKernel
	}
	outer, _ := parent.Deadline()
	inner, _ := child.Deadline()
	outerScope, outerOK := parent.Value(syntheticExecutionRegistrarKey{}).(*executionResourceScope)
	innerScope, innerOK := child.Value(syntheticExecutionRegistrarKey{}).(*executionResourceScope)
	if inner.After(outer) || !outerOK || !innerOK || outerScope == nil || innerScope != outerScope ||
		child.Value(domainTCPBaselineCleanupKey{}) != nil || child.Value(domainTCPCaptureCleanupKey{}) != nil || child.Value(domainTCPFailureCleanupKey{}) != nil {
		return ErrDomainTCPBaselineKernel
	}
	return nil
}

// Mismatched SNI/opaque baseline decisions use this standalone Current. Share
// only immutable executable bytes through its existing pure two-pass reader.
// Tools release their provider/gate before use; no lock crosses a callback.
// No Start, Connect, journal mutation or publication occurs inside this body.
func (r *domainTCPBaselineKernelOwner) currentInOriginalFileObservation(ctx context.Context) error {
	s, original, err := r.originalCurrentSources(ctx)
	if err != nil {
		return err
	}
	if !original {
		return r.currentWithFiles(ctx, nil)
	}
	defer domainTCPMeasure("baseline-current-original-file-read")(0)
	err = s.resource.observeTools(ctx, func(observed context.Context) error {
		if err := domainTCPBaselineCurrentReadContext(ctx, observed); err != nil {
			return err
		}
		if err := s.current(observed, r); err != nil {
			return err
		}
		result := s.process.withFileObservation(observed, func(files *xrayDomainTCPFileObservation) error {
			if err := s.current(observed, r); err != nil {
				return err
			}
			result := r.currentWithFiles(observed, files)
			return errors.Join(result, s.current(observed, r), domainTCPBaselineCurrentReadContext(ctx, observed), observed.Err())
		})
		return errors.Join(result, domainTCPBaselineCurrentReadContext(ctx, observed))
	})
	// Both byte closings and original associations complete before returning to
	// the caller that may subsequently issue a journal, effect or native Dial.
	return errors.Join(err, s.current(ctx, r), ctx.Err())
}
