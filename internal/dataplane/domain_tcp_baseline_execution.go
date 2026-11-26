package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

// Retained compiler input in the original execution journal, never an
// accepted socket, routing authority or permission to replay a native dial.
type ExecutionDomainTCPBaselineDefinition struct {
	Schema  int                                 `json:"schema"`
	Capture ExecutionDomainTCPCaptureDefinition `json:"capture"`
	Source  netip.AddrPort                      `json:"source"`
	Target  netip.AddrPort                      `json:"target"`
	Egress  string                              `json:"egress"`
}

func (d ExecutionDomainTCPBaselineDefinition) Clone() ExecutionDomainTCPBaselineDefinition {
	d.Capture = d.Capture.Clone()
	return d
}
func (d ExecutionDomainTCPBaselineDefinition) flowSpec() domainTCPBaselineFlowSpec {
	return domainTCPBaselineFlowSpec{Capture: d.Capture.Process.Capture, Source: d.Source, Target: d.Target, Egress: d.Egress}
}
func validateDomainTCPBaselineExecutionResource(e Execution, r ExecutionResource, terminal bool) error {
	d := r.DomainTCPBaseline
	planID := e.PlanID
	if e.ResourcePlanID != "" {
		planID = e.ResourcePlanID
	}
	if d == nil || d.Schema != 1 || d.Capture.Schema != 1 || r.Kind != "domain-tcp-baseline-flow" || r.NodeTransit != nil || r.NFQWS != nil || r.SyntheticBaseline != nil || r.XraySelectedTCP != nil || r.XrayDomainTCP != nil || r.DomainTCPCapture != nil || d.Capture.Process.validate() != nil || d.Capture.Process.PlanID != planID || d.Capture.Process.PlanDigest != e.Digest {
		return ErrExecutionJournal
	}
	p, err := compileDomainTCPBaselineFlow(d.flowSpec())
	if err != nil {
		return ErrExecutionJournal
	}
	digest, err := PolicyEffectPlanDigest(p)
	if err != nil || r.Generation != p.Generation || r.EffectsDigest != digest {
		return ErrExecutionJournal
	}
	switch r.Phase {
	case "planned", "prepared", "connected", "closed":
		if terminal || r.State != "prepared" {
			return ErrExecutionJournal
		}
	case "removed":
		if r.State != "removed" {
			return ErrExecutionJournal
		}
	case "unused":
		if r.State != "unused" {
			return ErrExecutionJournal
		}
	default:
		return ErrExecutionJournal
	}
	return nil
}

type domainTCPBaselineExecutionResource struct {
	self                   *domainTCPBaselineExecutionResource
	kernel                 *domainTCPBaselineKernelOwner
	accepted               *domainAcceptedTCP
	definition             ExecutionDomainTCPBaselineDefinition
	effects                PolicyEffectPlan
	digest, root, relative string
	anchor                 os.FileInfo
	mu                     sync.Mutex
	entered                bool
	started                bool
	failure                error
	cleanup                *operationgate.ExclusiveCleanupReview
	native                 *domainTCPBaselineNative
}

type domainTCPBaselineCleanupKey struct{}

func (r *domainTCPBaselineExecutionResource) local(ctx context.Context) error {
	if r == nil || r.self != r || r.kernel == nil || r.kernel.self != r.kernel || r.kernel.capture == nil || r.accepted == nil || r.anchor == nil || r.relative == "" || xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainTCPBaselineKernel
	}
	c := r.kernel.capture
	cleanup := ctx.Value(domainTCPBaselineCleanupKey{}) == r
	if cleanup {
		if r.cleanup == nil || r.accepted.self != r.accepted || r.accepted.capture != c.capture || c.process.material.control.CurrentForCleanupOperation(ctx, r.cleanup) != nil {
			return ErrDomainTCPBaselineKernel
		}
	} else if err := r.accepted.current(ctx, c.capture, r.accepted.socket); err != nil {
		return err
	}
	if !reflect.DeepEqual(r.definition.Capture, c.definition) || r.definition.Source != r.accepted.socket.Source || r.definition.Target != netip.AddrPortFrom(c.definition.Process.Capture.Xray.RealIP, r.accepted.socket.OriginalDestination.Port()) || r.definition.Egress != r.kernel.path.Egress || r.root != filepath.Join(c.process.scope.root, r.relative) {
		return ErrDomainTCPBaselineKernel
	}
	p, err := compileDomainTCPBaselineFlow(r.definition.flowSpec())
	if err != nil || !reflect.DeepEqual(p, r.effects) {
		return ErrDomainTCPBaselineKernel
	}
	digest, err := PolicyEffectPlanDigest(p)
	if err != nil || digest != r.digest {
		return ErrDomainTCPBaselineKernel
	}
	return nil
}
func (r *domainTCPBaselineExecutionResource) registered(ctx context.Context) error {
	if err := r.local(ctx); err != nil {
		return err
	}
	s := r.kernel.capture.process.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	cleanup := ctx.Value(domainTCPBaselineCleanupKey{}) == r
	if !s.open || !cleanup && (s.syntheticClosing || s.failure != nil) || s.domainTCPBaselines[filepath.Base(r.relative)] != r || s.checkOriginalOwner(ctx, nil, !cleanup, cleanup) != nil {
		return ErrDomainTCPBaselineKernel
	}
	info, err := s.owned.Stat(r.relative)
	if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(info, r.anchor) {
		return ErrDomainTCPBaselineKernel
	}
	for _, record := range s.execution.Resources {
		if record.ID == filepath.Base(r.relative) {
			if validateDomainTCPBaselineExecutionResource(*s.execution, record, false) != nil || record.State != "prepared" || !reflect.DeepEqual(record.DomainTCPBaseline, &r.definition) {
				return ErrDomainTCPBaselineKernel
			}
			return nil
		}
	}
	return ErrDomainTCPBaselineKernel
}

func issueDomainTCPBaselineFlow(ctx context.Context, kernel *domainTCPBaselineKernelOwner, socket DomainPolicyTCPSocket) (*domainTCPBaselineExecutionResource, error) {
	if kernel == nil || kernel.self != kernel || kernel.capture == nil {
		return nil, ErrDomainTCPBaselineKernel
	}
	accepted, err := originalDomainAcceptedTCP(ctx, kernel.capture.capture, socket)
	if err != nil {
		return nil, err
	}
	if err := kernel.Current(ctx); err != nil {
		return nil, err
	}
	c := kernel.capture
	cleanup, err := c.process.material.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, err
	}
	d := ExecutionDomainTCPBaselineDefinition{Schema: 1, Capture: c.definition.Clone(), Source: socket.Source, Target: netip.AddrPortFrom(c.definition.Process.Capture.Xray.RealIP, socket.OriginalDestination.Port()), Egress: kernel.path.Egress}
	p, err := compileDomainTCPBaselineFlow(d.flowSpec())
	if err != nil {
		return nil, err
	}
	digest, err := PolicyEffectPlanDigest(p)
	if err != nil {
		return nil, err
	}
	r := &domainTCPBaselineExecutionResource{kernel: kernel, accepted: accepted, definition: d, effects: p, digest: digest, cleanup: cleanup}
	r.self = r
	s := c.process.scope
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || !s.domainTCPProof || s.domainTCPOwner == nil || s.domainTCPOwner.kernel != kernel || s.syntheticClosing || s.failure != nil || s.resourceCount() >= maxExecutionResources || s.checkOriginalOwner(ctx, nil, true, false) != nil {
		return nil, ErrDomainTCPBaselineKernel
	}
	// The fixed table/mark is exclusively owned by one original flow until its
	// socket and COMMON effects have both been positively retired.
	for _, prior := range s.execution.Resources {
		if prior.DomainTCPBaseline != nil && prior.State != "removed" && prior.State != "unused" {
			return nil, ErrDomainTCPBaselineKernel
		}
	}
	if err := s.owned.MkdirAll("execution-resources", 0700); err != nil {
		return nil, executionJournalError(err)
	}
	relative, err := s.owned.MkdirTemp("execution-resources", "bf-")
	if err != nil {
		return nil, executionJournalError(err)
	}
	anchor, err := s.owned.Stat(relative)
	if err != nil {
		return nil, executionJournalError(err)
	}
	r.relative, r.root, r.anchor = relative, filepath.Join(s.root, relative), anchor
	if err := r.local(ctx); err != nil {
		return nil, err
	}
	for _, path := range []string{r.root, filepath.Dir(r.root), s.root} {
		opened, err := openJournalDirectory(path)
		if err != nil {
			return nil, executionJournalError(err)
		}
		if err := errors.Join(syncDataplaneJournalDirectory(opened), opened.Close()); err != nil {
			return nil, executionJournalError(err)
		}
	}
	if s.domainTCPBaselines == nil {
		s.domainTCPBaselines = map[string]*domainTCPBaselineExecutionResource{}
	}
	s.domainTCPBaselines[filepath.Base(relative)] = r
	copy := d.Clone()
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: filepath.Base(relative), Kind: "domain-tcp-baseline-flow", State: "prepared", Phase: "planned", Generation: p.Generation, EffectsDigest: digest, DomainTCPBaseline: &copy})
	if err := s.persist(); err != nil {
		return r, err
	}
	if !kernel.flow.CompareAndSwap(nil, r) {
		return r, ErrDomainTCPBaselineKernel
	}
	return r, nil
}
