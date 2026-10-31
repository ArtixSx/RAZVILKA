package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Retained comparison input in the existing execution journal. Neither this
// definition nor a complete receipt can reconstruct the original listener.
type ExecutionDomainTCPCaptureDefinition struct {
	Schema  int                              `json:"schema"`
	Process ExecutionXrayDomainTCPDefinition `json:"process"`
}

func (d ExecutionDomainTCPCaptureDefinition) Clone() ExecutionDomainTCPCaptureDefinition {
	d.Process = d.Process.Clone()
	return d
}

func validateDomainTCPCaptureExecutionResource(execution Execution, r ExecutionResource, terminal bool) error {
	d := r.DomainTCPCapture
	planID := execution.PlanID
	if execution.ResourcePlanID != "" {
		planID = execution.ResourcePlanID
	}
	if d == nil || d.Schema != 1 || r.Kind != "domain-tcp-capture" || r.XrayDomainTCP != nil || r.XraySelectedTCP != nil || r.NFQWS != nil || r.NodeTransit != nil || r.SyntheticBaseline != nil || d.Process.validate() != nil || d.Process.PlanID != planID || d.Process.PlanDigest != execution.Digest {
		return ErrExecutionJournal
	}
	plan, err := compileDomainTCPCaptureEffects(d.Process.Capture, d.Process.Mapping)
	if err != nil {
		return errors.Join(ErrExecutionJournal, err)
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil || r.Generation != plan.Generation || r.EffectsDigest != digest {
		return ErrExecutionJournal
	}
	switch r.Phase {
	case "planned", "capture-prepared", "closed":
		if r.State != "prepared" || terminal {
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

// Issued only around the actual opened capture and original started process.
// No public constructor accepts an effects plan, root or readiness callback.
type domainTCPCaptureExecutionResource struct {
	self                   *domainTCPCaptureExecutionResource
	process                *XrayDomainTCPExecutionResource
	capture                *DomainPolicyTCPCapture
	mapping                *dnscontrol.SyntheticDNSMapping
	tools                  *SyntheticDNSCommandTools
	toolsFrozen            SyntheticDNSCommandTools
	backend                *BackendInventory
	definition             ExecutionDomainTCPCaptureDefinition
	effects                PolicyEffectPlan
	digest, root, relative string
	anchor                 os.FileInfo
	mu                     sync.Mutex
	started                bool
	failed                 error
}

func (r *domainTCPCaptureExecutionResource) local(ctx context.Context) error {
	if r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil || r.process == nil || r.process.self != r.process || r.process.material == nil || r.capture == nil || r.capture.self != r.capture || r.capture.xray == nil || r.capture.xray.resource != r.process || r.capture.spec != r.definition.Process.Capture || r.mapping != r.process.material.mapping || r.capture.listener == nil || r.tools == nil || !r.tools.valid() || !reflect.DeepEqual(*r.tools, r.toolsFrozen) || r.backend == nil || r.process.scope == nil || r.process.scope.networkIdentity == nil {
		return ErrDomainPolicyTCPConsumer
	}
	s := r.process.scope
	if ctx.Value(syntheticExecutionRegistrarKey{}) != s || r.tools.Provider != s.networkIdentity.provider || r.tools.Identity != s.networkIdentity.value || r.backend.reader.Provider != r.tools.Provider || r.backend.review != r.tools.ReviewSHA256 || r.backend.reader.IPTables != r.tools.IPTables || r.root != filepath.Join(s.root, r.relative) || r.anchor == nil || r.relative == "" {
		return ErrDomainPolicyTCPConsumer
	}
	if !reflect.DeepEqual(r.definition.Process, r.process.definition) {
		return ErrDomainPolicyTCPConsumer
	}
	address, err := r.capture.Address()
	if err != nil || address != r.capture.spec.Listen {
		return ErrDomainPolicyTCPConsumer
	}
	raw, err := r.capture.listener.SyscallConn()
	if err != nil {
		return err
	}
	if err = raw.Control(func(uintptr) {}); err != nil {
		return err
	}
	r.capture.mu.Lock()
	closed := r.capture.closed
	r.capture.mu.Unlock()
	if closed || r.capture.ctx.Err() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	plan, err := compileDomainTCPCaptureEffects(r.definition.Process.Capture, r.definition.Process.Mapping)
	if err != nil || !reflect.DeepEqual(plan, r.effects) {
		return ErrDomainPolicyTCPConsumer
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil || digest != r.digest {
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}

func (r *domainTCPCaptureExecutionResource) registered(ctx context.Context) error {
	if err := r.local(ctx); err != nil {
		return err
	}
	s := r.process.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.syntheticClosing || s.failure != nil || s.domainTCPCaptures[filepath.Base(r.relative)] != r || s.checkOriginalOwner(ctx, nil, true, false) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	info, err := s.owned.Stat(r.relative)
	if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(info, r.anchor) {
		return ErrDomainPolicyTCPConsumer
	}
	for _, record := range s.execution.Resources {
		if record.ID == filepath.Base(r.relative) {
			if validateDomainTCPCaptureExecutionResource(*s.execution, record, false) != nil || record.State != "prepared" || !reflect.DeepEqual(record.DomainTCPCapture, &r.definition) {
				return ErrDomainPolicyTCPConsumer
			}
			return nil
		}
	}
	return ErrDomainPolicyTCPConsumer
}

func (r *domainTCPCaptureExecutionResource) current(ctx context.Context) error {
	if err := r.registered(ctx); err != nil {
		return err
	}
	if err := r.process.Current(ctx); err != nil {
		return err
	}
	if err := r.mapping.Current(ctx); err != nil {
		return err
	}
	if err := r.tools.Runner.CheckSyntheticDNS(ctx, r.tools.Identity); err != nil {
		return err
	}
	return r.registered(ctx)
}

func issueDomainTCPCaptureResource(ctx context.Context, process *XrayDomainTCPExecutionResource, capture *DomainPolicyTCPCapture, baseline *syntheticBaselineExecutionResource) (*domainTCPCaptureExecutionResource, error) {
	if baseline == nil || baseline.self != baseline || baseline.capture != capture || baseline.binding == nil || baseline.mapping == nil || baseline.inspector == nil || baseline.inspector.self != baseline.inspector {
		return nil, ErrDomainPolicyTCPConsumer
	}
	tools, backend := baseline.tools, baseline.backend
	if process == nil || process.self != process || process.material == nil || capture == nil || capture.self != capture || capture.xray == nil || capture.xray.resource != process || tools == nil || !tools.valid() || backend == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := process.Current(ctx); err != nil {
		return nil, err
	}
	if baseline.binding != process.material.binding || baseline.mapping != process.material.mapping {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := baseline.currentBaseline(ctx); err != nil {
		return nil, err
	}
	plan, err := compileDomainTCPCaptureEffects(process.definition.Capture, process.definition.Mapping)
	if err != nil {
		return nil, err
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil {
		return nil, err
	}
	r := &domainTCPCaptureExecutionResource{process: process, capture: capture, mapping: process.material.mapping, tools: tools, toolsFrozen: *tools, backend: backend, definition: ExecutionDomainTCPCaptureDefinition{Schema: 1, Process: process.definition.Clone()}, effects: plan, digest: digest}
	r.self = r
	s := process.scope
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.syntheticClosing || s.failure != nil || s.resourceCount() >= maxExecutionResources || s.checkOriginalOwner(ctx, nil, true, false) != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	for _, previous := range s.domainTCPCaptures {
		if previous.capture == capture || previous.process == process {
			return nil, ErrDomainPolicyTCPConsumer
		}
	}
	if err := s.owned.MkdirAll("execution-resources", 0700); err != nil {
		return nil, executionJournalError(err)
	}
	relative, err := s.owned.MkdirTemp("execution-resources", "dc-")
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
		if err = errors.Join(syncDataplaneJournalDirectory(opened), opened.Close()); err != nil {
			return nil, executionJournalError(err)
		}
	}
	if s.domainTCPCaptures == nil {
		s.domainTCPCaptures = map[string]*domainTCPCaptureExecutionResource{}
	}
	id := filepath.Base(relative)
	s.domainTCPCaptures[id] = r
	definition := r.definition.Clone()
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: id, Kind: "domain-tcp-capture", State: "prepared", Phase: "planned", Generation: plan.Generation, EffectsDigest: digest, DomainTCPCapture: &definition})
	if err := s.persist(); err != nil {
		return r, err
	}
	if !baseline.inspector.capture.CompareAndSwap(nil, r) {
		return r, ErrDomainPolicyTCPConsumer
	}
	return r, nil
}
