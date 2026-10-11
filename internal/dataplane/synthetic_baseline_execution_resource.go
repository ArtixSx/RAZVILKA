package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Issued only by the original finite binding and registered before COMMON
// effects. Saved definitions, receipt status and kernel images cannot issue it.
// Baseline preparation is distinct from capture and publication readiness.
type syntheticBaselineExecutionResource struct {
	self        *syntheticBaselineExecutionResource
	binding     *SyntheticDNSExecutionBinding
	mapping     *dnscontrol.SyntheticDNSMapping
	backend     *BackendInventory
	capture     *DomainPolicyTCPCapture
	inspector   *syntheticBaselineKernelInspector
	definition  *ExecutionSyntheticBaselineDefinition
	effects     PolicyEffectPlan
	digest      string
	tools       *SyntheticDNSCommandTools
	toolsFrozen SyntheticDNSCommandTools
	control     *operationgate.ControlEpochReview
	retirement  *dnscontrol.SyntheticDNSRetirementReview
	root        string
	relative    string
	anchor      os.FileInfo
	mu          sync.Mutex
	prepared    bool
	failed      error
}

func (*syntheticBaselineExecutionResource) String() string {
	return "[original COMMON synthetic baseline resource]"
}
func (*syntheticBaselineExecutionResource) GoString() string {
	return "[original COMMON synthetic baseline resource]"
}

// capture is the actual pointer emitted by RunDomainPolicyTCP/WithCapture,
// before mapping preparation. A prepared-mapping observation is not input.
func (b *SyntheticDNSExecutionBinding) issueBaseline(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, backend *BackendInventory, capture *DomainPolicyTCPCapture) (*syntheticBaselineExecutionResource, error) {
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	definition, err := b.baselineResourceDefinition(ctx, mapping)
	if err != nil {
		return nil, err
	}
	if capture == nil || !capture.matchesObservation(definition.Mapping) {
		return nil, ErrSyntheticBaselineTransition
	}
	if err := capture.Current(ctx); err != nil {
		return nil, err
	}
	endpoint, err := capture.Address()
	if err != nil || endpoint.String() != b.transport.CaptureEndpoint {
		return nil, errors.Join(ErrSyntheticBaselineTransition, err)
	}
	tools, err := b.scope.syntheticBaselineCommandTools(ctx, b)
	if err != nil || !tools.valid() || backend == nil || tools.Provider != b.scope.networkIdentity.provider || tools.Identity != b.scope.networkIdentity.value || backend.reader.Provider != tools.Provider || backend.review != tools.ReviewSHA256 || backend.reader.IPTables != tools.IPTables {
		return nil, errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if err := tools.Runner.CheckSyntheticDNS(ctx, tools.Identity); err != nil {
		return nil, err
	}
	if existing, err := b.scope.lookupSyntheticBaseline(ctx, b, mapping, backend, capture); existing != nil || err != nil {
		return existing, err
	}
	inspector, err := b.baselineInspector(ctx, mapping, backend)
	if err != nil {
		return nil, err
	}
	digest, err := PolicyEffectPlanDigest(inspector.plan)
	if err != nil {
		return nil, err
	}
	// The session supplies the original control review. No sequence number or
	// reconstructed DNS authority can replace that object.
	control, err := b.baselineControl()
	if err != nil {
		return nil, err
	}
	if err := control.Current(ctx); err != nil {
		return nil, err
	}
	session, err := b.originalSyntheticSession(control)
	if err != nil {
		return nil, err
	}
	// Bind this reservation to the SAME source, not another resolver with an
	// equal definition/generation. Retain its pre-issued retirement view before
	// any effects; this view grants no expiry, removal or publication authority.
	retirement, err := mapping.ReviewRetirement(ctx, session.synthetic.source, b.dns, b.transport.DNS, control, b.root, b.transport.Definition)
	if err != nil {
		return nil, err
	}
	r := &syntheticBaselineExecutionResource{binding: b, mapping: mapping, backend: backend, capture: capture, inspector: inspector, definition: definition, effects: inspector.plan, digest: digest, tools: tools, control: control}
	r.self = r
	r.retirement = retirement
	r.toolsFrozen = *tools
	// This existing journal write must succeed before a receipt is opened or
	// any runner is reachable. Failed persistence retains the unknown fence.
	if err := b.scope.reserveSyntheticBaseline(ctx, r); err != nil {
		// A concurrent issuer may have registered the SAME original mapping
		// under this scope lock. Reuse only that exact source/reader/capture
		// owner; a persistence failure keeps lookup fenced and cannot retry Add.
		if existing, lookupErr := b.scope.lookupSyntheticBaseline(ctx, b, mapping, backend, capture); lookupErr == nil && existing != nil {
			return existing, existing.current(ctx)
		}
		return nil, err
	}
	return r, r.current(ctx)
}

// Local immutable comparisons only, also safe under the tool's source locks.
func (r *syntheticBaselineExecutionResource) local(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil || r.binding == nil || r.binding.self != r.binding || r.binding.scope == nil || r.binding.scope.networkIdentity == nil || r.mapping == nil || r.retirement == nil || r.backend == nil || r.capture == nil || r.inspector == nil || r.inspector.self != r.inspector || r.inspector.mapping != r.mapping || r.inspector.backend != r.backend || r.inspector.identity != r.binding.scope.networkIdentity || r.control == nil || !r.tools.valid() || r.relative == "" || r.anchor == nil || r.root != filepath.Join(r.binding.scope.root, r.relative) {
		return ErrSyntheticBaselineTransition
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrSyntheticBaselineTransition
	}
	if !reflect.DeepEqual(*r.tools, r.toolsFrozen) || r.tools.Identity != r.binding.scope.networkIdentity.value || r.tools.Provider != r.binding.scope.networkIdentity.provider || r.backend.reader.Provider != r.tools.Provider || r.backend.review != r.tools.ReviewSHA256 || r.backend.reader.IPTables != r.tools.IPTables || !reflect.DeepEqual(r.inspector.plan, r.effects) {
		return ErrSyntheticBaselineTransition
	}
	compiled, err := syntheticBaselineDefinitionEffects(r.definition)
	if err != nil || !reflect.DeepEqual(compiled, r.effects) {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	digest, err := PolicyEffectPlanDigest(r.effects)
	if err != nil || digest != r.digest {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	return nil
}

func (r *syntheticBaselineExecutionResource) current(ctx context.Context) error {
	if err := r.local(ctx); err != nil {
		return err
	}
	if err := r.binding.Current(ctx); err != nil {
		return err
	}
	if err := r.binding.scope.currentSyntheticBaseline(ctx, r, true); err != nil {
		return err
	}
	if err := r.mapping.Current(ctx); err != nil {
		return err
	}
	if err := r.capture.Current(ctx); err != nil {
		return err
	}
	if err := r.tools.Runner.CheckSyntheticDNS(ctx, r.tools.Identity); err != nil {
		return err
	}
	if err := r.control.Current(ctx); err != nil {
		return err
	}
	if err := r.capture.Current(ctx); err != nil {
		return err
	}
	if err := r.mapping.Current(ctx); err != nil {
		return err
	}
	if err := r.binding.Current(ctx); err != nil {
		return err
	}
	return r.local(ctx)
}

// An attempt is one-shot. Unknown Start/Wait/ACK/readback never retries Add or
// deletes a possibly issued alias. COMMON's original receipt remains fenced.
func (r *syntheticBaselineExecutionResource) prepareBaseline(ctx context.Context) error {
	if r == nil || r.self != r {
		return ErrSyntheticBaselineTransition
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	if r.prepared {
		return r.currentBaseline(ctx)
	}
	if err := r.current(ctx); err != nil {
		return err
	}
	runtime := PolicyEffectRuntime{
		Runner: &syntheticBaselineEffectRunner{resource: r},
		Tools:  PolicyEffectTools{IPTables: r.tools.IPTables},
		Preflight: func(c context.Context) error {
			if err := r.current(c); err != nil {
				return err
			}
			view, err := r.inspector.read(c)
			if err != nil {
				return err
			}
			for i := range r.effects.Effects {
				count, err := syntheticBaselineExactPresence(view.Rows, r.effects, i)
				if err != nil || count != 0 {
					return errors.Join(ErrSyntheticBaselineTransition, err)
				}
			}
			return syntheticBaselinePreDNATEquivalent(view.Rows, r.effects)
		},
		ExactPresence: r.inspector.ExactPresence,
		BeforeDelete:  func(context.Context, int) error { return dnscontrol.ErrSyntheticDNSTransitionPending },
		Guard:         func(c context.Context, _ int) error { return r.current(c) },
	}
	if err := ApplyPolicyEffectsWithReceipt(ctx, runtime, r.effects, r.root); err != nil {
		r.failed = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.failed
	}
	if err := r.currentBaseline(ctx); err != nil {
		r.failed = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.failed
	}
	if err := r.binding.scope.recordSyntheticBaselinePhase(ctx, r, "baseline-prepared"); err != nil {
		r.failed = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.failed
	}
	r.prepared = true
	return nil
}

// Complete ACK and the SAME complete original image are independently needed.
// This does not establish native RPDB/post-DNAT firmware equivalence, nor DNS
// publication. The eventual concrete publication receiver must prove those.
func (r *syntheticBaselineExecutionResource) currentBaseline(ctx context.Context) error {
	if err := r.current(ctx); err != nil {
		return err
	}
	// Retain the actual anchored document and permanent lock descriptors
	// across readback. Status alone cannot authenticate a replaced receipt.
	receipt, err := observeNetworkPolicyEffects(ctx, r.effects, r.root, policyAdditionOptions{})
	defer receipt.close()
	status := receipt.status
	if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted || status.Added != len(r.effects.Effects) || status.Pending != 0 || status.Cleaned != 0 {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if err := r.inspector.CheckPrepared(ctx); err != nil {
		return err
	}
	if err := r.current(ctx); err != nil {
		return err
	}
	return receipt.current()
}

func (r *syntheticBaselineExecutionResource) prepareCapture(ctx context.Context) (*DomainPolicyTCPCaptureMapping, error) {
	if err := r.prepareBaseline(ctx); err != nil {
		return nil, err
	}
	prepared, err := r.capture.PrepareSyntheticMapping(ctx, r.mapping)
	if err != nil {
		return nil, err
	}
	if err := r.currentBaseline(ctx); err != nil {
		return nil, err
	}
	if err := prepared.Current(ctx); err != nil {
		return nil, err
	}
	if err := r.binding.scope.recordSyntheticBaselinePhase(ctx, r, "capture-ready"); err != nil {
		return nil, err
	}
	return prepared, nil
}

type syntheticBaselineEffectRunner struct {
	resource *syntheticBaselineExecutionResource
}

func (r *syntheticBaselineEffectRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r == nil || r.resource == nil || r.resource.self != r.resource {
		return nil, ErrSyntheticBaselineTransition
	}
	if err := r.resource.current(ctx); err != nil {
		return nil, err
	}
	return r.resource.tools.Runner.RunSyntheticDNS(ctx, r, name, args...)
}

func (*syntheticBaselineEffectRunner) syntheticDNSCommandAdmission() {}

// Only local owner and actual COMMON invocation comparisons at Cmd.Start.
// Tool/provider/physical callbacks already ran before the held-fd runner; do
// not reenter them while that producer holds its source locks.
func (runner *syntheticBaselineEffectRunner) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if runner == nil || runner.resource == nil || begin == nil {
		return ErrSyntheticBaselineTransition
	}
	r := runner.resource
	if err := r.local(ctx); err != nil {
		return err
	}
	if review != r.tools.ReviewSHA256 || name != r.tools.IPTables {
		return ErrSyntheticBaselineTransition
	}
	invocation, err := observePolicyEffectCommandInvocation(ctx, r.effects, r.root, name, args)
	if err != nil || invocation == nil || invocation.cleanup {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if !reflect.DeepEqual(args, r.effects.Effects[invocation.index].Add) {
		return ErrSyntheticBaselineTransition
	}
	// Join the SAME scope's Start barrier. Close cannot release its original
	// owner between the last local check and actual Cmd.Start acknowledgement.
	r.binding.scope.startMu.RLock()
	defer r.binding.scope.startMu.RUnlock()
	return invocation.withStart(ctx, func() error {
		if err := r.binding.scope.currentSyntheticBaselineStart(ctx, r); err != nil {
			return err
		}
		err := r.control.WithStart(ctx, begin)
		return errors.Join(err, r.binding.scope.currentSyntheticBaselineStart(ctx, r))
	})
}
