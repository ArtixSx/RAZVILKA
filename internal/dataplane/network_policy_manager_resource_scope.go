package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// A scope exists only inside the Manager's existing operation. Closing it
// revokes every retained callback and cancels borrowers; unfinished resources
// keep the existing journal fenced. No persisted outcome creates an issuer.
type executionResourceScope struct {
	mu                      sync.Mutex
	closeMu                 sync.Mutex
	startMu                 sync.RWMutex
	manager                 *Manager
	managerRoot             string
	adapterOwner            Adapter
	plan                    Plan
	adapter                 string
	registryGeneration      uint64
	execution               *Execution
	root                    string
	owned                   *ownedfs.Root
	anchor                  os.FileInfo
	ctx                     context.Context
	cancel                  context.CancelFunc
	guard                   func(context.Context) error
	open                    bool
	observationOpen         atomic.Bool // Read-only observers never reenter mu/guards.
	failure                 error
	closedErr               error
	issued                  map[string]*executionTransitResource
	nfqws                   map[string]*NFQWSExecutionResource
	networkIdentity         *networkPolicyIdentity
	nfqwsTransfer           *nfqwsExecutionTransferBarrier
	retained                bool
	retainedOwner           *retainedNFQWSExecution
	syntheticPhases         map[*syntheticBaselineExecutionPhase]struct{}
	syntheticClosing        bool
	pending                 bool // Original unknown Apply: cleanup only, never ACTIVE.
	syntheticBaselineSource *syntheticBaselineCoordinator
	syntheticBaselines      map[string]*syntheticBaselineExecutionResource
	xraySelectedTCP         map[string]*XraySelectedTCPExecutionResource
	retainedXrayOwner       *retainedXrayExecution
	wgOwner                 *wgOperationOwner
	wgRecords               *wgExecutionRecords
	retainedWGOwner         *retainedWGExecution
	wgCleanupJoined         bool // Actual complete rollback or native retirement only.
}

type executionTransitResource struct {
	spec     NodeTransitSpec
	root     string
	relative string
	anchor   os.FileInfo
	digest   string
	effects  string
	readback networkPolicyTransitReadback
	admitted bool
}

func (m *Manager) newExecutionResourceScope(ctx context.Context, plan Plan, adapter string, execution *Execution, root string) (*executionResourceScope, error) {
	if ctx == nil || execution == nil || !validPlanID(plan.PlanID) || !validPlanDigest(plan.Digest) ||
		execution.Digest != plan.Digest || !slices.Contains(plan.Adapters, adapter) {
		return nil, ErrNodeTransitUnavailable
	}
	parent := execution.PlanID
	if execution.ResourcePlanID != "" {
		parent = execution.ResourcePlanID
	}
	if parent != plan.PlanID || filepath.Join(m.StateRoot, "transactions", execution.PlanID) != root {
		return nil, ErrNodeTransitUnavailable
	}
	owned, anchor, err := openNetworkPolicyObservationRoot(root)
	if err != nil {
		return nil, executionJournalError(err)
	}
	child, cancel := context.WithCancel(ctx)
	plan = cloneExecutionResourcePlan(plan)
	guard, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	m.registryMu.RLock()
	registryGeneration := m.registryGeneration
	adapterOwner := m.Adapters[adapter]
	m.registryMu.RUnlock()
	identity := m.executionNetworkIdentity()
	if identity != nil {
		if err := identity.check(ctx); err != nil {
			cancel()
			_ = owned.Close()
			return nil, err
		}
	}
	s := &executionResourceScope{manager: m, managerRoot: m.StateRoot, adapterOwner: adapterOwner, plan: plan, adapter: adapter, execution: execution,
		root: root, owned: owned, anchor: anchor, ctx: child, cancel: cancel, guard: guard,
		open: true, issued: map[string]*executionTransitResource{}, nfqws: map[string]*NFQWSExecutionResource{}, xraySelectedTCP: map[string]*XraySelectedTCPExecutionResource{}, registryGeneration: registryGeneration, networkIdentity: identity}
	s.observationOpen.Store(true)
	if a, ok := adapterOwner.(*WARPWireGuardAdapter); ok && a != nil && a.wgCommandTools != nil {
		s.wgOwner, err = newWGOperationOwner(ctx, s)
		if err == nil {
			s.wgRecords, err = newWGExecutionRecords(s)
		}
		if err == nil {
			err = m.writeExecutionOwned(root, *execution, s)
		}
		if err != nil {
			cancel()
			if s.wgRecords != nil {
				_ = s.wgRecords.close()
			}
			_ = owned.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *executionResourceScope) context() context.Context {
	return s.contextWith(s.ctx)
}

// Preserve the actual phase's cancellation and values, including a finite
// original-owner cleanup context. The issuer still checks its own lifetime.
func (s *executionResourceScope) contextWith(ctx context.Context) context.Context {
	if s.wgOwner != nil {
		ctx = context.WithValue(ctx, wgOperationMaterialKey{}, s.wgOwner.material)
		ctx = context.WithValue(ctx, wgOperationOwnerKey{}, s.wgOwner)
	}
	ctx = context.WithValue(ctx, nfqws2ActiveActivationRegistrarKey{}, s)
	ctx = context.WithValue(ctx, nodeTransitRegistrarKey{}, nodeTransitRegistrar(s.issueTransit))
	ctx = context.WithValue(ctx, nfqwsExecutionRegistrarKey{}, nfqwsExecutionRegistrar(s.issueNFQWS))
	ctx = context.WithValue(ctx, xraySelectedTCPRegistrarKey{}, xraySelectedTCPRegistrar(s.issueXraySelectedTCP))
	return withSyntheticExecutionRegistrar(ctx, s)
}

// Called with s.mu held. Actual owner readback runs outside this mutex and
// rechecks the matching record after returning, so read-only guards can reenter.
func (s *executionResourceScope) checkCurrent(ctx context.Context, resource *executionTransitResource, forward bool) error {
	return s.checkOriginalOwner(ctx, resource, forward, false)
}

// A failed journal write cannot erase the original physical owner. Only the
// separately pre-issued NFQ cleanup capability may ignore that sticky error;
// the final journal still remains fenced. Forward use always checks failure.
func (s *executionResourceScope) checkOriginalOwner(ctx context.Context, resource *executionTransitResource, forward, originalNFQCleanup bool) error {
	if !s.open || s.failure != nil && !originalNFQCleanup || s.guard == nil || ctx == nil || s.manager.StateRoot != s.managerRoot || s.manager.executionNetworkIdentity() != s.networkIdentity {
		return errors.Join(ErrNodeTransitUnavailable, s.failure)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if forward {
		if s.pending {
			return ErrNFQWSScopedOwner
		}
		if s.retained {
			if s.retainedWGOwner != nil {
				if err := s.checkRetainedWGOperation(ctx, true); err != nil {
					return err
				}
			} else if s.retainedXrayOwner != nil {
				if err := s.checkRetainedXrayOperation(ctx, true); err != nil {
					return err
				}
			} else {
				op, err := s.retainedOperation(ctx)
				if err != nil || !op.forward {
					return ErrNFQWSScopedOwner
				}
			}
		} else if err := s.ctx.Err(); err != nil {
			return err // Cancellation detachment grants cleanup only.
		}
	}
	s.manager.registryMu.RLock()
	currentRegistry := s.manager.registryGeneration
	adapterOwner := s.manager.Adapters[s.adapter]
	s.manager.registryMu.RUnlock()
	if currentRegistry != s.registryGeneration || !sameNetworkPolicyDependency(adapterOwner, s.adapterOwner) {
		return ErrNodeTransitUnavailable
	}
	current, err := os.Lstat(s.root)
	if err != nil || !os.SameFile(s.anchor, current) {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	if resource != nil {
		current, err = s.owned.Stat(resource.relative)
		if err != nil || !os.SameFile(resource.anchor, current) {
			return errors.Join(ErrNodeTransitUnavailable, err)
		}
	}
	return nil
}

func (s *executionResourceScope) check(ctx context.Context, resource *executionTransitResource, forward bool) error {
	if err := s.checkCurrent(ctx, resource, forward); err != nil {
		return err
	}
	if s.networkIdentity != nil {
		if err := s.networkIdentity.check(ctx); err != nil {
			return err
		}
	}
	if forward {
		if err := verifyNetworkProfile(ctx, s.plan.NetworkProfileID, s.manager.FreshProfile); err != nil {
			return err
		}
	}
	// Cleanup is bounded by this still-held operation, exact issued identity
	// and the same live context-aware authority. WAN freshness grants forward
	// effects only; it cannot convert a retained old rule into an unowned rule.
	if err := s.guard(ctx); err != nil {
		return err
	}
	if s.networkIdentity != nil {
		if err := s.networkIdentity.check(ctx); err != nil {
			return err
		}
	}
	// External readers may cancel the original request, change the registry or
	// replace a retained root while returning a nominally successful result.
	return s.checkCurrent(ctx, resource, forward)
}

func (s *executionResourceScope) issueTransit(ctx context.Context, spec NodeTransitSpec) (nodeTransitRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, nil, true); err != nil {
		return nodeTransitRegistration{}, err
	}
	readback, ok := ctx.Value(networkPolicyTransitReadbackKey{}).(networkPolicyTransitReadback)
	if !ok || readback == nil || spec.Engine != s.adapter || spec.PlanID != s.plan.PlanID ||
		spec.PlanDigest != s.plan.Digest || spec.NetworkProfile != s.plan.NetworkProfileID || s.resourceCount() >= maxExecutionResources {
		return nodeTransitRegistration{}, ErrNodeTransitUnavailable
	}
	compiled, err := CompileNodeTransit(spec)
	if err != nil {
		return nodeTransitRegistration{}, err
	}
	effects, err := PolicyEffectPlanDigest(compiled)
	if err != nil {
		return nodeTransitRegistration{}, err
	}
	if err := s.owned.MkdirAll("execution-resources", 0700); err != nil {
		return nodeTransitRegistration{}, executionJournalError(err)
	}
	relative, err := s.owned.MkdirTemp("execution-resources", "nt-")
	if err != nil {
		return nodeTransitRegistration{}, executionJournalError(err)
	}
	anchor, err := s.owned.Stat(relative)
	if err != nil {
		return nodeTransitRegistration{}, executionJournalError(err)
	}
	resource := &executionTransitResource{spec: spec, root: filepath.Join(s.root, relative), relative: relative,
		anchor: anchor, digest: compiled.Generation, effects: effects, readback: readback}
	for _, path := range []string{resource.root, filepath.Dir(resource.root), s.root} {
		opened, err := openJournalDirectory(path)
		if err != nil {
			return nodeTransitRegistration{}, executionJournalError(err)
		}
		err = syncDataplaneJournalDirectory(opened)
		_ = opened.Close()
		if err != nil {
			return nodeTransitRegistration{}, executionJournalError(err)
		}
	}
	s.issued[filepath.Base(relative)] = resource
	return nodeTransitRegistration{root: resource.root,
		register: func(c context.Context, got NodeTransitSpec, root, digest string) error {
			return s.registerTransit(c, resource, got, root, digest)
		},
		settle: func(c context.Context, got NodeTransitSpec, root, digest string) error {
			return s.settleTransit(c, resource, got, root, digest, networkPolicyTransitRemoved)
		},
		settleUnused: func(c context.Context, got NodeTransitSpec, root, digest string) error {
			return s.settleTransit(c, resource, got, root, digest, networkPolicyTransitUnused)
		},
		cleanupGuard: func(c context.Context) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.check(c, resource, false)
		}}, nil
}

func (s *executionResourceScope) resourceCount() int {
	ids := make(map[string]bool, len(s.issued)+len(s.execution.Resources))
	for id := range s.issued {
		ids[id] = true
	}
	for id := range s.nfqws {
		ids[id] = true
	}
	for id := range s.syntheticBaselines {
		ids[id] = true
	}
	for id := range s.xraySelectedTCP {
		ids[id] = true
	}
	for _, resource := range s.execution.Resources {
		ids[resource.ID] = true
	}
	return len(ids)
}

func (s *executionResourceScope) matchingTransit(resource *executionTransitResource, spec NodeTransitSpec, root, digest string) (int, error) {
	id := filepath.Base(resource.relative)
	if s.issued[id] != resource || spec != resource.spec || root != resource.root || digest != resource.digest {
		return -1, ErrNodeTransitUnavailable
	}
	for i, recorded := range s.execution.Resources {
		if recorded.ID == id {
			if recorded.Kind != "node-transit" || recorded.NodeTransit == nil || *recorded.NodeTransit != spec ||
				recorded.Generation != digest || recorded.EffectsDigest != resource.effects || recorded.State != "prepared" {
				return -1, ErrNodeTransitUnavailable
			}
			return i, nil
		}
	}
	return -1, nil
}

func (s *executionResourceScope) persist() error {
	if s.retainedOwner != nil {
		if err := s.retainedOwner.recordsCurrent(); err != nil {
			s.failure = errors.Join(s.failure, err)
			return err
		}
	}
	err := s.manager.writeExecutionOwned(s.root, *s.execution, s)
	if err == nil && s.retainedOwner != nil {
		err = s.retainedOwner.captureRecords()
	}
	if err == nil && s.retainedXrayOwner != nil {
		err = s.retainedXrayOwner.captureRecords()
	}
	if err != nil {
		s.failure = errors.Join(s.failure, err)
	}
	return err
}

func (s *executionResourceScope) registerTransit(ctx context.Context, resource *executionTransitResource, spec NodeTransitSpec, root, digest string) error {
	if ctx == nil {
		return ErrNodeTransitUnavailable
	}
	already, err := func() (bool, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		index, err := s.matchingTransit(resource, spec, root, digest)
		if err != nil {
			return false, err
		}
		removing, _ := ctx.Value(nodeTransitRemovalKey{}).(bool)
		if err := s.check(ctx, resource, index < 0 || !removing); err != nil {
			return false, err
		}
		if index >= 0 {
			if !resource.admitted {
				return false, ErrNodeTransitUnavailable
			}
			return true, nil // Exact admitted live record also registers cleanup.
		}
		if len(s.execution.Resources) >= maxExecutionResources {
			return false, ErrNodeTransitUnavailable
		}
		copy := spec
		s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: filepath.Base(resource.relative), Kind: "node-transit", State: "prepared",
			Generation: digest, EffectsDigest: resource.effects, NodeTransit: &copy})
		// Retain intent before any common receipt entry or effect invocation.
		// Refused readback can only settle through live unused evidence.
		return false, s.persist()
	}()
	if err != nil || already {
		return err
	}
	if err := resource.readback(ctx, spec, root, digest, networkPolicyTransitPrepared); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if index, err := s.matchingTransit(resource, spec, root, digest); err != nil || index < 0 {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	if err := s.check(ctx, resource, true); err != nil {
		return err
	}
	resource.admitted = true
	return nil
}

func (s *executionResourceScope) settleTransit(ctx context.Context, resource *executionTransitResource, spec NodeTransitSpec, root, digest string, mode networkPolicyTransitReadbackMode) error {
	if err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.check(ctx, resource, false); err != nil {
			return err
		}
		index, err := s.matchingTransit(resource, spec, root, digest)
		if err != nil || index < 0 || mode != networkPolicyTransitRemoved && mode != networkPolicyTransitUnused {
			return errors.Join(ErrNodeTransitUnavailable, err)
		}
		return nil
	}(); err != nil {
		return err
	}
	// Check the matching prepared record BEFORE a one-shot unused proof can be
	// consumed. Both outcomes require actual private owner/receipt readback.
	if err := resource.readback(ctx, spec, root, digest, mode); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.matchingTransit(resource, spec, root, digest)
	if err != nil || index < 0 {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	if err := s.check(ctx, resource, false); err != nil {
		return err
	}
	s.execution.Resources[index].State = string(mode)
	return s.persist()
}

func (s *executionResourceScope) close() error {
	// Revoke every finite DNS carrier before joining any borrower. Its closing
	// Current can need startMu.RLock, so cancellation/join must precede the
	// closing writer barrier. Scope cancellation still waits for real Start ACK.
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	if s.wgOwner != nil && s.wgOwner.mutationAttempted.Load() && !s.wgCleanupJoined {
		s.mu.Unlock()
		return ErrWGOperationOwner
	}
	if !s.open {
		err := s.closedErr
		s.mu.Unlock()
		return err
	}
	s.syntheticClosing = true
	phases := make([]*syntheticBaselineExecutionPhase, 0, len(s.syntheticPhases))
	for phase := range s.syntheticPhases {
		phases = append(phases, phase)
	}
	s.mu.Unlock()
	for _, phase := range phases {
		phase.cancel()
	}
	var phaseErr error
	for _, phase := range phases {
		phaseErr = errors.Join(phaseErr, phase.Close())
	}
	// A live one-shot managed Start holds this barrier through actual child
	// Start ACK. Closing cannot release the operation or revoke its root early.
	s.startMu.Lock()
	defer s.startMu.Unlock()
	s.mu.Lock()
	if !s.open {
		s.mu.Unlock()
		return s.closedErr
	}
	s.open = false
	s.observationOpen.Store(false)
	s.cancel()
	changed := false
	for i := range s.execution.Resources {
		resource := &s.execution.Resources[i]
		if (s.nfqws[resource.ID] != nil || s.xraySelectedTCP[resource.ID] != nil) && (resource.State == "prepared" || resource.State == "active") || s.syntheticBaselines[resource.ID] != nil && resource.State == "prepared" {
			resource.State = "prepared"
			resource.Phase = "closed"
			changed = true
		}
	}
	if changed {
		_ = s.persist() // Failure is sticky; pending never becomes terminal.
	}
	// Closing one temporary phase cannot revoke another participant's retained
	// Apply owner. Structural validation still covers the complete execution;
	// only this issuer's own resources must already be terminal at its close.
	ownedExecution := *s.execution
	ownedExecution.Resources = nil
	for _, resource := range s.execution.Resources {
		if s.nfqws[resource.ID] != nil || s.issued[resource.ID] != nil || s.syntheticBaselines[resource.ID] != nil || s.xraySelectedTCP[resource.ID] != nil {
			ownedExecution.Resources = append(ownedExecution.Resources, resource)
		}
	}
	err := errors.Join(phaseErr, s.failure, validateExecutionResources(*s.execution, false), validateExecutionResources(ownedExecution, true))
	xrayResources := make([]*XraySelectedTCPExecutionResource, 0, len(s.xraySelectedTCP))
	for _, resource := range s.xraySelectedTCP {
		xrayResources = append(xrayResources, resource)
	}
	s.mu.Unlock()
	for _, resource := range xrayResources {
		err = errors.Join(err, resource.closeOriginalDescriptors())
	}
	if s.wgRecords != nil {
		err = errors.Join(err, s.wgRecords.close())
	}
	if s.wgOwner != nil {
		err = errors.Join(err, s.wgOwner.closeCommon())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closedErr = errors.Join(err, s.owned.Close())
	return s.closedErr
}

// WithExecutionResources runs a reviewed isolated check under the SAME
// operation gate and journal, without changing the original committed plan.
// It never adopts retained resources or supplies recovery deletion authority.
func (m *Manager) WithExecutionResources(ctx context.Context, expected Plan, adapter string, action func(context.Context) error) error {
	if m == nil || ctx == nil || action == nil {
		return ErrNodeTransitUnavailable
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	return m.withExecutionResourcesLocked(ctx, expected, adapter, action)
}

func (m *Manager) withExecutionResourcesLocked(ctx context.Context, expected Plan, adapter string, action func(context.Context) error) error {
	guard, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	if guard == nil || action == nil || !slices.Contains(expected.Adapters, adapter) || !validPlanID(expected.PlanID) ||
		!validPlanDigest(expected.Digest) || expected.SchemaVersion != SchemaVersion || expected.SafeMode || !expected.Ready || expected.Noop ||
		!filepath.IsAbs(m.StateRoot) || filepath.Clean(m.StateRoot) != m.StateRoot {
		return ErrNodeTransitUnavailable
	}
	if _, exists := m.adapter(adapter); !exists {
		return ErrNodeTransitUnavailable
	}
	if err := errors.Join(m.checkExecutionRecovery(), m.checkPlanNetwork(ctx, expected)); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	execution := Execution{PlanID: "dp-check-" + hex.EncodeToString(nonce[:]), ResourcePlanID: expected.PlanID, Digest: expected.Digest,
		State: "checking", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []ExecutionStep{{Adapter: adapter, Phase: "health", State: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}}}
	root := filepath.Join(m.StateRoot, "transactions", execution.PlanID)
	if err := m.prepareExecutionRoot(root); err != nil {
		return err
	}
	if err := m.writeExecution(root, execution); err != nil {
		return err
	}
	scope, err := m.newExecutionResourceScope(ctx, expected, adapter, &execution, root)
	if err != nil {
		return err
	}
	defer scope.close() // Revoke callbacks and anchored descriptors on panic too.
	actionErr := action(scope.context())
	err = errors.Join(actionErr, m.checkPlanNetwork(ctx, expected), scope.close())
	execution.Steps[0].State = "passed"
	if err != nil {
		execution.Steps[0].State = "failed"
		execution.Steps[0].Detail = err.Error()
		execution.Error = err.Error()
	}
	execution.Steps[0].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	execution.FinishedAt = execution.Steps[0].FinishedAt
	execution.State = "temporary-complete"
	if validateExecutionResources(execution, true) != nil {
		execution.State = "resource-failed"
	}
	return errors.Join(err, m.writeExecution(root, execution))
}
