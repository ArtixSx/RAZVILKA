package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
)

// These guards are installed by the concrete App assembly, which retains its
// original Store and physical/source owners through joined retirement.
type XraySelectedTCPActiveGuard func(context.Context, Plan) error

type xraySelectedTCPExecution struct {
	self                         *xraySelectedTCPExecution
	mu                           sync.Mutex
	material                     *XrayOperationMaterial
	plan                         Plan
	panel                        context.Context
	inventory                    *BackendInventory
	gate                         *NetworkPolicyAdapter
	checks                       *NetworkPolicyChecks
	committedGuard, cleanupGuard XraySelectedTCPActiveGuard
	resource                     *XraySelectedTCPExecutionResource
	node                         *xraySelectedTCPCommittedNode
	bound, started, retired      bool
	replacement                  *xraySelectedTCPReplacement
}

type xraySelectedTCPExecutionKey struct{}

// The association blocks legacy dispatch while an original selected-TCP
// assembly owns this exact registered adapter. It creates no runtime grant.
var xraySelectedTCPExecutions = struct {
	sync.Mutex
	live map[*ProxyTunnelAdapter]*xraySelectedTCPExecution
}{live: make(map[*ProxyTunnelAdapter]*xraySelectedTCPExecution)}

func (m *XrayOperationMaterial) BindExecution(ctx, panel context.Context, expected Plan, inventory *BackendInventory, gate *NetworkPolicyAdapter, checks *NetworkPolicyChecks, committed, cleanupGuard XraySelectedTCPActiveGuard) (context.Context, error) {
	return m.bindExecution(ctx, panel, expected, inventory, gate, checks, committed, cleanupGuard, nil)
}

func (m *XrayOperationMaterial) bindExecution(ctx, panel context.Context, expected Plan, inventory *BackendInventory, gate *NetworkPolicyAdapter, checks *NetworkPolicyChecks, committed, cleanupGuard XraySelectedTCPActiveGuard, pair *xraySelectedTCPReplacement) (context.Context, error) {
	if m == nil || m.self != m || xraySelectedTCPFinite(ctx) != nil || panel == nil || panel.Err() != nil || inventory == nil || gate == nil || checks == nil || committed == nil || cleanupGuard == nil ||
		ctx.Value(xraySelectedTCPExecutionKey{}) != nil || expected.LAN == nil || expected.LAN.Mode != LANPolicyXraySelectedTCPMode || m.material == nil || !reflect.DeepEqual(expected.LAN, m.material.spec.LAN) || !xraySelectedTCPScopeRouteMatches(expected, m.material) ||
		gate.identity == nil || !gate.identity.acceptsMode(LANPolicyXraySelectedTCPMode) || inventory.reader.Provider != gate.identity.provider || checks.gate != gate || checks.manager != m.manager || checks.inventory == nil ||
		inventory.review != checks.inventory.review || inventory.reader.IPTables != checks.inventory.reader.IPTables || inventory.reader.IP6Tables != checks.inventory.reader.IP6Tables || !sameNetworkPolicyDependency(inventory.reader.Runner, checks.inventory.reader.Runner) ||
		gate.Binding == nil || gate.Binding.Runtime == nil || gate.Binding.Runtime.Runner == nil || gate.Binding.Runtime.ScopeCheck == nil {
		return nil, ErrXrayOperationOwner
	}
	m.barrier.Lock()
	defer m.barrier.Unlock()
	if err := m.current(ctx, false); err != nil {
		return nil, err
	}
	m.manager.registryMu.RLock()
	registered := m.manager.Adapters[NetworkPolicyAdapterID] == gate && m.manager.Adapters["xray"] == m.adapter
	m.manager.registryMu.RUnlock()
	if !registered || gate.StateRoot != filepath.Join(m.managerRoot, NetworkPolicyAdapterID) {
		return nil, ErrXrayOperationOwner
	}
	node, err := captureXraySelectedTCPCommittedNode(ctx, m)
	if err != nil {
		return nil, err
	}
	e := &xraySelectedTCPExecution{material: m, plan: cloneExecutionResourcePlan(expected), panel: panel, inventory: inventory, gate: gate, checks: checks, committedGuard: committed, cleanupGuard: cleanupGuard, bound: true}
	e.node = node
	e.self = e
	e.replacement = pair
	xraySelectedTCPExecutions.Lock()
	defer xraySelectedTCPExecutions.Unlock()
	prior := xraySelectedTCPExecutions.live[m.adapter]
	if pair == nil && prior != nil || pair != nil && (pair.self != pair || pair.candidate != nil || pair.prior.execution != prior || pair.manager != m.manager) || prior == nil && len(xraySelectedTCPExecutions.live) >= maxExecutionResources {
		return nil, ErrXrayOperationOwner
	}
	if pair != nil {
		pair.candidate = e
	}
	m.execution = e
	xraySelectedTCPExecutions.live[m.adapter] = e
	return context.WithValue(context.WithValue(ctx, xrayOperationMaterialKey{}, m), xraySelectedTCPExecutionKey{}, e), nil
}

func xraySelectedTCPExecutionFor(ctx context.Context, original *ProxyTunnelAdapter, plan Plan, root string) (*xraySelectedTCPExecution, bool, error) {
	xraySelectedTCPExecutions.Lock()
	associated := xraySelectedTCPExecutions.live[original]
	xraySelectedTCPExecutions.Unlock()
	var value any
	if ctx != nil {
		value = ctx.Value(xraySelectedTCPExecutionKey{})
	}
	if value == nil {
		if associated != nil {
			return nil, true, ErrXrayOperationOwner
		}
		return nil, false, nil
	}
	e, ok := value.(*xraySelectedTCPExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.self != e.material || original != e.material.adapter || !xraySelectedTCPAssociated(associated, e) ||
		!xraySelectedTCPSamePlan(e.plan, plan) || root != filepath.Join(e.material.managerRoot, "transactions", e.plan.PlanID, "xray") || xraySelectedTCPFinite(ctx) != nil {
		return nil, true, ErrXrayOperationOwner
	}
	return e, true, nil
}

func xraySelectedTCPSamePlan(expected, actual Plan) bool {
	actual = cloneExecutionResourcePlan(actual)
	actual.State, actual.ObservedEvidence, actual.Note, actual.EvidenceNote = expected.State, expected.ObservedEvidence, expected.Note, expected.EvidenceNote
	if len(actual.RouteEvidence) != len(expected.RouteEvidence) {
		return false
	}
	for i := range actual.RouteEvidence {
		actual.RouteEvidence[i].Observed, actual.RouteEvidence[i].Source, actual.RouteEvidence[i].Note = expected.RouteEvidence[i].Observed, expected.RouteEvidence[i].Source, expected.RouteEvidence[i].Note
	}
	return reflect.DeepEqual(expected, actual)
}

func (e *xraySelectedTCPExecution) owners(ctx context.Context) error {
	if e == nil || e.self != e || !e.bound || e.material == nil || e.material.self != e.material || e.panel == nil || e.panel.Err() != nil || e.inventory == nil || e.gate == nil || e.checks == nil ||
		e.checks.gate != e.gate || e.checks.manager != e.material.manager || e.checks.identity != e.gate.identity || e.checks.closed.Load() || e.gate.Binding != e.checks.binding ||
		e.gate.Binding == nil || e.gate.Binding.Runtime != e.checks.runtime || e.inventory.reader.Provider != e.gate.identity.provider || xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayOperationOwner
	}
	xraySelectedTCPExecutions.Lock()
	original := xraySelectedTCPAssociated(xraySelectedTCPExecutions.live[e.material.adapter], e)
	xraySelectedTCPExecutions.Unlock()
	if !original || e.material.registration.Current(ctx) != nil {
		return ErrXrayOperationOwner
	}
	return e.gate.identity.check(ctx)
}

func (e *xraySelectedTCPExecution) forward(ctx context.Context) error {
	if err := e.owners(ctx); err != nil {
		return err
	}
	e.material.barrier.RLock()
	defer e.material.barrier.RUnlock()
	return e.material.current(ctx, false)
}

func (e *xraySelectedTCPExecution) snapshot(ctx context.Context) error {
	if err := e.forward(ctx); err != nil {
		return err
	}
	if e.replacement != nil {
		return e.replacement.priorStructural(ctx)
	}
	mode, err := e.material.adapter.currentXrayRuntimeMode(ctx)
	if err != nil || mode != proxyXrayModeCold {
		return errors.Join(ErrXrayOperationOwner, err)
	}
	// Clean-install selected-TCP does not import another native/legacy owner.
	snapshot, err := e.inventory.Read(ctx, e.gate.identity.value)
	if err != nil || snapshot.RequireComplete() != nil {
		return errors.Join(ErrXrayOperationOwner, err)
	}
	if _, err := inspectXrayStockOutputQueues(snapshot); err != nil {
		return err
	}
	return e.forward(ctx)
}

func (e *xraySelectedTCPExecution) prepare(ctx context.Context) error {
	if err := e.forward(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.resource != nil || e.started || e.retired {
		return ErrXrayOperationOwner
	}
	r, err := AcquireXraySelectedTCPExecutionResource(ctx, e.material, e.material.material.spec.Clone())
	if r != nil {
		e.resource = r
	} // A lost publication ACK retains original compensation.
	return err
}

func (e *xraySelectedTCPExecution) validate(ctx context.Context) error {
	if err := e.forward(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	r := e.resource
	e.mu.Unlock()
	if r == nil {
		return ErrXrayOperationOwner
	}
	r.observationMu.RLock()
	defer r.observationMu.RUnlock()
	return errors.Join(r.configCurrent(ctx), r.executable.current(ctx))
}

// Candidate evidence is the genuine exact service/WAN admission check. The
// router's OUTPUT probe cannot pretend to traverse client PREROUTING.
func (e *xraySelectedTCPExecution) canary(ctx context.Context, routes RoutePlan) error {
	if !reflect.DeepEqual(routes, e.plan.RoutePlanFor("xray")) {
		return ErrXrayOperationOwner
	}
	return e.validate(ctx)
}
