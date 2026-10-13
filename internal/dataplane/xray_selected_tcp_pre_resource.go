package dataplane

import (
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
)

// Private original Manager observation only. It grants no active consumer,
// native command, COMMON receipt or deletion permission. The first actual
// issuer attempt irrevocably ends the never-materialized branch.
type xraySelectedTCPPreResource struct {
	self      *xraySelectedTCPPreResource
	owner     *xrayOperationOwner
	execution *xraySelectedTCPExecution
	attempted atomic.Bool
}

type xraySelectedTCPPreResourceKey struct{}

func (m *Manager) originalXrayPreResourceScope(ctx context.Context, plan Plan, execution *Execution, root string) (*executionResourceScope, *xraySelectedTCPPreResource, error) {
	e, ok := ctx.Value(xraySelectedTCPExecutionKey{}).(*xraySelectedTCPExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.manager != m || e.replacement != nil ||
		!xraySelectedTCPSamePlan(e.plan, plan) || e.owners(ctx) != nil {
		return nil, nil, ErrXrayOperationOwner
	}
	s, err := m.newExecutionResourceScope(ctx, plan, "xray", execution, root)
	if err != nil {
		return nil, nil, err
	}
	o, err := newXrayOperationOwner(ctx, s)
	if err != nil {
		return nil, nil, errors.Join(err, s.close())
	}
	p := &xraySelectedTCPPreResource{owner: o, execution: e}
	p.self = p
	e.mu.Lock()
	if e.preResource != nil || e.resource != nil || e.started || e.retired {
		e.mu.Unlock()
		return nil, nil, errors.Join(ErrXrayOperationOwner, s.close())
	}
	e.preResource = p
	e.mu.Unlock()
	return s, p, nil
}

func (p *xraySelectedTCPPreResource) context(ctx context.Context, cleanup bool) (context.Context, error) {
	if p == nil || p.self != p || p.owner == nil || p.execution == nil || p.execution.preResource != p ||
		ctx == nil || ctx.Value(xraySelectedTCPExecutionKey{}) != p.execution {
		return nil, ErrXrayOperationOwner
	}
	e := p.execution
	e.mu.Lock()
	r := e.resource
	e.mu.Unlock()
	o := p.owner
	if r != nil {
		if r.self != r || r.scope != o.scope || r.material != o.material || r.owner == nil {
			return nil, ErrXrayOperationOwner
		}
		o = r.owner // Original resource owns every later command and settlement.
	}
	var bound context.Context
	var err error
	if cleanup {
		bound, err = o.cleanupContext(ctx)
	} else {
		bound, err = o.context(ctx)
	}
	if err != nil {
		return nil, err
	}
	bound = context.WithValue(bound, xraySelectedTCPPreResourceKey{}, p)
	if r == nil {
		err = p.current(bound)
	}
	return bound, err
}

// Pure original metadata/file bookend. No source, physical, provider, process
// or caller callback follows the final backend image through this method.
func (p *xraySelectedTCPPreResource) current(ctx context.Context) error {
	return p.currentBeforeIssuer(ctx, false)
}

// Only the SAME sealed issuer may enter while e.prepare is in progress. The
// stock/unused observers never take this branch, and attempted remains sticky.
func (p *xraySelectedTCPPreResource) currentBeforeIssuer(ctx context.Context, issuing bool) error {
	if p == nil || p.self != p || p.owner == nil || p.owner.self != p.owner || p.owner.scope == nil || p.owner.material == nil ||
		p.owner.material.self != p.owner.material || p.owner.material.closed.Load() || p.execution == nil || p.execution.self != p.execution ||
		p.execution.preResource != p || p.execution.material != p.owner.material || p.owner.material.execution != p.execution || !p.execution.bound ||
		p.execution.gate == nil || p.execution.checks == nil || p.execution.checks.closed.Load() ||
		p.execution.checks.gate != p.execution.gate || p.execution.checks.manager != p.owner.material.manager || p.execution.checks.identity != p.execution.gate.identity ||
		ctx == nil || ctx.Value(xraySelectedTCPPreResourceKey{}) != p || ctx.Value(xrayOperationOwnerKey{}) != p.owner ||
		ctx.Value(xrayOperationMaterialKey{}) != p.owner.material || ctx.Value(xraySelectedTCPExecutionKey{}) != p.execution || xraySelectedTCPFinite(ctx) != nil || p.attempted.Load() {
		return ErrXrayOperationOwner
	}
	e, s := p.execution, p.owner.scope
	e.mu.Lock()
	unused := e.resource == nil && !e.started && !e.retired && e.replacement == nil && (!e.preparing || issuing)
	e.mu.Unlock()
	if !unused {
		return ErrXrayOperationOwner
	}
	s.mu.Lock()
	err := s.checkOriginalOwner(ctx, nil, !p.owner.material.IsCleanupContext(ctx), false)
	if err == nil && (s.adapter != "xray" || s.adapterOwner != p.owner.material.adapter || s.manager != p.owner.material.manager ||
		s.networkIdentity != e.gate.identity || !xraySelectedTCPSamePlan(e.plan, s.plan) || !s.observationOpen.Load() ||
		s.execution.PlanID != s.plan.PlanID || s.execution.Digest != s.plan.Digest || s.execution.ResourcePlanID != "" ||
		len(s.execution.Resources) != 0 || s.resourceCount() != 0 || s.retained || s.pending) {
		err = ErrXrayOperationOwner
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if _, err := s.owned.Stat("execution-resources"); !errors.Is(err, os.ErrNotExist) {
		return ErrPolicyAdditionUnknown
	}
	file, err := s.owned.OpenFile("xray", os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		if p.attempted.Load() {
			return ErrPolicyAdditionUnknown
		}
		return nil // No adapter snapshot/materialization directory yet.
	}
	if err != nil {
		return ErrPolicyAdditionUnknown
	}
	names, readErr := file.Readdirnames(1)
	closeErr := file.Close()
	if len(names) != 0 || readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || p.attempted.Load() {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

func (p *xraySelectedTCPPreResource) unused(ctx context.Context, e *xraySelectedTCPExecution) error {
	if p == nil || e != p.execution || p.owner == nil || p.owner.material == nil || !p.owner.material.IsCleanupContext(ctx) {
		return ErrXrayOperationOwner
	}
	if err := p.owner.checkHeld(ctx, true); err != nil {
		return err
	}
	return p.current(ctx)
}

func xraySelectedTCPMaterializationAttempt(ctx context.Context, s *executionResourceScope, material *XrayOperationMaterial) error {
	if material == nil || material.execution == nil || material.execution.preResource == nil {
		return nil // Existing separate resource/replacement callers stay closed.
	}
	p := material.execution.preResource
	if p.self != p || p.owner == nil || p.owner.scope != s || p.owner.material != material || p.execution != material.execution ||
		ctx.Value(xraySelectedTCPPreResourceKey{}) != p || p.currentBeforeIssuer(ctx, true) != nil {
		return ErrXrayOperationOwner
	}
	p.attempted.Store(true)
	return nil
}

func (e *xraySelectedTCPExecution) originalSnapshotInventory(ctx context.Context) (BackendInventorySnapshot, error) {
	p := e.preResource
	if p == nil {
		return e.inventory.Read(ctx, e.gate.identity.value) // Existing replacement.
	}
	if e.inventory.reader.Provider == nil || e.checks.inventory == nil || e.inventory.reader.Provider != e.gate.identity.provider ||
		e.checks.inventory.reader.Provider != e.inventory.reader.Provider {
		return BackendInventorySnapshot{}, ErrBackendInventoryUnknown
	}
	if err := p.current(ctx); err != nil {
		return BackendInventorySnapshot{}, err
	}
	image, err := e.checks.read(ctx, e.gate.identity.value) // SAME frozen startup collector.
	if err != nil {
		return BackendInventorySnapshot{}, err
	}
	return image, p.current(ctx)
}
