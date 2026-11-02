package dataplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
)

// Manager.operation serializes enrollment and successor publication. The
// mutex protects only detached snapshots; no native/kernel callback runs held.
// A saved marker can describe these owners, but cannot construct this pool.
type domainTCPStandbyPool struct {
	self      *domainTCPStandbyPool
	mu        sync.Mutex
	manager   *Manager
	entries   []*domainTCPStandbyPoolEntry
	successor *domainTCPGlobalSuccessor
	keeper    *domainTCPGlobalKeeper
}

type domainTCPStandbyPoolEntry struct {
	detached   *DomainTCPDetachedStandby
	retained   *retainedXrayExecution
	history    *domainTCPGlobalHistory
	definition ExecutionDomainDNSCoexistencePrior
	profile    string
}

func (m *Manager) hasPendingDomainSuccessor() bool {
	if m == nil {
		return false
	}
	m.retainedXrayMu.Lock()
	pool := m.domainPool
	m.retainedXrayMu.Unlock()
	if pool == nil {
		return false
	}
	if pool.self != pool || pool.manager != m {
		return true
	}
	pool.mu.Lock()
	c := pool.successor
	keeper := pool.keeper
	count := len(pool.entries)
	pool.mu.Unlock()
	if count < 1 || count > 2 {
		return true
	}
	if c == nil {
		return false
	} // Reservation still leaves the SAME current slot.
	if c.self != c || c.scope == nil || c.scope.manager != m {
		return true
	}
	c.mu.Lock()
	pending := c.pending || c.failure != nil
	c.mu.Unlock()
	c.scope.mu.Lock()
	closedKnown := keeper != nil && keeper.cursor == c && keeper.ready.Load() && !keeper.closed.Load()
	pending = pending || c.scope.pending || c.scope.failure != nil || !c.scope.open && !closedKnown
	c.scope.mu.Unlock()
	return pending
}

func (p *domainTCPStandbyPool) originals() ([]*domainTCPStandbyPoolEntry, error) {
	if p == nil || p.self != p || p.manager == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	p.manager.retainedXrayMu.Lock()
	same := p.manager.domainPool == p
	p.manager.retainedXrayMu.Unlock()
	if !same {
		return nil, ErrPolicyAdditionUnknown
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) < 1 || len(p.entries) > 2 {
		return nil, ErrPolicyAdditionUnknown
	}
	return append([]*domainTCPStandbyPoolEntry(nil), p.entries...), nil
}

func (e *domainTCPStandbyPoolEntry) current(ctx context.Context, manager *Manager, plan Plan, historical bool) error {
	if e == nil || e.detached == nil || e.detached.self != e.detached || e.history == nil || e.retained == nil || e.detached.owner == nil || e.detached.owner.process == nil {
		return ErrPolicyAdditionUnknown
	}
	d, owner := e.detached, e.detached.owner
	s := owner.process.scope
	if s == nil || s.manager != manager || e.profile != s.plan.NetworkProfileID || e.profile != plan.NetworkProfileID || d.owner != owner || e.retained.scope != s || e.retained.standby != owner {
		return ErrPolicyAdditionUnknown
	}
	d.mu.Lock()
	finished, registryDone := d.finished, d.registryDone
	d.mu.Unlock()
	s.mu.Lock()
	same := s.retained && s.retainedXrayOwner == e.retained && !e.retained.pending
	s.mu.Unlock()
	if !finished || !registryDone || !same {
		return ErrPolicyAdditionUnknown
	}
	if err := manager.checkPlanNetwork(ctx, plan); err != nil {
		return err
	}
	if err := owner.original.compareStandby(ctx, false); err != nil {
		return err
	}
	var err error
	if historical {
		err = e.history.currentHistorical(ctx)
	} else {
		err = e.history.currentOriginal(ctx)
	}
	if err != nil {
		return err
	}
	return manager.checkPlanNetwork(ctx, plan)
}

// Called only while the original Manager operation is held, before creating
// the successor scope or writing its first checking image. Failure retains the
// existing slot and all exact original owners.
func (m *Manager) reserveDomainPool(ctx context.Context, plan Plan, detached *DomainTCPDetachedStandby) (*domainTCPStandbyPool, error) {
	if m == nil || detached == nil || detached.self != detached || detached.owner == nil || detached.owner.process == nil || detached.original == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	s := detached.owner.process.scope
	if s == nil || s.manager != m {
		return nil, ErrPolicyAdditionUnknown
	}
	m.retainedXrayMu.Lock()
	existingPool, slot := m.domainPool, m.retainedXray
	m.retainedXrayMu.Unlock()
	if slot == nil && existingPool != nil {
		entries, err := existingPool.originals()
		if err != nil {
			return nil, err
		}
		existingPool.mu.Lock()
		keeper := existingPool.keeper
		cursor := existingPool.successor
		existingPool.mu.Unlock()
		if keeper == nil || keeper.cursor != cursor || entries[len(entries)-1].detached != detached {
			return nil, ErrPolicyAdditionUnknown
		}
		if keeper.continuation == nil || keeper.continuation.Reference().Count >= 256 {
			return nil, ErrDomainPolicyTCPCaptureRetirementPending
		}
		for _, entry := range entries {
			if err := entry.current(ctx, m, plan, true); err != nil {
				return nil, err
			}
		}
		if err := keeper.current(ctx); err != nil {
			return nil, err
		}
		return existingPool, nil
	}
	detached.mu.Lock()
	finished, registryDone := detached.finished, detached.registryDone
	detached.mu.Unlock()
	if !finished || !registryDone || detached.failure != nil || detached.continuation == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	s.mu.Lock()
	retained := s.retainedXrayOwner
	same := s.retained && retained != nil && retained.standby == detached.owner && !retained.pending
	beforeImage, marshalErr := json.Marshal(s.execution)
	var record Execution
	decodeErr := json.Unmarshal(beforeImage, &record)
	s.mu.Unlock()
	if !same || marshalErr != nil || decodeErr != nil || s.plan.NetworkProfileID != plan.NetworkProfileID {
		return nil, errors.Join(ErrPolicyAdditionUnknown, marshalErr, decodeErr)
	}
	if err := errors.Join(detached.original.compareStandby(ctx, false), m.checkPlanNetwork(ctx, plan)); err != nil {
		return nil, err
	}
	history, err := borrowDomainTCPGlobalHistory(ctx, detached.owner, record)
	if err != nil {
		return nil, err
	}
	var baseline *ExecutionSyntheticBaselineDefinition
	baselineID := filepath.Base(detached.owner.baseline.relative)
	for _, row := range record.Resources {
		if row.ID == baselineID {
			baseline = row.SyntheticBaseline
		}
	}
	if baseline == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	entry := &domainTCPStandbyPoolEntry{detached: detached, retained: retained, history: history, profile: s.plan.NetworkProfileID,
		definition: ExecutionDomainDNSCoexistencePrior{ExecutionPlanID: record.PlanID, Digest: record.Digest, BaselineID: baselineID, JournalSHA256: hex.EncodeToString(history.digest[:]), Baseline: *cloneExecutionSyntheticBaselineDefinition(baseline), Detached: detached.definition.Clone()}}
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	if m.retainedXray != retained || m.replacementXray != nil {
		return nil, ErrPolicyAdditionUnknown
	}
	pool := m.domainPool
	if pool == nil {
		pool = &domainTCPStandbyPool{manager: m}
		pool.self = pool
	} else if pool.self != pool || pool.manager != m {
		return nil, ErrPolicyAdditionUnknown
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if c := pool.successor; c != nil {
		if c.self != c || c.pool != pool || c.scope != s || c.scope.domainTCPOwner != detached.original || c.records != detached.owner.process.records || c.forwardCurrentState() != nil {
			return nil, ErrDomainPolicyTCPCaptureRetirementPending
		}
	}
	for _, prior := range pool.entries {
		if prior.detached == detached && prior.retained == retained {
			return pool, nil
		}
		if prior.definition.ExecutionPlanID == record.PlanID {
			return nil, ErrPolicyAdditionUnknown
		}
	}
	if len(pool.entries) >= 2 {
		return nil, ErrDomainPolicyTCPCaptureRetirementPending
	}
	pool.entries = append(pool.entries, entry)
	m.domainPool = pool
	// Reserve comparison custody now. The successor cursor transfers the slot
	// only after it owns the actual new scope and original writer holder.
	return pool, nil
}
