package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Observation only. A decoded marker cannot reconstruct the pool, its current
// latest writer, or a published predecessor. Unrelated generic writes remain
// refused even after this comparison succeeds.
func (m *Manager) checkKnownDomainPoolRecord(ctx context.Context, record Execution) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil || record.DomainDNSCoexistence == nil {
		return ErrPolicyAdditionUnknown
	}
	m.retainedXrayMu.Lock()
	pool, retained := m.domainPool, m.retainedXray
	m.retainedXrayMu.Unlock()
	if pool == nil || pool.self != pool || pool.manager != m {
		return ErrPolicyAdditionUnknown
	}
	pool.mu.Lock()
	c, keeper := pool.successor, pool.keeper
	pool.mu.Unlock()
	if keeper != nil {
		return m.checkKnownDomainKeeperRecord(ctx, record)
	}
	if c == nil || c.original() != nil || retained == nil || retained.self != retained || retained.scope != c.scope || retained.records != c.records || retained.standby == nil || retained.standby.process == nil || retained.standby.process.records != c.records || record.State != "resource-failed" || validateExecutionResources(record, false) != nil {
		return ErrPolicyAdditionUnknown
	}
	wanted, e1 := json.Marshal(c.definition)
	actual, e2 := json.Marshal(record.DomainDNSCoexistence)
	if e1 != nil || e2 != nil || !bytes.Equal(wanted, actual) {
		return errors.Join(ErrExecutionJournal, e1, e2)
	}
	if err := m.checkKnownDomainStandbyRecord(ctx, record); err != nil {
		return err
	}
	// Preserve the existing original standby observer's bounded twelve-second
	// lifetime. This extra comparison returns no cleanup/effect permission.
	prior, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if err := c.comparePrior(prior, true); err != nil {
		return err
	}
	if err := prior.Err(); err != nil {
		return err
	}
	return m.checkKnownDomainStandbyRecord(ctx, record)
}
