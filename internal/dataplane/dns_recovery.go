package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"
)

// PrepareDNSRecovery releases only the DNS runtime of the still-current
// committed plan. A later Apply must obtain fresh authority and check health.
// The application's existing exclusive lease spans BOTH calls and cleanup.
func (m *Manager) PrepareDNSRecovery(ctx context.Context, expected Plan) error {
	if expected.DNS == nil {
		return ErrReviewChanged
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if err := m.checkExecutionRecovery(); err != nil {
		_, cleanupErr := m.revokeUnverifiedDNS(ctx)
		return errors.Join(err, cleanupErr)
	}
	current, exists, err := m.committedLocked()
	if err != nil {
		return executionJournalError(err)
	}
	if !exists || !reflect.DeepEqual(current, expected) {
		return ErrReviewChanged
	}
	adapter, exists := m.adapter(scopedDNSAdapterID)
	owner, supported := adapter.(RuntimeDeactivator)
	if !exists || !supported {
		return errors.New("scoped DNS cleanup owner unavailable")
	}
	report := Recovery{PlanID: expected.PlanID, State: "dns-stopped-for-recheck", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.rollbackTimeout())
	defer cancel()
	cleanupErr := owner.Deactivate(cleanupCtx)
	step := RecoveryStep{Adapter: scopedDNSAdapterID, State: "dns-redirects-released"}
	if cleanupErr != nil {
		report.State, report.Guarded, report.FailureCount = "safe-mode", true, 1
		step.State, step.Detail = "dns-cleanup-failed", cleanupErr.Error()
	}
	report.Steps = []RecoveryStep{step}
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return errors.Join(cleanupErr, executionJournalError(m.writeRecoveryLocked(report)))
}

// Local DNS redirects cannot outlive their in-process server or its network
// authority. This narrow hook removes ONLY the DNS adapter's owned redirects;
// it neither replays settings nor restarts/uninstalls other engines.
type unverifiedDNSRevoker interface {
	revokeUnverifiedDNS(context.Context) error
}

func (a *ScopedDNSAdapter) revokeUnverifiedDNS(ctx context.Context) error {
	return a.Deactivate(ctx)
}

func (m *Manager) revokeUnverifiedDNS(parent context.Context) ([]RecoveryStep, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), m.rollbackTimeout())
	defer cancel()
	m.registryMu.RLock()
	owners := map[string]unverifiedDNSRevoker{}
	for id, adapter := range m.Adapters {
		if owner, ok := adapter.(unverifiedDNSRevoker); ok {
			owners[id] = owner
		}
	}
	m.registryMu.RUnlock()
	ids := make([]string, 0, len(owners))
	for id := range owners {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	steps := []RecoveryStep{}
	var failure error
	for _, id := range ids {
		step := RecoveryStep{Adapter: id, State: "dns-redirects-released"}
		if err := owners[id].revokeUnverifiedDNS(ctx); err != nil {
			step.State, step.Detail = "dns-cleanup-failed", err.Error()
			failure = errors.Join(failure, err)
		}
		steps = append(steps, step)
	}
	return steps, failure
}
