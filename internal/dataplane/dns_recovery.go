package dataplane

import (
	"context"
	"errors"
	"slices"
)

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
