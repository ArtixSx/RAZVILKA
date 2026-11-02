package strategylab

import "context"

// SelectManaged uses only the original completed in-process epoch. Persisted
// evidence remains history after restart and cannot reconstruct this owner.
func (m *Manager) SelectManaged(ctx context.Context, serviceID, protocol, family, candidateID string, mode AdaptiveMode, frozen bool) (Selection, error) {
	if m == nil || protocol != "tcp" || family != "ipv4" || mode != ModePreferred && mode != ModeOnly {
		return Selection{}, ErrManagedProbeContextRequired
	}
	epoch, err := m.currentManagedProbeEpoch(ctx, candidateID, serviceID)
	if err != nil {
		return Selection{}, err
	}
	if epoch == nil {
		return Selection{}, ErrManagedProbeContextRequired
	}
	return epoch.SelectForMode(ctx, mode, frozen)
}
