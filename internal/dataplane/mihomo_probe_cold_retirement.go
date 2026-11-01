package dataplane

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

const mihomoColdRetirementDetail = "Finite probe interrupted; original parent is gone and fresh complete process/socket absence was observed. Service and original cleanup remain unverified."

// RetireMihomoProbeAfterParentExit is offline, file-only compensation. The
// existing CLI holds every private-store lifetime lease before entering it.
// A PID is never adopted or signalled and no service result is reconstructed.
func (m *Manager) RetireMihomoProbeAfterParentExit(ctx context.Context, id, digest string, offlineCurrent func(context.Context) error) (Execution, error) {
	provider := netidentity.NewProcProvider()
	return m.retireMihomoProbeMetadata(ctx, id, digest, offlineCurrent, func(c context.Context, d ExecutionMihomoProbeDefinition) (netidentity.Identity, error) {
		return observeMihomoColdAbsence(c, provider, d, m.StateRoot)
	}, true, nil)
}
