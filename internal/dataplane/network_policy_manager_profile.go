package dataplane

import (
	"errors"
	"strings"

	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

var ErrWireGuardProfileRevision = errors.New("exact reviewed named WireGuard profile revision is required")

// FrozenWireGuardProfileRevision validates metadata sealed by the full plan.
// The WG owner must still read the same registered Store and compare its exact
// current revision before each effect. Empty legacy preview metadata is never
// a grant to bind whichever profile happens to have this name at apply time.
func FrozenWireGuardProfileRevision(route Route) (string, error) {
	const prefix = "wireguard:"
	if !strings.HasPrefix(route.Resolved, prefix) || !wireguardprofile.ValidID(strings.TrimPrefix(route.Resolved, prefix)) || !validNetworkPolicyGeneration(route.WireGuardProfileRevision) {
		return "", ErrWireGuardProfileRevision
	}
	if strings.HasPrefix(route.Selected, prefix) && route.Selected != route.Resolved {
		return "", ErrWireGuardProfileRevision
	}
	return route.WireGuardProfileRevision, nil
}
