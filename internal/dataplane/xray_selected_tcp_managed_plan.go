package dataplane

import (
	"context"
	"reflect"
	"time"
)

// The original in-call material selects the dedicated compiler branch. This
// produces comparison intent only; native admission remains in Manager Stage.
func BuildManagedXraySelectedTCPList(ctx context.Context, input Input, material *XrayOperationMaterial, now time.Time) (Plan, error) {
	if material == nil || material.self != material || material.material == nil || input.LAN == nil || input.LAN.Mode != LANPolicyXraySelectedTCPMode || !reflect.DeepEqual(input.LAN, material.material.spec.LAN) ||
		!xraySelectedTCPScopeRouteMatches(Plan{Routes: input.Routes}, material.material) {
		return Plan{}, ErrXrayOperationOwner
	}
	material.barrier.RLock()
	defer material.barrier.RUnlock()
	if err := material.current(ctx, false); err != nil {
		return Plan{}, err
	}
	input.managedXraySelectedTCP = material
	return BuildAt(input, now)
}
