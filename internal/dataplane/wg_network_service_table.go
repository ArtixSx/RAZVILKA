package dataplane

import (
	"context"
	"errors"
)

// A sampled /0 lookup cannot explain a foreign specific route in the inner
// table. Observe the complete numeric table and accept only the compiler's one
// exact default tuple. This is presence evidence, never interface/receipt
// ownership; callers must establish private authority independently.
func (a *WARPWireGuardAdapter) wgNetworkServiceTablePresence(ctx context.Context, state PolicyState, family int) (int, error) {
	if state.NetworkPolicyGeneration == "" || state.Interface != a.interfaceName() || state.Table != a.table() || family != 4 && family != 6 {
		return 0, ErrWGNetworkPolicy
	}
	if a.wgCommandTools != nil {
		runner, ok := a.Runner.(wgExecRunner)
		if !ok || runner.adapter != a {
			return 0, ErrWGOperationOwner
		}
		return runner.readProbeKernelServiceTable(ctx, family) // Bound refusal never falls back to CLI.
	}
	data, err := a.readWGCompleteDetailedNumericTable(ctx, state.Table, family)
	if err != nil {
		return 0, err
	}
	rows, err := parseWGEndpointRoutes(data)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	route := rows[0]
	destination, metric, scope := "0.0.0.0/0", 0, "link"
	if family == 6 {
		destination, metric, scope = "::/0", 1024, "global"
	}
	if route.Destination != "default" && route.Destination != destination || route.Type != "unicast" || route.Device != state.Interface || route.Gateway != "" || route.Source != "" || route.SelectedSource != "" || route.From != "" || route.Protocol != "boot" || route.Scope != scope || route.Metric != metric || len(route.Flags) != 0 || len(route.Table) != 0 && !wgEndpointTableMatches(route.Table, state.Table) {
		return 0, ErrWGNetworkPolicy
	}
	return 1, ctx.Err()
}

func (a *WARPWireGuardAdapter) verifyWGNetworkServiceTables(ctx context.Context, state PolicyState, wanted int) error {
	for _, family := range []int{4, 6} {
		count, err := a.wgNetworkServiceTablePresence(ctx, state, family)
		if err != nil || count != wanted {
			return errors.Join(err, ErrWGNetworkPolicy)
		}
	}
	return ctx.Err()
}
