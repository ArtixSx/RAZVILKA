package dataplane

import (
	"context"
	"net/netip"
	"time"
)

// BuildManagedNFQWSList consumes an ORIGINAL current managed material beside
// a scoped literal-IP input. Generic Build/HTTP descriptors retain the closed
// legacy device-scope boundary. This plan grants no process/queue/receipt.
func BuildManagedNFQWSList(ctx context.Context, input Input, material *NFQWSActiveMaterial, now time.Time) (Plan, error) {
	if material == nil || material.self != material || input.LAN == nil || ValidateLANPolicyRuntime(input.LAN) != nil || len(input.Routes) != 1 || input.managedNFQWS != nil {
		return Plan{}, ErrNFQWSScopedOwner
	}
	if err := material.Current(ctx); err != nil {
		return Plan{}, err
	}
	for _, route := range input.Routes {
		if route.Resolved != "nfqws2" || route.Selected != "nfqws2" || route.LogicalServiceID != material.reference.ServiceID || len(route.Domains) != 0 || len(route.CIDRs) == 0 || len(route.Sources) != 1 || len(route.Ingress) != 1 || route.NetworkPolicyGeneration != input.LAN.Generation {
			return Plan{}, ErrNFQWSScopedOwner
		}
		if len(route.CIDRs) != 1 {
			return Plan{}, ErrNFQWSScopedOwner
		}
		for _, raw := range []string{route.CIDRs[0], route.Sources[0]} {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
				return Plan{}, ErrNFQWSScopedOwner
			}
		}
	}
	input.managedNFQWS = material
	return BuildAt(input, now)
}

// A ready scoped plan cannot downgrade the actual typed LAN participant to
// global package/init execution by dropping its private managed owner context.
func (m *Manager) checkManagedNFQWSApply(ctx context.Context, plan Plan) error {
	if plan.LAN == nil {
		return nil
	}
	adapter, ok := m.adapter("nfqws2")
	if !ok {
		return nil
	}
	if _, actual := adapter.(*NFQWS2Adapter); !actual {
		return nil
	}
	gateAdapter, ok := m.adapter(NetworkPolicyAdapterID)
	gate, typed := gateAdapter.(*NetworkPolicyAdapter)
	if !ok || !typed || gate.identity == nil {
		return nil
	}
	scoped := false
	for _, route := range plan.Routes {
		scoped = scoped || AdapterID(route.Resolved) == "nfqws2" && len(route.Sources) > 0
	}
	if !scoped {
		return nil
	}
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.manager != m || e.material.adapter != adapter || e.gate != gate || !nfqws2ActiveSamePlan(e.plan, plan) {
		return ErrNFQWSScopedOwner
	}
	return nil
}
