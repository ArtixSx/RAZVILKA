package dataplane

import (
	"context"
	"errors"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Caller already holds the SAME c.boundary, after every actual consumer has
// independently settled. Read the complete image twice with no intervening
// owner callback; only this original LAN body can remain during its cleanup.
func (c *NetworkPolicyChecks) retiredWGInventory(ctx context.Context, lan *LANPolicyRuntimePlan) error {
	var stock *networkPolicyXraySelectedTCPStockObservation
	if ctx.Value(xraySelectedTCPExecutionKey{}) != nil {
		e, ok := ctx.Value(xraySelectedTCPExecutionKey{}).(*xraySelectedTCPExecution)
		if !ok || e == nil || e.self != e || e.material == nil || e.material.execution != e || e.checks != c || !e.material.IsCleanupContext(ctx) {
			return ErrNetworkPolicyConsumers
		}
		var err error
		stock, err = c.xraySelectedTCPStockExecution(ctx)
		if err != nil || stock == nil || stock.pre != nil && stock.pre.execution != e ||
			stock.resource != nil && stock.resource.material.execution != e {
			return errors.Join(ErrNetworkPolicyConsumers, err)
		}
	}
	compare := func(image BackendInventorySnapshot) error {
		if stock == nil {
			return checkNetworkPolicyInventory(image, c.network, lan, nil)
		}
		rows, err := stock.comparison(image)
		if err != nil {
			return err
		}
		return checkNetworkPolicyInventoryWithStock(image, c.network, lan, c.identity.inventoryMode(lan), nil, rows)
	}
	first, err := c.read(ctx, c.network)
	if err != nil {
		return err
	}
	if err := compare(first); err != nil {
		return err
	}
	last, err := c.read(ctx, c.network)
	if err != nil || !reflect.DeepEqual(first, last) {
		return errors.Join(ErrBackendInventoryUnknown, err)
	}
	return errors.Join(compare(last), stock.current(ctx))
}

type wgInactivityCleanupKey struct{}

// Comparison carrier only. Each original source still authenticates the real
// same-control cleanup review; this grants no effect or source-read authority.
func WithWGInactivityCleanup(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) context.Context {
	return context.WithValue(ctx, wgInactivityCleanupKey{}, cleanup)
}

// Bind once AFTER all actual adapters/tool sources and inactivity owners have
// been frozen by trusted startup. Never bind from a request or reconstruct it.
func (c *NetworkPolicyChecks) BindManagedWGInactivitySources(ctx context.Context, sources map[string]*WGInactivityRead) error {
	if c == nil || c.current(ctx) != nil || c.identity.mode != LANPolicyManagedListMode || c.wgInactivity != nil || len(sources) != 2 {
		return ErrNetworkPolicyConsumers
	}
	frozen := make(map[string]*WGInactivityRead, 2)
	for _, id := range []string{"wireguard", "amneziawg"} {
		r := sources[id]
		if r == nil || r.self != r || r.manager != c.manager || r.root != c.root || r.registry != c.generation || r.identity != c.identity || r.adapter != c.adapters[id] || r.tools.EngineID != id || r.tools.Provider != c.identity.provider || r.tools.Identity != c.network || r.tools.IP != c.tools[0] || r.tools.IPTables != c.tools[1] || r.tools.IP6Tables != c.tools[2] {
			return ErrNetworkPolicyConsumers
		}
		if err := r.WithCurrent(ctx, nil, r.CurrentFiles); err != nil {
			return err
		}
		frozen[id] = r
	}
	if err := c.current(ctx); err != nil {
		return err
	}
	c.manager.registryMu.Lock()
	defer c.manager.registryMu.Unlock()
	if c.manager.registryGeneration != c.generation || c.manager.wgPreEffectChecks != nil {
		return ErrNetworkPolicyConsumers
	}
	c.wgInactivity = frozen
	c.manager.wgPreEffectChecks = c
	return nil
}

// A fresh read session exists only through this one RetireCheck. Save EACH
// original callback context: nesting sources replaces their private key.
// Full tool/control/Provider reads occur outside c.boundary; its closing calls
// use only those still-live source sessions and original file bookends.
func (c *NetworkPolicyChecks) withWGInactivity(ctx context.Context, use func(func() error) error) error {
	if c == nil || c.current(ctx) != nil || use == nil {
		return ErrNetworkPolicyConsumers
	}
	if c.identity.mode != LANPolicyManagedListMode {
		return use(func() error { return nil })
	}
	if len(c.wgInactivity) != 2 {
		return ErrRuntimeInactivity
	}
	return c.withWGInactivitySessions(ctx, func(contexts [2]context.Context, bookends func() error) error {
		var observed error
		for i, id := range [2]string{"wireguard", "amneziawg"} {
			if err := c.wgInactivity[id].VerifyCurrentRuntimeInactive(contexts[i]); err != nil {
				observed = errors.Join(observed, ErrNetworkPolicyConsumers, err)
			}
		}
		if observed != nil {
			return observed
		}
		return use(bookends)
	})
}

func (c *NetworkPolicyChecks) withWGInactivitySessions(ctx context.Context, use func([2]context.Context, func() error) error) error {
	cleanup, _ := ctx.Value(wgInactivityCleanupKey{}).(*operationgate.ExclusiveCleanupReview)
	var contexts [2]context.Context
	ids := [2]string{"wireguard", "amneziawg"}
	var enter func(int, context.Context) error
	enter = func(index int, parent context.Context) error {
		if index == len(ids) {
			return use(contexts, func() error {
				var result error
				for i, id := range ids {
					result = errors.Join(result, c.wgInactivity[id].CurrentFiles(contexts[i]))
				}
				return result
			})
		}
		r := c.wgInactivity[ids[index]]
		if r == nil || r.manager != c.manager || r.adapter != c.adapters[ids[index]] || r.identity != c.identity {
			return ErrRuntimeInactivity
		}
		return r.WithCurrent(parent, cleanup, func(original context.Context) error {
			contexts[index] = original
			return enter(index+1, original)
		})
	}
	return enter(0, ctx)
}
