package app

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

// One original startup owner supplies the fixed shared policy participant for
// both concrete list runtimes. No request, callback or copied descriptor can
// replace its provider, tools, inventory, control or registered gate.
type managedListPolicyOwner struct {
	self                  *managedListPolicyOwner
	mu                    sync.Mutex
	app                   *App
	manager               *dataplane.Manager
	panel                 context.Context
	provider              *netidentity.Provider
	tools                 *startuptools.Lease
	inventory             *dataplane.BackendInventory
	gate                  *dataplane.NetworkPolicyAdapter
	checks                *dataplane.NetworkPolicyChecks
	control               *operationgate.ControlEpochReview
	nfq                   *ManagedNFQWSListRuntime
	xray                  *ManagedXraySelectedTCPListRuntime
	nfqClosed, xrayClosed bool
	closed                atomic.Bool
	closeErr              error // guarded by mu; repeated release preserves a failed join
}

func (a *App) configureReviewedStockListPolicy(ctx, panel context.Context) (*managedListPolicyOwner, error) {
	if a == nil || a.Dataplane == nil || a.Store == nil || a.Components == nil || a.StrategyLab == nil || a.SelfUpdateFiles == nil || ctx == nil || panel == nil || panel.Err() != nil {
		return nil, dataplane.ErrNetworkPolicyAuthority
	}
	a.managedListPolicyMu.Lock()
	defer a.managedListPolicyMu.Unlock()
	if p := a.managedListPolicy; p != nil {
		if !p.original() || p.closed.Load() || p.panel != panel {
			return nil, dataplane.ErrNetworkPolicyAuthority
		}
		return p, nil
	}
	c, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if _, finite := c.Deadline(); !finite {
		return nil, dataplane.ErrNetworkPolicyAuthority
	}
	control, err := a.managedNFQControl(c)
	if err != nil {
		return nil, err
	}
	defer a.closeUnretainedManagedNFQControl(control)
	provider, err := netidentity.NewReviewedStockNC1812Provider(c)
	if err != nil {
		return nil, err
	}
	tools, err := startuptools.AcquireReviewedStockNC1812Policy(panel, provider)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = tools.Close()
		}
	}()
	descriptor, err := tools.InventoryTools()
	if err != nil {
		return nil, err
	}
	inventory, err := dataplane.NewReviewedStockNC1812BackendInventory(provider, descriptor)
	if err != nil {
		return nil, err
	}
	policyTools, runner, err := tools.PolicyRuntimeTools()
	if err != nil {
		return nil, err
	}
	p := &managedListPolicyOwner{app: a, manager: a.Dataplane, panel: panel, provider: provider, tools: tools, inventory: inventory, control: control}
	p.self = p
	lan := &dataplane.LANPolicyRuntime{Runner: runner, IP: policyTools.IP, IPTables: policyTools.IPTables, IP6Tables: policyTools.IP6Tables, ScopeCheck: p.scopeCheck,
		ConsumerCheck: func(c context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
			if p.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return p.checks.ConsumerCheck(c, plan)
		}}
	binding := &dataplane.LANPolicyReceiptBinding{Runtime: lan, ApplyGuard: p.lanApplyGuard, CleanupGuard: p.lanCleanupGuard,
		RetireCheck: func(c context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
			if p.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return p.checks.RetireCheck(c, plan)
		}}
	p.gate, err = dataplane.NewNetworkPolicyAdapter(c, dataplane.NetworkPolicyAssemblyOptions{Mode: dataplane.LANPolicyManagedListDirectMode, Provider: provider, Binding: binding,
		InventoryCheck: func(c context.Context, identity netidentity.Identity, plan *dataplane.LANPolicyRuntimePlan) error {
			if p.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return p.checks.InventoryCheck(c, identity, plan)
		}})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.manager.StateRoot, 0700); err != nil {
		return nil, err
	}
	if err := p.manager.Register(p.gate); err != nil {
		return nil, err
	}
	// A registered participant cannot be silently replaced after a failed bind.
	a.managedListPolicy = p
	p.checks, err = p.manager.BindNetworkPolicyChecks(p.gate, inventory)
	if err != nil {
		p.closed.Store(true)
		return nil, err
	}
	if a.DNS == nil {
		p.closed.Store(true)
		return nil, dataplane.ErrRuntimeInactivity
	}
	if err := p.manager.BindRuntimeInactivitySources(c, provider, inventory, a.DNS.Path); err != nil {
		p.closed.Store(true)
		return nil, err
	}
	a.retainManagedNFQControl(control)
	keep = true
	return p, nil
}

func (p *managedListPolicyOwner) original() bool {
	return p != nil && p.self == p && p.app != nil && p.app.managedListPolicy == p && p.app.Dataplane == p.manager && p.manager != nil && p.panel != nil && p.panel.Err() == nil && p.provider != nil && p.tools != nil && p.inventory != nil && p.gate != nil && p.control != nil
}

// Closed dispatch uses the actual concrete operation tags. Both tags, a copy,
// foreign App/runtime or another policy owner always refuse before delegation.
func (p *managedListPolicyOwner) runtimeFor(ctx context.Context) (*ManagedNFQWSListRuntime, *ManagedXraySelectedTCPListRuntime, error) {
	if !p.original() || p.closed.Load() || ctx == nil || ctx.Err() != nil {
		return nil, nil, dataplane.ErrNetworkPolicyAuthority
	}
	n, x := ctx.Value(managedNFQWSListOperationKey{}), ctx.Value(managedXraySelectedTCPListOperationKey{})
	if (n == nil) == (x == nil) {
		return nil, nil, dataplane.ErrNetworkPolicyAuthority
	}
	if n != nil {
		r := p.app.managedNFQList
		if r == nil || r.policy != p || r.gate != p.gate || r.checks != p.checks {
			return nil, nil, dataplane.ErrNetworkPolicyAuthority
		}
		if _, _, err := r.executionFor(ctx); err != nil {
			return nil, nil, err
		}
		return r, nil, nil
	}
	r := p.app.managedXraySelectedTCPList
	if r == nil || r.policy != p {
		return nil, nil, dataplane.ErrNetworkPolicyAuthority
	}
	if _, _, err := r.executionFor(ctx); err != nil {
		return nil, nil, err
	}
	return nil, r, nil
}

func (p *managedListPolicyOwner) scopeCheck(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	n, x, err := p.runtimeFor(ctx)
	if err != nil {
		return err
	}
	if n != nil {
		return n.scopeCheck(ctx, plan)
	}
	return x.scopeCheck(ctx, plan)
}

func (p *managedListPolicyOwner) lanApplyGuard(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan, effect dataplane.LANPolicyEffect) error {
	n, x, err := p.runtimeFor(ctx)
	if err != nil {
		return err
	}
	if n != nil {
		return n.lanApplyGuard(ctx, plan, effect)
	}
	return x.lanApplyGuard(ctx, plan, effect)
}

func (p *managedListPolicyOwner) lanCleanupGuard(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan, effect dataplane.LANPolicyEffect) error {
	n, x, err := p.runtimeFor(ctx)
	if err != nil {
		return err
	}
	if n != nil {
		return n.lanCleanupGuard(ctx, plan, effect)
	}
	return x.lanCleanupGuard(ctx, plan, effect)
}

func (p *managedListPolicyOwner) attachXray(r *ManagedXraySelectedTCPListRuntime) error {
	if !p.original() || p.closed.Load() || r == nil || r.self != r || r.app != p.app || r.manager != p.manager || r.policy != p || p.app.managedXraySelectedTCPList != r {
		return dataplane.ErrNetworkPolicyAuthority
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() || p.xray != nil && p.xray != r {
		return dataplane.ErrNetworkPolicyAuthority
	}
	p.xray, p.xrayClosed = r, false
	return nil
}

func (p *managedListPolicyOwner) releaseXray(r *ManagedXraySelectedTCPListRuntime) error {
	if p == nil || p.self != p || p.app == nil || p.app.managedListPolicy != p {
		return dataplane.ErrNetworkPolicyAuthority
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.xray != r || r == nil || r.self != r || r.policy != p || r.app != p.app || p.app.managedXraySelectedTCPList != r || !r.closed || r.active != nil || r.pending != nil || r.preparing != nil {
		return dataplane.ErrNetworkPolicyAuthority
	}
	p.xrayClosed = true
	return p.closeIfReleased()
}

func (p *managedListPolicyOwner) releaseNFQ(r *ManagedNFQWSListRuntime) error {
	if p == nil || p.self != p || p.app == nil || p.app.managedListPolicy != p {
		return dataplane.ErrNetworkPolicyAuthority
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nfq != r || r == nil || r.self != r || r.policy != p || r.app != p.app || p.app.managedNFQList != r || !r.closed || r.active != nil || r.pending != nil {
		return dataplane.ErrNetworkPolicyAuthority
	}
	p.nfqClosed = true
	return p.closeIfReleased()
}

func (p *managedListPolicyOwner) closeIfReleased() error {
	if p.nfq != nil && !p.nfqClosed || p.xray != nil && !p.xrayClosed {
		return nil
	}
	if p.closed.Swap(true) {
		return p.closeErr
	}
	p.closeErr = errors.Join(p.checks.Close(), p.tools.Close())
	return p.closeErr
}
