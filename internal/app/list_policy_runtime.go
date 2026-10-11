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
	wg                    *ManagedWGListRuntime
	wgClosed              bool
	wgAvailable           map[string]bool
	wgInactivity          map[string]*dataplane.WGInactivityRead
	nfqClosed, xrayClosed bool
	closed                atomic.Bool
	closeErr              error // guarded by mu; repeated release preserves a failed join
	startupReady          bool
	startupFailure        error
}

func (a *App) configureReviewedStockListPolicy(ctx, panel context.Context) (result *managedListPolicyOwner, resultErr error) {
	if a == nil || a.Dataplane == nil || a.Store == nil || a.Components == nil || a.StrategyLab == nil || a.SelfUpdateFiles == nil || ctx == nil || panel == nil || panel.Err() != nil {
		return nil, dataplane.ErrNetworkPolicyAuthority
	}
	a.managedListPolicyMu.Lock()
	defer a.managedListPolicyMu.Unlock()
	if p := a.managedListPolicy; p != nil {
		if p.startupFailure != nil {
			return nil, p.startupFailure
		}
		if !p.original() || p.closed.Load() || p.panel != panel {
			return nil, dataplane.ErrNetworkPolicyAuthority
		}
		return p, nil
	}
	p := &managedListPolicyOwner{app: a, manager: a.Dataplane, panel: panel}
	p.self = p
	a.managedListPolicy = p
	stage := "operation"
	defer func() {
		if resultErr != nil {
			p.startupFailure = &managedListStartupFailure{stage: stage, cause: resultErr}
			resultErr = errors.Join(p.startupFailure, p.closeStartupResources())
		} else {
			p.startupReady = true
		}
	}()
	c, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if _, finite := c.Deadline(); !finite {
		return nil, dataplane.ErrNetworkPolicyAuthority
	}
	stage = "control"
	control, err := a.managedNFQControl(c)
	if err != nil {
		return nil, err
	}
	defer a.closeUnretainedManagedNFQControl(control)
	p.control = control
	stage = "network-identity"
	provider, err := netidentity.NewReviewedStockNC1812Provider(c)
	if err != nil {
		return nil, err
	}
	p.provider = provider
	stage = "startup-tools"
	tools, err := startuptools.AcquireReviewedStockNC1812ManagedList(panel, provider)
	if err != nil {
		return nil, err
	}
	p.tools = tools
	stage = "inventory-tools"
	descriptor, err := tools.InventoryTools()
	if err != nil {
		return nil, err
	}
	stage = "backend-inventory"
	inventory, err := dataplane.NewReviewedStockNC1812BackendInventory(provider, descriptor)
	if err != nil {
		return nil, err
	}
	p.inventory = inventory
	stage = "policy-tools"
	policyTools, runner, err := tools.PolicyRuntimeTools()
	if err != nil {
		return nil, err
	}
	stage = "wg-tools-identity"
	p.wgAvailable = map[string]bool{}
	actualIdentity, err := provider.Observe(c)
	if err != nil {
		return nil, err
	}
	stage = "wg-tools-observation"
	wgTools, err := tools.ManagedListWGCommandTools(c, actualIdentity)
	if err != nil {
		return nil, err
	}
	for _, engine := range []string{"wireguard", "amneziawg"} {
		descriptor, available := wgTools[engine]
		if !available {
			continue
		}
		stage = "wg-tools-bind-" + engine
		if err := p.manager.BindManagedWGCommandTools(c, descriptor); err != nil {
			return nil, err
		}
		p.wgAvailable[engine] = true
	}
	lan := &dataplane.LANPolicyRuntime{Runner: runner, IP: policyTools.IP, IPTables: policyTools.IPTables, IP6Tables: policyTools.IP6Tables, ScopeCheck: p.scopeCheck,
		TransportCheck: func(c context.Context, plan *dataplane.LANPolicyRuntimePlan, family int, line string) error {
			if p.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return p.checks.WGTransportCheck(c, plan, family, line)
		},
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
	stage = "policy-gate"
	p.gate, err = dataplane.NewNetworkPolicyAdapter(c, dataplane.NetworkPolicyAssemblyOptions{Mode: dataplane.LANPolicyManagedListMode, Provider: provider, Binding: binding,
		InventoryCheck: func(c context.Context, identity netidentity.Identity, plan *dataplane.LANPolicyRuntimePlan) error {
			if p.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return p.checks.InventoryCheck(c, identity, plan)
		}})
	if err != nil {
		return nil, err
	}
	stage = "state-root"
	if err := os.MkdirAll(p.manager.StateRoot, 0700); err != nil {
		return nil, err
	}
	stage = "register-policy"
	if err := p.manager.Register(p.gate); err != nil {
		return nil, err
	}
	// A registered participant cannot be silently replaced after a failed bind.
	a.managedListPolicy = p
	stage = "consumer-checks"
	p.checks, err = p.manager.BindNetworkPolicyChecks(p.gate, inventory)
	if err != nil {
		return nil, err
	}
	stage = "dns-owner"
	if a.DNS == nil {
		return nil, dataplane.ErrRuntimeInactivity
	}
	stage = "inactivity-sources"
	if err := p.manager.BindRuntimeInactivitySources(c, provider, inventory, a.DNS.Path); err != nil {
		return nil, err
	}
	stage = "wg-inactivity-sources"
	p.wgInactivity = make(map[string]*dataplane.WGInactivityRead, 2)
	for _, engine := range []string{"wireguard", "amneziawg"} {
		stage = "wg-inactivity-sources-" + engine
		source, err := tools.ReviewWGInactivity(c, p.manager, control, engine)
		if err != nil {
			return nil, err
		}
		p.wgInactivity[engine] = source
	}
	stage = "wg-inactivity-binding"
	if err := p.checks.BindManagedWGInactivitySources(c, p.wgInactivity); err != nil {
		return nil, err
	}
	a.retainManagedNFQControl(control)
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
	if ctx.Value(managedWGListOperationKey{}) != nil {
		return nil, nil, dataplane.ErrNetworkPolicyAuthority
	}
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
	if r, err := p.wgRuntimeFor(ctx); r != nil || err != nil {
		if err != nil {
			return err
		}
		return r.scopeCheck(ctx, plan)
	}
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
	if r, err := p.wgRuntimeFor(ctx); r != nil || err != nil {
		if err != nil {
			return err
		}
		return r.lanApplyGuard(ctx, plan, effect)
	}
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
	if r, err := p.wgRuntimeFor(ctx); r != nil || err != nil {
		if err != nil {
			return err
		}
		return r.lanCleanupGuard(ctx, plan, effect)
	}
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
	if p.nfq != nil && !p.nfqClosed || p.xray != nil && !p.xrayClosed || p.wg != nil && !p.wgClosed {
		return nil
	}
	if p.closed.Swap(true) {
		return p.closeErr
	}
	p.closeErr = errors.Join(p.closeWGInactivity(), p.checks.Close(), p.tools.Close())
	return p.closeErr
}

func (p *managedListPolicyOwner) closeWGInactivity() error {
	var result error
	for _, engine := range []string{"wireguard", "amneziawg"} {
		if source := p.wgInactivity[engine]; source != nil {
			result = errors.Join(result, source.Close())
		}
	}
	return result
}
