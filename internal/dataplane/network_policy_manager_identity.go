package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrNetworkPolicyIdentity = errors.New("LAN runtime requires its original fresh typed network identity")

// NetworkPolicyAssemblyOptions binds the existing shared LAN participant to
// trusted startup owners. Construction performs observations only. Inventory
// must check complete backend coverage and exact allowed consumers: nil LAN
// requires the entire owned gate namespace to be absent, including orphans.
// These callbacks come from owners, never request/config capability flags.
type NetworkPolicyAssemblyOptions struct {
	// Mode is frozen by the concrete startup participant, including while
	// proving absence after retirement. It never grants a consumer or effect.
	Mode           string
	Provider       *netidentity.Provider
	Binding        *LANPolicyReceiptBinding
	InventoryCheck func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error
}

type networkPolicyIdentity struct {
	mode        string
	value       netidentity.Identity
	provider    *netidentity.Provider
	withCurrent func(context.Context, func(context.Context, netidentity.Identity) error) error
}

func (n *networkPolicyIdentity) acceptsMode(mode string) bool {
	if n == nil {
		return false
	}
	if n.mode == LANPolicyManagedListDirectMode {
		return lanPolicyDirectMode(mode)
	}
	if n.mode == LANPolicyManagedListMode {
		return mode == "" || lanPolicyDirectMode(mode)
	}
	return mode == n.mode
}

func (n *networkPolicyIdentity) inventoryMode(lan *LANPolicyRuntimePlan) string {
	if (n.mode == LANPolicyManagedListDirectMode || n.mode == LANPolicyManagedListMode) && lan != nil {
		return lan.Mode
	}
	return n.mode
}

func (n *networkPolicyIdentity) use(ctx context.Context, use func(context.Context) error) error {
	if n == nil || n.value.Validate() != nil || n.withCurrent == nil || ctx == nil || use == nil {
		return ErrNetworkPolicyIdentity
	}
	return n.withCurrent(ctx, func(c context.Context, got netidentity.Identity) error {
		if got != n.value || got.Validate() != nil || c.Err() != nil {
			return errors.Join(ErrNetworkPolicyIdentity, c.Err())
		}
		return use(c)
	})
}

func (n *networkPolicyIdentity) check(ctx context.Context) error {
	return n.use(ctx, func(c context.Context) error { return c.Err() })
}

// NewNetworkPolicyAdapter returns the concrete existing Manager participant.
// The caller registers it on the SAME Manager. This does not create a worker,
// issue NFQ launch authority, or turn the temporary NFQ assembly into an active
// process owner. Active NFQ requires its separately approved durable lifecycle.
func NewNetworkPolicyAdapter(ctx context.Context, options NetworkPolicyAssemblyOptions) (*NetworkPolicyAdapter, error) {
	if options.Provider == nil || !networkPolicyAssemblyOptionsValid(options) {
		return nil, ErrNetworkPolicyIdentity
	}
	identity, err := options.Provider.Observe(ctx)
	if err != nil {
		return nil, errors.Join(ErrNetworkPolicyIdentity, err)
	}
	return newNetworkPolicyIdentityAdapter(options, &networkPolicyIdentity{mode: options.Mode, value: identity, provider: options.Provider, withCurrent: options.Provider.WithCurrent})
}

func networkPolicyAssemblyOptionsValid(options NetworkPolicyAssemblyOptions) bool {
	b := options.Binding
	return (options.Mode == "" || lanPolicyDirectMode(options.Mode) || options.Mode == LANPolicyManagedListDirectMode || options.Mode == LANPolicyManagedListMode) && b != nil && b.Runtime != nil && b.Runtime.Runner != nil && b.Runtime.IP != "" && b.Runtime.IPTables != "" && b.Runtime.IP6Tables != "" &&
		b.Runtime.ScopeCheck != nil && b.ApplyGuard != nil && b.CleanupGuard != nil && b.RetireCheck != nil && options.InventoryCheck != nil
}

func newNetworkPolicyIdentityAdapter(options NetworkPolicyAssemblyOptions, identity *networkPolicyIdentity) (*NetworkPolicyAdapter, error) {
	if !networkPolicyAssemblyOptionsValid(options) || identity == nil || identity.mode != options.Mode || identity.value.Validate() != nil || identity.withCurrent == nil {
		return nil, ErrNetworkPolicyIdentity
	}
	// Freeze the descriptor and callbacks; caller changes cannot replace the
	// retained identity or bypass a boundary by editing the original binding.
	binding := *options.Binding
	runtime := *binding.Runtime
	physical, apply, cleanup, retire := runtime.ScopeCheck, binding.ApplyGuard, binding.CleanupGuard, binding.RetireCheck
	inventory := options.InventoryCheck
	boundary := func(ctx context.Context, p *LANPolicyRuntimePlan, stage string, check func(context.Context) error) error {
		if options.Mode == LANPolicyManagedListMode {
			// Full retained WG/tool/control owners must run outside the held
			// Provider/collector leaf. The SAME identity brackets each actual
			// command and complete inventory, with explicit outer bookends.
			if err := identity.check(ctx); err != nil {
				return lanPolicyPreflightAt("boundary-identity", err)
			}
			if p != nil && (ValidateLANPolicyRuntime(p) != nil || !identity.acceptsMode(p.Mode)) {
				return lanPolicyPreflightAt("boundary-plan", ErrLANPolicyRuntime)
			}
			if err := check(ctx); err != nil {
				return lanPolicyPreflightAt(stage, err)
			}
			if err := inventory(ctx, identity.value, CloneLANPolicyRuntime(p)); err != nil {
				return lanPolicyPreflightAt("boundary-inventory", err)
			}
			return lanPolicyPreflightAt("boundary-identity", identity.check(ctx))
		}
		return lanPolicyPreflightAt("boundary-identity", identity.use(ctx, func(c context.Context) error {
			if p != nil && (ValidateLANPolicyRuntime(p) != nil || !identity.acceptsMode(p.Mode)) {
				return lanPolicyPreflightAt("boundary-plan", ErrLANPolicyRuntime)
			}
			if err := check(c); err != nil {
				return lanPolicyPreflightAt(stage, err)
			}
			return lanPolicyPreflightAt("boundary-inventory", inventory(c, identity.value, CloneLANPolicyRuntime(p)))
		}))
	}
	runtime.Runner = networkPolicyIdentityRunner{identity: identity, runner: runtime.Runner}
	runtime.ScopeCheck = func(ctx context.Context, p *LANPolicyRuntimePlan) error {
		return boundary(ctx, p, "boundary-physical", func(c context.Context) error { return physical(c, CloneLANPolicyRuntime(p)) })
	}
	binding.Runtime = &runtime
	binding.ApplyGuard = func(ctx context.Context, p *LANPolicyRuntimePlan, effect LANPolicyEffect) error {
		return boundary(ctx, p, "boundary-apply", func(c context.Context) error { return apply(c, CloneLANPolicyRuntime(p), cloneLANPolicyEffect(effect)) })
	}
	binding.CleanupGuard = func(ctx context.Context, p *LANPolicyRuntimePlan, effect LANPolicyEffect) error {
		return boundary(ctx, p, "boundary-cleanup", func(c context.Context) error {
			return cleanup(c, CloneLANPolicyRuntime(p), cloneLANPolicyEffect(effect))
		})
	}
	binding.RetireCheck = func(ctx context.Context, p *LANPolicyRuntimePlan) error {
		return boundary(ctx, p, "boundary-retire", func(c context.Context) error { return retire(c, CloneLANPolicyRuntime(p)) })
	}
	return &NetworkPolicyAdapter{Binding: &binding, identity: identity, InventoryCheck: func(ctx context.Context) error {
		return boundary(ctx, nil, "boundary-inventory", func(c context.Context) error { return c.Err() })
	}}, nil
}

// Every actual read/effect remains inside the same concrete provider's thread
// bracket. Its short cap applies to one CLI operation, never the whole Apply
// or an active process lifetime. The original admitted runner is retained.
type networkPolicyIdentityRunner struct {
	identity *networkPolicyIdentity
	runner   NFQWS2Runner
}

func (r networkPolicyIdentityRunner) Run(ctx context.Context, name string, args ...string) (output []byte, result error) {
	if r.runner == nil {
		return nil, ErrNetworkPolicyIdentity
	}
	err := r.identity.use(ctx, func(c context.Context) error {
		output, result = r.runner.Run(c, name, args...)
		return result
	})
	return output, err
}

func (r networkPolicyIdentityRunner) RunBounded(ctx context.Context, name string, limit int, args ...string) (output []byte, result error) {
	bounded, ok := r.runner.(backendInventoryBoundedRunner)
	if !ok {
		return nil, errBackendInventory
	}
	err := r.identity.use(ctx, func(c context.Context) error {
		output, result = bounded.RunBounded(c, name, limit, args...)
		return result
	})
	return output, err
}

// NetworkIdentity is detached observation metadata, never a writer grant.
func (a *NetworkPolicyAdapter) NetworkIdentity() (netidentity.Identity, bool) {
	if a == nil || a.identity == nil {
		return netidentity.Identity{}, false
	}
	return a.identity.value, true
}

func (a *NetworkPolicyAdapter) gateFor(p Plan) (*networkPolicyGateState, error) {
	state, err := networkPolicyGateFor(p)
	if err != nil || a.identity == nil {
		return state, err
	}
	identity := a.identity.value
	if identity.Validate() != nil || !a.identity.acceptsMode(state.LAN.Mode) {
		return nil, ErrNetworkPolicyIdentity
	}
	state.Schema, state.NetworkIdentity = 2, &identity
	return state, nil
}

func (a *NetworkPolicyAdapter) gateIdentityMatches(state *networkPolicyGateState) bool {
	if state == nil {
		return false
	}
	if a.identity == nil {
		return state.Schema == 1 && state.NetworkIdentity == nil
	}
	return state.Schema == 2 && state.LAN != nil && a.identity.acceptsMode(state.LAN.Mode) && state.NetworkIdentity != nil && state.NetworkIdentity.Validate() == nil && *state.NetworkIdentity == a.identity.value
}

func (m *Manager) executionNetworkIdentity() *networkPolicyIdentity {
	adapter, _ := m.adapter(NetworkPolicyAdapterID)
	gate, ok := adapter.(*NetworkPolicyAdapter)
	if !ok || gate == nil {
		return nil
	}
	return gate.identity
}

// Typed Manager resources require the SAME full typed compiler identity.
// The owner's validator independently cross-checks proc's canonical old field;
// reviewed singleton requires that field empty. Neither old strings nor saved
// identity metadata issue a provider, a resource or launch authority.
func nfqwsExecutionNetworkMatches(identity netidentity.Identity, spec NFQWSScopedSpec) error {
	if identity.Validate() != nil || spec.NetworkIdentity == nil || *spec.NetworkIdentity != identity || !nfqwsScopedSpecNetworkValid(spec) {
		return ErrNetworkPolicyIdentity
	}
	return nil
}
