package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Issued for the actual registered LAN participant and its original control
// operation, before effects. It has no command, runner or callback factory.
type LANPolicyCommandAdmission struct {
	self       *LANPolicyCommandAdmission
	manager    *Manager
	gate       *NetworkPolicyAdapter
	binding    *LANPolicyReceiptBinding
	runtime    *LANPolicyRuntime
	frozen     LANPolicyRuntime
	control    *operationgate.ControlEpochReview
	cleanup    *operationgate.ExclusiveCleanupReview
	review     string
	generation uint64
	closed     atomic.Bool
}

func (m *Manager) ReviewLANPolicyCommandAdmission(ctx context.Context, gate *NetworkPolicyAdapter, inventory *BackendInventory, control *operationgate.ControlEpochReview) (*LANPolicyCommandAdmission, error) {
	if m == nil || ctx == nil || control == nil || gate == nil || inventory == nil || inventory.reader.CheckTools == nil || gate.identity == nil || gate.identity.provider == nil || gate.identity.provider != inventory.reader.Provider || gate.Binding == nil || gate.Binding.Runtime == nil || !lanPolicyHash(inventory.review) {
		return nil, ErrLANPolicyRuntime
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrLANPolicyRuntime
	}
	if m.retainedNFQOwner() != nil || m.HasPendingManagedNFQWS() {
		return nil, ErrNetworkPolicyReplacement
	}
	if err := control.Current(ctx); err != nil {
		return nil, err
	}
	if err := inventory.reader.CheckTools(ctx, backendInventoryScope{Network: gate.identity.value, ToolReviewID: inventory.review}); err != nil {
		return nil, err
	}
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, err
	}
	m.registryMu.RLock()
	registered, generation := m.Adapters[NetworkPolicyAdapterID], m.registryGeneration
	m.registryMu.RUnlock()
	if registered != gate || gate.StateRoot != filepath.Join(m.StateRoot, NetworkPolicyAdapterID) || gate.Binding.Runtime.IPTables != inventory.reader.IPTables || gate.Binding.Runtime.IP6Tables != inventory.reader.IP6Tables {
		return nil, ErrLANPolicyRuntime
	}
	o := &LANPolicyCommandAdmission{manager: m, gate: gate, binding: gate.Binding, runtime: gate.Binding.Runtime, frozen: *gate.Binding.Runtime, control: control, cleanup: cleanup, review: inventory.review, generation: generation}
	o.self = o
	gate.Binding.commandOwner = o
	return o, nil
}

func (o *LANPolicyCommandAdmission) Close() {
	if o != nil && o.self == o {
		o.closed.Store(true)
	}
}

type lanPolicyCommandCall struct {
	self    *lanPolicyCommandCall
	owner   *LANPolicyCommandAdmission
	binding *LANPolicyReceiptBinding
	plan    PolicyEffectPlan
	root    string
	cleanup bool
	open    atomic.Bool
}
type lanPolicyCommandCallKey struct{}
type lanPolicyCommandRunner struct {
	owner   *LANPolicyCommandAdmission
	binding *LANPolicyReceiptBinding
	plan    PolicyEffectPlan
	root    string
	cleanup bool
	base    NFQWS2Runner
}

func (b *LANPolicyReceiptBinding) bindCommandRunner(c *lanPolicyReceiptCall, root string, cleanup bool) {
	if b.commandOwner != nil {
		c.runtime.Runner = lanPolicyCommandRunner{owner: b.commandOwner, binding: b, plan: c.mixed, root: root, cleanup: cleanup, base: c.runtime.Runner}
	}
}

func (r lanPolicyCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	c := &lanPolicyCommandCall{owner: r.owner, binding: r.binding, plan: r.plan, root: r.root, cleanup: r.cleanup}
	c.self = c
	c.open.Store(true)
	defer c.open.Store(false)
	return r.base.Run(context.WithValue(ctx, lanPolicyCommandCallKey{}, c), name, args...)
}

// WithLANPolicyCommandStart consumes only an actual original LAN COMMON RPC.
// false means no LAN issuer; a present invalid issuer is always handled/refused.
// All Scope/Store/tools/NI/kernel checks precede this final native tool leaf.
func WithLANPolicyCommandStart(ctx context.Context, name string, args []string, reviewSHA string, begin func() error) (bool, error) {
	if ctx == nil || ctx.Err() != nil || begin == nil {
		return true, ErrLANPolicyRuntime
	}
	raw := ctx.Value(lanPolicyCommandCallKey{})
	if raw == nil {
		return false, nil
	}
	c, ok := raw.(*lanPolicyCommandCall)
	if !ok || c == nil || c.self != c || !c.open.Load() || c.owner == nil {
		return true, ErrLANPolicyRuntime
	}
	o := c.owner
	current := func() error {
		if o.self != o || o.closed.Load() || !c.open.Load() || o.manager == nil || o.gate == nil || o.binding != c.binding || o.gate.Binding != o.binding || o.binding.commandOwner != o || o.binding.Runtime != o.runtime || reviewSHA != o.review || !sameNetworkPolicyDependency(o.runtime.Runner, o.frozen.Runner) || [3]string{o.runtime.IP, o.runtime.IPTables, o.runtime.IP6Tables} != [3]string{o.frozen.IP, o.frozen.IPTables, o.frozen.IP6Tables} {
			return ErrLANPolicyRuntime
		}
		o.manager.registryMu.RLock()
		actual, generation := o.manager.Adapters[NetworkPolicyAdapterID], o.manager.registryGeneration
		o.manager.registryMu.RUnlock()
		if actual != o.gate || generation != o.generation || o.gate.StateRoot != filepath.Join(o.manager.StateRoot, NetworkPolicyAdapterID) {
			return ErrLANPolicyRuntime
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return true, err
	}
	i, err := observePolicyEffectCommandInvocation(ctx, c.plan, c.root, name, args)
	if err != nil || i.cleanup != c.cleanup {
		return true, errors.Join(ErrLANPolicyRuntime, err)
	}
	if i.tools != (PolicyEffectTools{IP: o.frozen.IP, IPTables: o.frozen.IPTables, IP6Tables: o.frozen.IP6Tables}) {
		return true, ErrLANPolicyRuntime
	}
	cleanup := o.cleanup
	if c.cleanup {
		if raw := ctx.Value(nfqwsRetainedOperationKey{}); raw != nil {
			op, ok := raw.(*nfqwsRetainedOperation)
			if !ok || op == nil || op.self != op || !op.open.Load() || op.forward || op.owner == nil || op.owner.self != op.owner || op.owner.scope.manager != o.manager || op.owner.execution.gate != o.gate || op.owner.execution.material.control != o.control || op.cleanup == nil {
				return true, ErrLANPolicyRuntime
			}
			cleanup = op.cleanup
		}
	}
	err = i.withStart(ctx, func() error {
		if err := current(); err != nil {
			return err
		}
		if c.cleanup {
			return o.control.WithCleanupStart(ctx, cleanup, begin)
		}
		return o.control.WithStart(ctx, begin)
	})
	return true, errors.Join(err, current())
}
