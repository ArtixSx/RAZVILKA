package dataplane

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
)

type wgNativeInvocationKey struct{}
type wgNativeInvocation struct {
	self       *wgNativeInvocation
	mu         sync.Mutex
	open, used bool
	adapter    *WARPWireGuardAdapter
	name       string
	args       []string
}

// Called only by the existing private a.run. Direct Runner.Run cannot issue a
// native mutation token, and a saved context cannot reuse it after Run returns.
func (a *WARPWireGuardAdapter) runWGCommand(ctx context.Context, name string, args []string) ([]byte, error) {
	i := &wgNativeInvocation{open: true, adapter: a, name: name, args: slices.Clone(args)}
	i.self = i
	defer func() { i.mu.Lock(); i.open = false; i.mu.Unlock() }()
	return (wgNamedForwardRunner{base: a.Runner}).Run(context.WithValue(ctx, wgNativeInvocationKey{}, i), name, args...)
}

type wgPolicyCommandKey struct{}
type wgPolicyCommand struct {
	adapter  *WARPWireGuardAdapter
	ref      warpWGPolicyReference
	compiled wgNetworkEffects
}
type wgPolicyCommandRunner struct {
	base    NFQWS2Runner
	command wgPolicyCommand
}

func (r wgPolicyCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.base.Run(context.WithValue(ctx, wgPolicyCommandKey{}, r.command), name, args...)
}

// wgExecRunner is the default existing WG/AWG runner. The legacy route path
// remains compatible. Once actual WG material is attached, a missing original
// Manager owner is an error; it cannot fall back to an unadmitted process.
type wgExecRunner struct{ adapter *WARPWireGuardAdapter }

type wgToolInvocationKey struct{}
type wgToolInvocation struct {
	self         *wgToolInvocation
	mu           sync.Mutex
	open, used   bool
	owner        *wgOperationOwner
	name, review string
	args         []string
}

func (*wgToolInvocation) wgCommandAdmission() {}
func (i *wgToolInvocation) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if i == nil || i.self != i || ctx == nil || ctx.Value(wgToolInvocationKey{}) != i || begin == nil {
		return ErrWGOperationOwner
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.open || i.used || i.name != name || i.review != review || !slices.Equal(i.args, args) {
		return ErrWGOperationOwner
	}
	i.used = true
	return i.owner.withToolStart(ctx, name, args, review, begin)
}

func (r wgExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, ErrWGOperationOwner
	}
	rawOwner, rawMaterial := ctx.Value(wgOperationOwnerKey{}), ctx.Value(wgOperationMaterialKey{})
	if rawOwner == nil && rawMaterial == nil {
		if r.adapter != nil && r.adapter.wgCommandTools != nil {
			return nil, ErrWGOperationOwner
		}
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	o, owned := rawOwner.(*wgOperationOwner)
	m, material := rawMaterial.(*WGOperationMaterial)
	if !owned || !material || m == nil || o == nil || o.self != o || o.material != m || o.scope == nil || o.adapter != r.adapter {
		return nil, ErrWGOperationOwner
	}
	o.material.barrier.RLock()
	defer o.material.barrier.RUnlock()
	o.scope.startMu.RLock()
	defer o.scope.startMu.RUnlock()
	cleanup := wgOperationCleanup(ctx)
	if err := o.check(ctx, cleanup); err != nil {
		return nil, err
	}
	tools := o.adapter.wgCommandTools
	if !tools.valid(o.adapter.ID()) {
		return nil, ErrWGOperationOwner
	}
	// The concrete original StartupTools source owns held-fd Start, output
	// bounds, lifetime cancellation, WaitDelay and exactly one Wait. Both WG
	// barriers retain this operation until the source has joined that Wait.
	invocation := &wgToolInvocation{open: true, owner: o, name: name, review: tools.ReviewSHA256, args: slices.Clone(args)}
	invocation.self = invocation
	ctx = context.WithValue(ctx, wgToolInvocationKey{}, invocation)
	defer func() { invocation.mu.Lock(); invocation.open = false; invocation.mu.Unlock() }()
	output, runErr := tools.Runner.RunWG(ctx, invocation, name, args...)
	closingErr := o.check(ctx, cleanup)
	if runErr != nil {
		return output, errors.Join(runErr, closingErr)
	}
	if cleanup && closingErr != nil {
		return output, closingErr // Unknown closing cleanup keeps prerequisites/fence.
	}
	if closingErr != nil && !cleanup {
		o.mu.Lock()
		o.revoked = closingErr
		o.mu.Unlock()
	}
	// Preserve the actual successful command ACK for COMMON/causal cleanup.
	// A closing forward revocation refuses the next command/phase.
	return output, nil
}

// withToolStart is called only by the one-use original RPC carrier under the
// retained source's tool/Provider
// bracket. Compare original pointers, frozen fields and COMMON/file ownership;
// full guards, Store/Scope, NI and tool checks belong outside this leaf.
func (o *wgOperationOwner) withToolStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if o == nil || o.self != o || ctx == nil || ctx.Value(wgOperationOwnerKey{}) != o || ctx.Value(wgOperationMaterialKey{}) != o.material || begin == nil || o.scope == nil || o.material == nil || !o.sameAdapter() || !o.adapter.wgCommandTools.valid(o.adapter.ID()) || review != o.adapter.wgCommandTools.ReviewSHA256 {
		return ErrWGOperationOwner
	}
	cleanup := wgOperationCleanup(ctx)
	o.material.mu.Lock()
	closed := o.material.closed
	o.material.mu.Unlock()
	if closed || o.material.self != o.material || o.material.manager.StateRoot != o.material.root {
		return ErrWGOperationOwner
	}
	o.scope.mu.Lock()
	err := o.scope.checkOriginalOwner(ctx, nil, !cleanup, cleanup)
	o.scope.mu.Unlock()
	if err != nil {
		return errors.Join(ErrWGOperationOwner, err)
	}
	if o.scope.wgRecords == nil {
		return ErrExecutionJournal
	}
	// A failed second journal publication keeps both original authored FDs.
	// Their phase images can differ for physical cleanup only; a missing or
	// replaced inode still refuses. Forward Start requires the complete pair.
	if err := o.scope.wgRecords.current(ctx, !cleanup); err != nil {
		return err
	}
	if !cleanup {
		o.mu.Lock()
		err = o.revoked
		o.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return (wgExecRunner{adapter: o.adapter}).withCommandStart(ctx, o, name, args, func() error {
		// Retain prerequisites even when a started mutation has no successful
		// command ACK. Only Manager's genuine rollback/inactivity can join it.
		if !wgReadOnlyCommand(o.adapter, name, args) {
			o.mutationAttempted.Store(true)
		}
		if cleanup {
			cap := o.material.cleanup
			if op, ok := ctx.Value(wgRetainedOperationKey{}).(*wgRetainedOperation); ok && op != nil && op.self == op && op.open.Load() && op.owner != nil && op.owner.scope == o.scope {
				cap = op.cleanup
			}
			return o.material.control.WithCleanupStart(ctx, cap, begin)
		}
		return o.material.control.WithStart(ctx, begin)
	})
}

func (r wgExecRunner) withCommandStart(ctx context.Context, o *wgOperationOwner, name string, args []string, start func() error) error {
	a := o.adapter
	companionRead := a.wgCommandTools != nil && (name == a.wgCommandTools.WG || name == a.wgCommandTools.AWG) && len(args) == 3 && args[0] == "show" && args[1] == "all" && args[2] == "public-key"
	if name == "" || !validPolicyEffectArgs(args) || name != a.ip() && name != a.wg() && name != a.wgNetworkFirewallBinary(false) && name != a.wgNetworkFirewallBinary(true) && !companionRead {
		return ErrWGOperationOwner
	}
	if i, ok := ctx.Value(wgNativeInvocationKey{}).(*wgNativeInvocation); ok {
		if i == nil {
			return ErrWGOperationOwner
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.self != i || !i.open || i.used || i.adapter == nil || i.adapter.ID() != a.ID() || !sameNetworkPolicyDependency(i.adapter.Runner, a.Runner) || i.name != name || !slices.Equal(i.args, args) {
			return ErrWGOperationOwner
		}
		i.used = true
		return start()
	}
	if i, ok := ctx.Value(policyEffectCommandInvocationKey{}).(*policyEffectCommandInvocation); ok {
		proof, present := ctx.Value(wgPolicyCommandKey{}).(wgPolicyCommand)
		if !present || proof.adapter != a || i == nil || i.session == nil || a.validWGPolicyReference(proof.ref) != nil || !reflect.DeepEqual(proof.ref.FrozenLAN, o.material.lan) || !reflect.DeepEqual(i.session.plan, proof.compiled.plan) {
			return ErrWGOperationOwner
		}
		expected, err := a.compileWGNetworkEffects(proof.ref)
		if err != nil || !reflect.DeepEqual(expected.plan, proof.compiled.plan) {
			return errors.Join(ErrWGOperationOwner, err)
		}
		root := i.session.path
		if root != a.wgPolicyGenerationRoot(proof.ref, "") && root != a.wgPolicyGenerationRoot(proof.ref, filepath.Join(o.scope.root, a.ID())) {
			return ErrWGOperationOwner
		}
		invocation, err := observePolicyEffectCommandInvocation(ctx, proof.compiled.plan, i.session.path, name, args)
		if err != nil {
			return err
		}
		if invocation.cleanup && !wgOperationCleanup(ctx) {
			return ErrWGOperationOwner
		}
		return invocation.withStart(ctx, start)
	}
	// Existing forwarding/readback helpers invoke Runner directly. Only these
	// read-only forms can omit a private native/COMMON mutation invocation.
	if wgReadOnlyCommand(a, name, args) {
		return start()
	}
	return ErrWGOperationOwner
}

func wgReadOnlyCommand(a *WARPWireGuardAdapter, name string, args []string) bool {
	if name == a.wg() {
		return len(args) >= 2 && args[0] == "show"
	}
	if name == a.ip() {
		for len(args) > 0 && strings.HasPrefix(args[0], "-") {
			if !slices.Contains([]string{"-4", "-6", "-N", "-details", "-j", "-d", "-o", "-s"}, args[0]) {
				return false
			}
			args = args[1:]
		}
		return len(args) >= 2 && slices.Contains([]string{"link", "addr", "address", "rule", "route"}, args[0]) && (args[1] == "show" || args[0] == "route" && args[1] == "get")
	}
	if name == a.wgNetworkFirewallBinary(false) || name == a.wgNetworkFirewallBinary(true) {
		if len(args) >= 2 && args[0] == "-t" {
			args = args[2:]
		}
		return len(args) > 0 && (args[0] == "-S" || args[0] == "-C")
	}
	return false
}
