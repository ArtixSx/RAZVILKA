package dataplane

import (
	"bytes"
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

func (r wgExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, ErrWGOperationOwner
	}
	rawOwner, rawMaterial := ctx.Value(wgOperationOwnerKey{}), ctx.Value(wgOperationMaterialKey{})
	if rawOwner == nil && rawMaterial == nil {
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
	// This preserves the existing path-based execution ABI. It is NOT the
	// StartupTools held-fd/tool+loader producer and claims no pinned native
	// evidence. CORE must compose that source before opening stock List mode.
	cmd := exec.CommandContext(ctx, name, args...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	start := func() error {
		if cleanup {
			return o.material.control.WithCleanupStart(ctx, o.material.cleanup, cmd.Start)
		}
		return o.material.control.WithStart(ctx, cmd.Start)
	}
	startErr := r.withCommandStart(ctx, o, name, args, start)
	if cmd.Process == nil {
		return output.Bytes(), startErr
	}
	// Exactly one Wait, outside control/receipt admission. Both close barriers
	// retain this owner until cancellation has killed and Wait has joined it.
	waitErr := cmd.Wait()
	closingErr := o.check(ctx, cleanup)
	if startErr != nil || waitErr != nil {
		return output.Bytes(), errors.Join(startErr, waitErr, closingErr)
	}
	if cleanup && closingErr != nil {
		return output.Bytes(), closingErr // Unknown closing cleanup keeps prerequisites/fence.
	}
	if closingErr != nil && !cleanup {
		o.mu.Lock()
		o.revoked = closingErr
		o.mu.Unlock()
	}
	// Preserve the actual successful command ACK for COMMON/causal cleanup.
	// A closing forward revocation refuses the next command/phase.
	return output.Bytes(), nil
}

func (r wgExecRunner) withCommandStart(ctx context.Context, o *wgOperationOwner, name string, args []string, start func() error) error {
	a := o.adapter
	if name == "" || !validPolicyEffectArgs(args) || name != a.ip() && name != a.wg() && name != a.wgQuick() && name != a.wgNetworkFirewallBinary(false) && name != a.wgNetworkFirewallBinary(true) {
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
