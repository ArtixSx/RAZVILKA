package dataplane

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type mihomoLiveCommandKey struct{}
type mihomoLiveCleanupCommandKey struct{}
type MihomoLiveCommandAdmission interface {
	WithStart(context.Context, string, []string, string, func() error) error
	mihomoLiveCommandAdmission()
}
type mihomoLiveProtectedRunner interface {
	RunMihomoLive(context.Context, MihomoLiveCommandAdmission, string, ...string) ([]byte, error)
	RunMihomoLiveRead(context.Context, string, ...string) ([]byte, error)
}

func (c *mihomoLiveCommand) mihomoLiveCommandAdmission() {}
func (c *mihomoLiveCommand) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if ctx == nil || ctx.Value(mihomoLiveCommandKey{}) != c {
		return errMihomoLiveMaterial
	}
	handled, err := WithMihomoLiveCommandStart(ctx, name, args, review, begin)
	if !handled {
		return errMihomoLiveMaterial
	}
	return err
}

type mihomoLiveCommand struct {
	mu           sync.Mutex
	self         *mihomoLiveCommand
	owner        *mihomoLiveResource
	name, review string
	args         []string
	cleanup      *operationgate.ExclusiveCleanupReview
	open, used   bool
}
type mihomoLiveCommandRunner struct {
	adapter    *MihomoProbeAdapter
	base       NFQWS2Runner
	review     string
	gate       *NetworkPolicyAdapter
	gateRunner NFQWS2Runner
}

func (runner *mihomoLiveCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if runner == nil || runner.adapter == nil || runner.base == nil {
		return nil, errMihomoLiveMaterial
	}
	protected, ok := runner.base.(mihomoLiveProtectedRunner)
	if !ok {
		return nil, errMihomoLiveMaterial
	}
	if runner.gate != nil {
		actual, ok := runner.adapter.liveManager.adapter(NetworkPolicyAdapterID)
		if !ok || actual != runner.gate || runner.gate.Binding == nil || runner.gate.Binding.Runtime == nil || !sameNetworkPolicyDependency(runner.gate.Binding.Runtime.Runner, runner.gateRunner) {
			return nil, errMihomoLiveMaterial
		}
	}
	r, err := runner.adapter.liveResource(ctx)
	if err != nil {
		// The same retained runner is also used by read-only cold/global absence
		// inspection. Without a live call token its original native executor still
		// refuses every effect at its normal admission boundary.
		return protected.RunMihomoLiveRead(ctx, name, args...)
	}
	if r.proxy == nil || r.proxy.Runner != runner || name != r.proxy.ip() && name != r.proxy.IPTables && name != r.proxy.IP6Tables {
		return nil, errMihomoLiveMaterial
	}
	effect := mihomoLiveEffectCommand(name == r.proxy.ip(), args)
	if !effect {
		// The original retained tool source implements a closed read ABI and
		// refuses any unrecognized effect without a command admission token.
		return protected.RunMihomoLiveRead(ctx, name, args...)
	}
	var cleanup *operationgate.ExclusiveCleanupReview
	if actual, ok := ctx.Value(mihomoLiveCleanupCommandKey{}).(*operationgate.ExclusiveCleanupReview); ok {
		cleanup = actual
		err = r.control.CurrentForCleanupOperation(ctx, cleanup)
	} else if transitCleanup, _ := ctx.Value(nodeTransitCleanupKey{}).(bool); transitCleanup {
		// The original temporary transit owns this private cleanup context;
		// its captured SAME-Gate review remains valid after durable Stop.
		cleanup, err = r.nodeTransitCleanupReview(ctx)
	} else if op, ok := ctx.Value(mihomoLiveOperationKey{}).(*mihomoLiveOperation); ok && op != nil && !op.forward {
		cleanup, err = r.cleanupReview(ctx)
	} else {
		err = r.currentBeforeStart(ctx)
	}
	if err != nil {
		return nil, err
	}
	call := &mihomoLiveCommand{owner: r, name: name, args: slices.Clone(args), review: runner.review, cleanup: cleanup, open: true}
	call.self = call
	defer func() { call.mu.Lock(); call.open = false; call.mu.Unlock() }()
	data, err := protected.RunMihomoLive(context.WithValue(ctx, mihomoLiveCommandKey{}, call), call, name, args...)
	if cleanup != nil {
		err = errors.Join(err, r.control.CurrentForCleanupOperation(ctx, cleanup))
	} else {
		err = errors.Join(err, r.currentBeforeStart(ctx))
	}
	return data, err
}

func mihomoLiveEffectCommand(ip bool, args []string) bool {
	if ip {
		for len(args) > 0 && slices.Contains([]string{"-4", "-6", "-N", "-j", "-details", "-o"}, args[0]) {
			args = args[1:]
		}
		return len(args) >= 2 && slices.Contains([]string{"route", "rule"}, args[0]) && slices.Contains([]string{"add", "del", "replace"}, args[1])
	}
	return len(args) >= 3 && args[0] == "-t" && slices.Contains([]string{"-A", "-D", "-I", "-N", "-X", "-L"}, args[2])
}

// Only the original held-FD startup executor calls this final short leaf.
// No token means the caller must continue its pre-existing admission chain.
func WithMihomoLiveCommandStart(ctx context.Context, name string, args []string, review string, begin func() error) (bool, error) {
	if ctx == nil {
		return true, errMihomoLiveMaterial
	}
	raw := ctx.Value(mihomoLiveCommandKey{})
	if raw == nil {
		return false, nil
	}
	c, ok := raw.(*mihomoLiveCommand)
	if !ok || c == nil || c.self != c {
		return true, errMihomoLiveMaterial
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.owner
	if !c.open || c.used || begin == nil || ctx.Err() != nil || r == nil || r.self != r || r.scope == nil || r.adapter == nil || r.control == nil || !r.adapter.RegisteredWith(r.scope.manager) || name != c.name || !slices.Equal(args, c.args) || review != c.review || !validPlanDigest(review) {
		return true, errMihomoLiveMaterial
	}
	c.used = true
	// Expensive source/kernel/COMMON checks occur before the retained tool
	// gate; this leaf must never reenter that gate or Provider.
	if c.cleanup != nil {
		return true, r.control.WithCleanupStart(ctx, c.cleanup, begin)
	}
	return true, r.control.WithStart(ctx, begin)
}
