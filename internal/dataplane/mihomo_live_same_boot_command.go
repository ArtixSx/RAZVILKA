package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Separate from the warm issuer and from the closed cold read ABI. Only this
// package's exact per-call owner can implement the final Start admission.
type MihomoSameBootCommandAdmission interface {
	WithStart(context.Context, string, []string, string, func() error) error
	mihomoSameBootCommandAdmission()
}
type mihomoSameBootProtectedRunner interface {
	RunMihomoSameBootCleanup(context.Context, MihomoSameBootCommandAdmission, string, ...string) ([]byte, error)
}
type mihomoSameBootCommandKey struct{}
type mihomoSameBootCommand struct {
	mu           sync.Mutex
	self         *mihomoSameBootCommand
	owner        *mihomoSameBootCleanup
	name, review string
	args         []string
	open, used   bool
}

func (*mihomoSameBootCommand) mihomoSameBootCommandAdmission() {}

// The sealed object is a comparison only. Actual Start still needs its SAME
// live control/Gate cleanup barrier, and a consumed token cannot start twice.
func OriginalMihomoSameBootCommand(ctx context.Context, admission MihomoSameBootCommandAdmission, name string, args []string, review string) bool {
	c, ok := admission.(*mihomoSameBootCommand)
	if !ok || c == nil || c.self != c || ctx == nil || ctx.Value(mihomoSameBootCommandKey{}) != c {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.matches(ctx, name, args, review)
}
func (c *mihomoSameBootCommand) matches(ctx context.Context, name string, args []string, review string) bool {
	return c.open && !c.used && ctx.Err() == nil && c.owner != nil && c.owner.self == c.owner && !c.owner.effectsClosed && !c.owner.effectUnknown && c.owner.control != nil && c.owner.cleanup != nil && c.name == name && c.review == review && validPlanDigest(review) && slices.Equal(c.args, args)
}
func (c *mihomoSameBootCommand) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if c == nil || c.self != c || ctx == nil || ctx.Value(mihomoSameBootCommandKey{}) != c {
		return ErrMihomoLiveRetirement
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if begin == nil || !c.matches(ctx, name, args, review) {
		return ErrMihomoLiveRetirement
	}
	c.used = true
	// No tool/provider/private-journal reentry under the native held-FD gate.
	// All expensive original input/process checks bracket the entire Run.
	return c.owner.control.WithCleanupStart(ctx, c.owner.cleanup, begin)
}

type mihomoSameBootCleanup struct {
	planRecords                  []*mihomoColdRecord
	planMissing                  []string
	sidecar                      *mihomoSameBootSidecar
	policy                       *mihomoSameBootPolicy
	static                       *mihomoSameBootStatic
	controlRoot                  string
	effectsClosed, effectUnknown bool
	self                         *mihomoSameBootCleanup
	inputs                       *mihomoSameBootInputs
	read                         *mihomoColdReadRunner
	control                      *operationgate.ControlEpochReview
	cleanup                      *operationgate.ExclusiveCleanupReview
}

func (o *mihomoSameBootCleanup) current(ctx context.Context) error {
	defer mihomoSameBootNativeOwnerTiming(o, "source-current")()
	if o == nil || o.self != o || o.inputs == nil || o.read == nil || o.read.original == nil || o.read.proxy == nil || o.control == nil || o.cleanup == nil || !filepath.IsAbs(o.controlRoot) || filepath.Clean(o.controlRoot) != o.controlRoot || !o.control.MatchesControlRoot(o.controlRoot) || !o.sourceCoordinatesCurrent() || o.effectUnknown {
		return ErrMihomoLiveRetirement
	}
	if err := o.inputs.current(o.inputs.ctx); err != nil {
		return err
	}
	if err := o.planInputsCurrent(); err != nil {
		return err
	}
	if o.policy != nil && o.policy.closeErr != nil {
		return o.policy.closeErr
	}
	if o.static != nil {
		if !o.effectsClosed {
			if err := o.static.current(); err != nil {
				return err
			}
		} else if o.static.closeErr != nil {
			return o.static.closeErr
		}
	}
	if err := errors.Join(o.read.current(ctx), o.control.CurrentForCleanupOperation(ctx, o.cleanup)); err != nil {
		return err
	}
	identity, err := observeMihomoLiveColdProcesses(ctx, o.read.tools.Provider, o.inputs.definition, o.inputs.statePath)
	if err != nil || identity != o.inputs.definition.NetworkIdentity {
		return errors.Join(ErrMihomoLiveRetirement, err)
	}
	return errors.Join(o.inputs.current(o.inputs.ctx), o.read.current(ctx), o.control.CurrentForCleanupOperation(ctx, o.cleanup))
}

func (o *mihomoSameBootCleanup) absent(ctx context.Context) (netidentity.Identity, error) {
	defer mihomoSameBootNativeOwnerTiming(o, "absence")()
	if err := o.current(ctx); err != nil {
		return netidentity.Identity{}, err
	}
	proof, err := proxyInactivePlatformProof()
	if err != nil {
		return netidentity.Identity{}, err
	}
	if err := observeBootRetirement(ctx, o.read.proxy, proof); err != nil {
		return netidentity.Identity{}, err
	}
	if err := o.current(ctx); err != nil {
		return netidentity.Identity{}, err
	}
	return o.inputs.definition.NetworkIdentity, nil
}

func (o *mihomoSameBootCleanup) Run(ctx context.Context, name string, args ...string) (data []byte, resultErr error) {
	if err := o.current(ctx); err != nil {
		return nil, err
	}
	base, ok := o.read.source.(mihomoSameBootProtectedRunner)
	if !ok {
		return nil, ErrMihomoLiveRetirement
	}
	if !mihomoLiveEffectCommand(name == o.read.tools.IP, args) {
		return o.read.Run(ctx, name, args...)
	}
	if o.effectsClosed {
		return nil, ErrMihomoLiveRetirement
	}
	allowed, err := o.deleteCommand(ctx, name, args)
	if err != nil || !allowed {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	call := &mihomoSameBootCommand{owner: o, name: name, args: slices.Clone(args), review: o.read.tools.ReviewSHA256, open: true}
	call.self = call
	defer func() { call.mu.Lock(); call.open = false; call.mu.Unlock() }()
	data, resultErr = base.RunMihomoSameBootCleanup(context.WithValue(ctx, mihomoSameBootCommandKey{}, call), call, name, args...)
	call.mu.Lock()
	used := call.used
	call.mu.Unlock()
	if resultErr != nil && used {
		o.effectUnknown = true
	}
	if closing := o.current(ctx); closing != nil {
		data = nil
		resultErr = errors.Join(resultErr, closing)
	}
	return data, resultErr
}

// The current receipt cleanup chooses whether a deletion is owned. This
// additional closed ABI independently limits every effect to the immutable
// original policy; it cannot add/flush/replace or select an arbitrary table.
func (o *mihomoSameBootCleanup) deleteCommand(ctx context.Context, name string, args []string) (bool, error) {
	state := o.inputs.definition.Policy
	if name == o.read.tools.IP {
		plain := args
		if len(plain) > 0 && plain[0] == "-6" {
			plain = plain[1:]
		}
		if len(plain) < 2 || plain[1] != "del" || plain[0] != "rule" && plain[0] != "route" {
			return false, nil
		}
		rules, err := kernelRulesForPolicy(state)
		if err != nil {
			return false, err
		}
		for _, r := range rules {
			if slices.Equal(args, kernelRuleArgs("del", r)) {
				return true, nil
			}
		}
		for _, family := range []int{4, 6} {
			actual, err := recordedDefaultRoute(ctx, o.read, o.read.tools.IP, state, family)
			if err != nil {
				return false, err
			}
			if len(actual) > 0 && slices.Equal(args, actual) {
				return true, nil
			}
		}
		return false, nil
	}
	if name != o.read.tools.IPTables && name != o.read.ip6 {
		return false, nil
	}
	for _, table := range proxyFirewallTables(state) {
		if table.v6 != (name == o.read.ip6) || len(args) < 4 || args[0] != "-t" || args[1] != table.table {
			continue
		}
		if len(args) == 4 && args[2] == "-X" && args[3] == table.chain {
			return true, nil
		}
		if args[2] != "-D" {
			continue
		}
		var candidates [][]string
		if args[3] == table.chain {
			candidates = table.rules
		} else if args[3] == table.parent {
			candidates = table.jumps
		} else {
			continue
		}
		key := proxyFirewallRuleKey(args[4:])
		if strings.HasPrefix(key, "!") {
			return false, nil
		}
		for _, rule := range candidates {
			if key == proxyFirewallRuleKey(rule) {
				return true, nil
			}
		}
	}
	return false, nil
}

// RuntimeInactivitySourceReview.settings belongs to the original DNS manager,
// not the configuration Store. Its genuine CheckCurrent separately verifies
// that DNS association. Configuration is pinned by the original five-set and
// input FD; equating these distinct paths refuses every correctly wired CLI.
func (o *mihomoSameBootCleanup) sourceCoordinatesCurrent() bool {
	if o == nil || o.inputs == nil || o.read == nil || o.read.original == nil {
		return false
	}
	r := o.read.original
	return r.self == r && r.manager != nil && r.root == o.inputs.statePath && r.manager.StateRoot == o.inputs.statePath
}
