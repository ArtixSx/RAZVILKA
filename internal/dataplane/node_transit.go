package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var ErrNodeTransitUnavailable = errors.New("owned node transit is unavailable or changed")

const nodeTransitBudget = 10 * time.Second

// NodeTransitSpec is frozen local compiler intent. It is not an HTTP authority
// DTO or cleanup grant. The caller must bind it to the actual runtime, policy
// generation, admitted network and Manager-issued resource registration.
type NodeTransitSpec struct {
	Schema           int        `json:"schema"`
	Engine           string     `json:"engine"`
	BootID           string     `json:"boot_id"`
	PlanID           string     `json:"plan_id"`
	PlanDigest       string     `json:"plan_sha256"`
	NetworkProfile   string     `json:"network_profile"`
	RuntimeID        string     `json:"runtime_id"`
	PolicyGeneration string     `json:"policy_generation"`
	Interface        string     `json:"interface"`
	IfIndex          int        `json:"ifindex"`
	Source           netip.Addr `json:"source"`
	Destination      netip.Addr `json:"destination"`
	Table            int        `json:"table"`
	Priority         int        `json:"priority"`
}

// Inventory is reservation metadata for CORE conflict consumers. A matching
// slot/table/name is never rule ownership. Full typed intent and its receipt
// are required separately.
type NodeTransitOwnershipSpec struct {
	Engine, Interface string
	Table, Priority   int
}

func NodeTransitOwnershipSpecs() []NodeTransitOwnershipSpec {
	owners := PolicyOwnershipSpecs()
	end := 0
	for _, owner := range owners {
		if owner.SharedPriorityEnd > end {
			end = owner.SharedPriorityEnd
		}
	}
	if end < 1 || len(owners) == 0 || len(owners) > 64 || end > (1<<31-1)-len(owners) {
		return nil
	}
	result := make([]NodeTransitOwnershipSpec, len(owners))
	for i, owner := range owners {
		priority := end + i + 1
		if owner.Adapter == "" || !proxyFirewallInterface.MatchString(owner.Interface) || owner.Table < 1 || owner.Table > 252 {
			return nil
		}
		for j, other := range owners {
			if priority >= other.PriorityBase && priority <= other.PriorityEnd || priority == other.EndpointPriority || j != i && (owner.Adapter == other.Adapter || owner.Interface == other.Interface || owner.Table == other.Table) {
				return nil
			}
		}
		result[i] = NodeTransitOwnershipSpec{Engine: owner.Adapter, Interface: owner.Interface, Table: owner.Table, Priority: priority}
	}
	return result
}

func validateNodeTransitSpec(spec NodeTransitSpec) error {
	if spec.Schema != 1 || !kernelBootIDPattern.MatchString(spec.BootID) || !validPlanID(spec.PlanID) || !validPlanDigest(spec.PlanDigest) ||
		!systemprobe.ValidWANProfileID(spec.NetworkProfile) || !validPlanDigest(spec.RuntimeID) || len(spec.PolicyGeneration) != 32 || strings.Trim(spec.PolicyGeneration, "0123456789abcdef") != "" ||
		spec.IfIndex < 1 || spec.IfIndex > 1<<31-1 || !spec.Source.Is4() || spec.Source.Is4In6() || !nodeLANSourceAddress(spec.Source) ||
		!spec.Destination.Is4() || spec.Destination.Is4In6() || !publicfetch.PublicAddress(spec.Destination) {
		return ErrNodeTransitUnavailable
	}
	for _, owner := range NodeTransitOwnershipSpecs() {
		if spec.Engine == owner.Engine && spec.Interface == owner.Interface && spec.Table == owner.Table && spec.Priority == owner.Priority {
			return nil
		}
	}
	return ErrNodeTransitUnavailable
}

func nodeTransitSpecDigest(spec NodeTransitSpec) (string, error) {
	if err := validateNodeTransitSpec(spec); err != nil {
		return "", err
	}
	data, err := json.Marshal(spec)
	if err != nil || len(data) > 4096 {
		return "", ErrNodeTransitUnavailable
	}
	return routeidentity.Hash(append([]byte("node-transit-spec-v1\x00"), data...)), nil
}

// All callbacks are supplied by the trusted local issuer, never persisted
// commands or public DTOs. Registration is mandatory before receipt mutation.
// Cleanup uses its caller's separate authority; cancel detachment cannot renew
// a revoked review because the same context-aware guard remains mandatory.
type nodeTransitRuntime struct {
	runner                         NFQWS2Runner
	ip                             string
	preflight, guard, beforeDelete func(context.Context, NodeTransitSpec) error
	register                       func(context.Context, NodeTransitSpec, string, string) error
}

type nodeTransitLease struct {
	spec    NodeTransitSpec
	plan    PolicyEffectPlan
	digest  string
	root    string
	runtime nodeTransitRuntime
	options nodeTransitOptions
	busy    atomic.Bool
	applied atomic.Bool
	effects atomic.Bool
	unused  atomic.Pointer[nodeTransitBeforeEffectsError]
}

// This is live control-flow evidence for a newly issued root, not a persisted
// receipt, deletion grant or recovery classification. The issuer must never
// offer unused settlement for an older/recovery resource.
type nodeTransitBeforeEffectsError struct {
	cause error
	lease *nodeTransitLease
	root  os.FileInfo
}

func (e *nodeTransitBeforeEffectsError) Error() string {
	return "node transit refused before receipt/effects invocation: " + e.cause.Error()
}

func (e *nodeTransitBeforeEffectsError) Unwrap() error { return e.cause }

func isNodeTransitBeforeEffects(err error) bool {
	var before *nodeTransitBeforeEffectsError
	return errors.As(err, &before) && before != nil && before.lease != nil && before.root != nil && before.cause != nil
}

// Only private local fixtures may replace OS inventory/boot identity.
type nodeTransitOptions struct {
	boot       func() (string, error)
	interfaces func() ([]net.Interface, error)
	addresses  func(net.Interface) ([]net.Addr, error)
	fault      func(string, int) error
}

func newNodeTransitLease(spec NodeTransitSpec, root string, runtime nodeTransitRuntime) (*nodeTransitLease, error) {
	return newNodeTransitLeaseWithOptions(spec, root, runtime, nodeTransitOptions{})
}

func newNodeTransitLeaseWithOptions(spec NodeTransitSpec, root string, runtime nodeTransitRuntime, options nodeTransitOptions) (*nodeTransitLease, error) {
	plan, err := CompileNodeTransit(spec)
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || runtime.runner == nil || runtime.ip == "" || strings.ContainsAny(runtime.ip, "\x00\r\n") ||
		runtime.preflight == nil || runtime.guard == nil || runtime.beforeDelete == nil || runtime.register == nil {
		return nil, errors.Join(ErrNodeTransitUnavailable, err)
	}
	if options.boot == nil {
		options.boot = func() (string, error) { return (&ProxyTunnelAdapter{}).currentBootIdentity() }
	}
	return &nodeTransitLease{spec: spec, plan: plan, digest: plan.Generation, root: root, runtime: runtime, options: options}, nil
}

func (l *nodeTransitLease) identity(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := l.options.boot()
	if err != nil || boot != l.spec.BootID {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	request := nodeRouterHTTPSRequest{Interface: l.spec.Interface, IfIndex: l.spec.IfIndex, Source: l.spec.Source}
	if err := nodeRouterAssignedSource(ctx, request, nodeRouterHTTPSOptions{interfaces: l.options.interfaces, addresses: l.options.addresses}); err != nil {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	return ctx.Err()
}

func (l *nodeTransitLease) guard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.runtime.guard(ctx, l.spec); err != nil {
		return err
	}
	return l.identity(ctx)
}

func (l *nodeTransitLease) effectRuntime() PolicyEffectRuntime {
	return PolicyEffectRuntime{Runner: l.runtime.runner, Tools: PolicyEffectTools{IP: l.runtime.ip},
		Guard: func(ctx context.Context, _ int) error { return l.guard(ctx) },
		Preflight: func(ctx context.Context) error {
			if err := l.runtime.preflight(ctx, l.spec); err != nil {
				return err
			}
			count, err := l.presence(ctx)
			if err != nil || count != 0 {
				return errors.Join(ErrNodeTransitUnavailable, err)
			}
			return l.guard(ctx)
		},
		ExactPresence: func(ctx context.Context, index int) (int, error) {
			if index != 0 {
				return 0, ErrNodeTransitUnavailable
			}
			return l.presence(ctx)
		},
		BeforeDelete: func(ctx context.Context, index int) error {
			if index != 0 {
				return ErrNodeTransitUnavailable
			}
			if err := l.runtime.beforeDelete(ctx, l.spec); err != nil {
				return err
			}
			return l.guard(ctx)
		},
	}
}

func (l *nodeTransitLease) register(ctx context.Context) error {
	if err := l.guard(ctx); err != nil {
		return err
	}
	if err := l.runtime.register(ctx, l.spec, l.root, l.digest); err != nil {
		return err
	}
	return l.guard(ctx)
}

func (l *nodeTransitLease) Apply(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrNodeTransitUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, nodeTransitBudget)
	defer cancel()
	if !l.busy.CompareAndSwap(false, true) {
		return ErrNodeTransitUnavailable
	}
	defer l.busy.Store(false)
	l.unused.Store(nil)
	firstApply := !l.applied.Swap(true)
	if err := ctx.Err(); err != nil {
		return err
	}
	// Existence is only a retry fence; the common receipt loader establishes
	// its meaning. A fresh root is not opened or locked before registration.
	if _, err := os.Lstat(filepath.Join(l.root, policyAdditionFile)); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return errors.Join(ErrPolicyAdditionReceipt, err)
		}
		status, err := l.Inspect(ctx)
		if err != nil {
			return errors.Join(ErrPolicyAdditionReceipt, err)
		}
		if status.Unknown || status.Promoted {
			return ErrPolicyAdditionUnknown
		}
		return ErrPolicyAdditionExists
	}
	// Marker absence contributes only to a live first-call proof. It can never
	// establish unused status on its own, or restore it after shared entry.
	newRoot, rootErr := l.unusedRoot(ctx)
	classify := func(err error) error {
		if !firstApply || l.effects.Load() || rootErr != nil {
			return err
		}
		before := &nodeTransitBeforeEffectsError{cause: err, lease: l, root: newRoot}
		l.unused.Store(before)
		return before
	}
	if err := l.register(ctx); err != nil {
		return classify(err)
	}
	// This early invocation provides a definite before-effects refusal. The
	// shared backend repeats preflight under its permanent receipt lock; every
	// error after entering that backend remains unclassified.
	runtime := l.effectRuntime()
	if err := runtime.Preflight(ctx); err != nil {
		return classify(err)
	}
	l.unused.Store(nil)
	l.effects.Store(true)
	if err := applyPolicyEffects(ctx, runtime, l.plan, l.root, policyAdditionOptions{boot: l.options.boot, fault: l.options.fault}); err != nil {
		return err
	}
	count, err := l.presence(ctx)
	if err != nil || count != 1 {
		return errors.Join(ErrPolicyAdditionUnknown, ErrNodeTransitUnavailable, err)
	}
	return l.guard(ctx)
}

func (l *nodeTransitLease) Remove(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrNodeTransitUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, nodeTransitBudget)
	defer cancel()
	if !l.busy.CompareAndSwap(false, true) {
		return ErrNodeTransitUnavailable
	}
	defer l.busy.Store(false)
	l.unused.Store(nil)
	l.effects.Store(true)
	status, err := l.Inspect(ctx)
	if err != nil {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	if status.Unknown || status.Promoted {
		return ErrPolicyAdditionUnknown
	}
	if err := l.register(ctx); err != nil {
		return err
	}
	return removePolicyEffects(ctx, l.effectRuntime(), l.plan, l.root, policyAdditionOptions{boot: l.options.boot, fault: l.options.fault})
}

// VerifyUnused consumes only this lease's live before-effects refusal. A fresh
// lease, a disappeared receipt, or a read-only kernel snapshot cannot obtain
// this capability. It invokes no mutation or metadata settlement itself.
func (l *nodeTransitLease) VerifyUnused(ctx context.Context) error {
	if l == nil || ctx == nil || !l.busy.CompareAndSwap(false, true) {
		return ErrNodeTransitUnavailable
	}
	defer l.busy.Store(false)
	before := l.unused.Swap(nil)
	if before == nil || before.lease != l || l.effects.Load() {
		return ErrNodeTransitUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, nodeTransitBudget)
	defer cancel()
	if err := l.guard(ctx); err != nil {
		return err
	}
	root, err := l.unusedRoot(ctx)
	if err != nil || !os.SameFile(before.root, root) {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	count, err := l.presence(ctx)
	if err != nil || count != 0 {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	if err := l.guard(ctx); err != nil {
		return err
	}
	root, err = l.unusedRoot(ctx)
	if err != nil || !os.SameFile(before.root, root) {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	return ctx.Err()
}

// Bounded marker checks never interpret or grant authority from file contents.
func (l *nodeTransitLease) unusedRoot(ctx context.Context) (os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(l.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.Join(ErrNodeTransitUnavailable, err)
	}
	for _, name := range []string{policyAdditionFile, policyAdditionLock} {
		if _, err := os.Lstat(filepath.Join(l.root, name)); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(ErrNodeTransitUnavailable, err)
		}
	}
	return info, ctx.Err()
}

func (l *nodeTransitLease) Inspect(ctx context.Context) (PolicyAdditionStatus, error) {
	if l == nil || ctx == nil {
		return PolicyAdditionStatus{}, ErrNodeTransitUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, nodeTransitBudget)
	defer cancel()
	s, err := openPolicyEffectSession(ctx, l.plan, l.root, policyAdditionOptions{boot: l.options.boot})
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	defer s.close()
	if err := s.load(ctx); err != nil {
		return PolicyAdditionStatus{}, err
	}
	return s.status(), nil
}
