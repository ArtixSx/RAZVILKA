package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// WGSourceReadReview is an original bounded, read-only inspection owner. It
// needs no fabricated execution plan/scope and cannot admit a network effect.
// Its observations are comparison inputs, never Paths/Ready/ACTIVE authority.
type WGSourceReadReview struct {
	self      *WGSourceReadReview
	barrier   sync.RWMutex
	closed    atomic.Bool
	closeDone chan struct{}
	closeErr  error
	ctx       context.Context
	cancel    context.CancelFunc
	manager   *Manager
	root      string
	registry  uint64
	adapter   *WARPWireGuardAdapter
	shape     WARPWireGuardAdapter
	tools     WGCommandTools
	control   *operationgate.ControlEpochReview
	owned     *ownedfs.Root
	anchor    os.FileInfo
	identity  *networkPolicyIdentity
}

func (*WGSourceReadReview) String() string   { return "[original WG read-only source review]" }
func (*WGSourceReadReview) GoString() string { return "[original WG read-only source review]" }

func ReviewWGSourceRead(ctx context.Context, manager *Manager, control *operationgate.ControlEpochReview, engine string) (*WGSourceReadReview, error) {
	if ctx == nil || manager == nil || control == nil || engine != "wireguard" && engine != "amneziawg" || !filepath.IsAbs(manager.StateRoot) || filepath.Clean(manager.StateRoot) != manager.StateRoot {
		return nil, ErrWGOperationOwner
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, ErrWGOperationOwner
	}
	if err := control.Current(ctx); err != nil {
		return nil, errors.Join(ErrWGOperationOwner, err)
	}
	manager.registryMu.RLock()
	adapter, ok := manager.Adapters[engine].(*WARPWireGuardAdapter)
	registry := manager.registryGeneration
	manager.registryMu.RUnlock()
	if !ok || adapter == nil || adapter.ID() != engine || !adapter.wgCommandTools.valid(engine) {
		return nil, ErrWGOperationOwner
	}
	runner, ok := adapter.Runner.(wgExecRunner)
	if !ok || runner.adapter != adapter {
		return nil, ErrWGOperationOwner
	}
	owned, anchor, err := openNetworkPolicyObservationRoot(manager.StateRoot)
	if err != nil {
		return nil, errors.Join(ErrWGOperationOwner, err)
	}
	lifetime, cancel := context.WithCancel(ctx)
	r := &WGSourceReadReview{ctx: lifetime, cancel: cancel, manager: manager, root: manager.StateRoot, registry: registry, adapter: adapter, shape: *adapter, tools: *adapter.wgCommandTools, control: control, owned: owned, anchor: anchor, identity: manager.executionNetworkIdentity(), closeDone: make(chan struct{})}
	r.self = r
	if err := r.Current(ctx); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

// No Guard/Scope/Store/NI/tool callback may run under the tool/Provider gate.
func (r *WGSourceReadReview) pureCurrent(ctx context.Context) error {
	if r == nil || r.ctx == nil || r.ctx.Err() != nil {
		return ErrWGOperationOwner
	}
	return r.metadataCurrent(ctx)
}

func (r *WGSourceReadReview) metadataCurrent(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil || r.closed.Load() || r.manager == nil || r.manager.StateRoot != r.root || r.control == nil || r.owned == nil {
		return ErrWGOperationOwner
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return ErrWGOperationOwner
	}
	if !sameWGCommandShape(r.adapter, &r.shape, r.tools) || r.manager.executionNetworkIdentity() != r.identity {
		return ErrWGOperationOwner
	}
	r.manager.registryMu.RLock()
	valid := r.manager.registryGeneration == r.registry && r.manager.Adapters[r.adapter.ID()] == r.adapter
	r.manager.registryMu.RUnlock()
	if !valid {
		return ErrWGOperationOwner
	}
	node, err := os.Lstat(r.root)
	if err != nil || !networkPolicyPrivateDirectory(node) || !os.SameFile(r.anchor, node) {
		return errors.Join(ErrWGOperationOwner, err)
	}
	if r.identity != nil && (r.identity.provider != r.tools.Provider || r.identity.value != r.tools.Identity) {
		return ErrWGOperationOwner
	}
	return nil
}

func (r *WGSourceReadReview) Current(ctx context.Context) error {
	if err := r.pureCurrent(ctx); err != nil {
		return err
	}
	// Control.Current accepts fresh same-Gate comparison operations. This
	// reader also checks its retained ORIGINAL context so a fresh operation
	// cannot revive the capture after the original lease was released.
	if err := r.control.Current(r.ctx); err != nil {
		return errors.Join(ErrWGOperationOwner, err)
	}
	if err := r.control.Current(ctx); err != nil {
		return errors.Join(ErrWGOperationOwner, err)
	}
	if err := r.tools.Runner.CheckWG(ctx, r.tools.Identity); err != nil {
		return errors.Join(ErrWGOperationOwner, err)
	}
	return errors.Join(r.pureCurrent(ctx), r.control.Current(ctx), r.control.Current(r.ctx))
}

// NetworkIdentity is comparison only; it cannot issue a Provider or permission.
func (r *WGSourceReadReview) NetworkIdentity(ctx context.Context) (netidentity.Identity, error) {
	if err := r.Current(ctx); err != nil {
		return netidentity.Identity{}, err
	}
	return r.tools.Identity, nil
}

type wgSourceReadKey struct{}
type wgSourceReadInvocation struct {
	self         *wgSourceReadInvocation
	mu           sync.Mutex
	open, used   bool
	retained     bool
	owner        *WGSourceReadReview
	name, review string
	args         []string
}

func (*wgSourceReadInvocation) wgCommandAdmission() {}
func (i *wgSourceReadInvocation) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if i == nil || i.self != i || ctx == nil || ctx.Value(wgSourceReadKey{}) != i || begin == nil {
		return ErrWGOperationOwner
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.open || i.used || i.name != name || i.review != review || !slices.Equal(i.args, args) || !wgSourceReadCommand(i.owner.adapter, name, args) {
		return ErrWGOperationOwner
	}
	i.used = true
	if err := i.owner.sourceCurrentPure(ctx, i.retained); err != nil {
		return err
	}
	return i.owner.control.WithStart(ctx, begin)
}

// Run is only for the existing private endpoint parser's inspection calls.
// The independent held tool ABI and this one-use carrier both reject effects.
func (r *WGSourceReadReview) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.runSource(ctx, false, name, args...)
}

func (r *WGSourceReadReview) runSource(ctx context.Context, retained bool, name string, args ...string) ([]byte, error) {
	if r == nil || r.self != r || !wgSourceReadCommand(r.adapter, name, args) || !validPolicyEffectArgs(args) {
		return nil, ErrWGOperationOwner
	}
	r.barrier.RLock()
	defer r.barrier.RUnlock()
	if err := r.sourceCurrent(ctx, retained); err != nil {
		return nil, err
	}
	// Execute with the original operation capability, retaining the caller's
	// shorter deadline/cancellation without accepting it as new authority.
	deadline, _ := ctx.Deadline() // Current already required a bounded context.
	parent := r.ctx
	if retained {
		parent = ctx
	}
	c, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	i := &wgSourceReadInvocation{open: true, owner: r, name: name, review: r.tools.ReviewSHA256, args: slices.Clone(args), retained: retained}
	i.self = i
	c = context.WithValue(c, wgSourceReadKey{}, i)
	defer func() { i.mu.Lock(); i.open = false; i.mu.Unlock() }()
	out, err := r.tools.Runner.RunWG(c, i, name, args...)
	closing := r.sourceCurrent(c, retained)
	if closing != nil {
		return nil, errors.Join(err, closing)
	}
	// Preserve genuine bounded command diagnostics for endpoint format
	// negotiation only while the same original owner remains current.
	return slices.Clone(out), err
}

// This source only inspects a public identity or a numeric endpoint's main
// WAN route. In particular, WG private-key/dump and every mutation refuse
// before reaching even a supplied tool source; its own held ABI also checks.
func wgSourceReadCommand(a *WARPWireGuardAdapter, name string, args []string) bool {
	if a == nil {
		return false
	}
	if name == a.wg() && slices.Equal(args, []string{"show", "all", "public-key"}) {
		return true
	}
	if name != a.ip() {
		return false
	}
	family := "-4"
	if len(args) > 0 && (args[0] == "-4" || args[0] == "-6") {
		family, args = args[0], args[1:]
	}
	if len(args) > 0 && args[0] == "-j" {
		args = args[1:]
	}
	if len(args) != 5 || !slices.Equal(args[:2], []string{"route", "get"}) || args[3] != "mark" || args[4] != "0" {
		return false
	}
	address, err := netip.ParseAddr(args[2])
	return err == nil && address.String() == args[2] && address.Is4() == (family == "-4") && publicfetch.PublicAddress(address)
}

func (r *WGSourceReadReview) Close() error {
	if r == nil || r.self != r {
		return ErrWGOperationOwner
	}
	if !r.closed.CompareAndSwap(false, true) {
		<-r.closeDone
		return r.closeErr
	}
	defer close(r.closeDone)
	r.cancel()
	r.barrier.Lock()
	defer r.barrier.Unlock()
	r.closeErr = r.owned.Close()
	return r.closeErr
}
