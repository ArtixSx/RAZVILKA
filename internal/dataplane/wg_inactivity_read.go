package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// The original startup producer supplies the same-source comparison. A digest
// or equal path alone cannot match an already bound engine's actual lease.
type WGInactivityToolRunner interface {
	WGCommandToolRunner
	SameWGToolSource(WGCommandToolRunner) bool
}

// WGInactivityRead retains a startup inspection source, not an execution
// scope/material or a forward profile source. Each use needs a fresh actual
// finite operation of the SAME control Gate. Optional missing CLI is never
// inactivity: the existing complete IP/receipt/process reader must still run.
type WGInactivityRead struct {
	self         *WGInactivityRead
	barrier      sync.RWMutex
	closed       atomic.Bool
	life         context.Context
	cancel       context.CancelFunc
	closeDone    chan struct{}
	closeErr     error
	readCloseMu  sync.Mutex
	readCloseErr error
	manager      *Manager
	root         string
	registry     uint64
	owned        *ownedfs.Root
	anchor       os.FileInfo
	adapter      *WARPWireGuardAdapter
	shape        WARPWireGuardAdapter
	tools        WGCommandTools
	bound        WGCommandTools
	control      *operationgate.ControlEpochReview
	identity     *networkPolicyIdentity
}

func (*WGInactivityRead) String() string   { return "[original WG inactivity read source]" }
func (*WGInactivityRead) GoString() string { return "[original WG inactivity read source]" }

// ReviewWGInactivityRead is the assembly seam for Lease.ReviewWGInactivity.
// Its descriptor is comparison only; the original opaque startup runner owns
// full closure, one-use actual Start and sole joined Wait. Never expose this
// assembly as a DTO/HTTP owner constructor or use callback success as evidence.
func ReviewWGInactivityRead(ctx, lifetime context.Context, manager *Manager, control *operationgate.ControlEpochReview, tools WGCommandTools) (*WGInactivityRead, error) {
	if !wgInactivityFinite(ctx) || lifetime == nil || lifetime.Err() != nil || manager == nil || control == nil || !wgInactivityToolsValid(tools) {
		return nil, ErrWGOperationOwner
	}
	if err := control.Current(ctx); err != nil {
		return nil, err
	}
	manager.registryMu.RLock()
	a, ok := manager.Adapters[tools.EngineID].(*WARPWireGuardAdapter)
	registry := manager.registryGeneration
	manager.registryMu.RUnlock()
	if !ok || a == nil || a.ID() != tools.EngineID {
		return nil, ErrWGOperationOwner
	}
	runner, ok := a.Runner.(wgExecRunner)
	if !ok || runner.adapter != a || !filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot || !filepath.IsAbs(a.RuntimeConfigPath) || filepath.Clean(a.RuntimeConfigPath) != a.RuntimeConfigPath || filepath.Dir(a.RuntimeConfigPath) != a.StateRoot {
		return nil, ErrWGOperationOwner
	}
	root, anchor, err := openNetworkPolicyObservationRoot(manager.StateRoot)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(lifetime)
	r := &WGInactivityRead{life: life, cancel: cancel, manager: manager, root: manager.StateRoot, registry: registry, owned: root, anchor: anchor,
		adapter: a, shape: *a, tools: tools, control: control, identity: manager.executionNetworkIdentity(), closeDone: make(chan struct{})}
	r.self = r
	if a.wgCommandTools != nil {
		r.bound = *a.wgCommandTools
		if !tools.Runner.(WGInactivityToolRunner).SameWGToolSource(r.bound.Runner) {
			_ = r.Close()
			return nil, ErrWGOperationOwner
		}
	}
	if err := r.current(ctx, nil); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

func wgInactivityFinite(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	_, bounded := ctx.Deadline()
	return bounded
}

func wgInactivityToolsValid(t WGCommandTools) bool {
	if t.EngineID != "wireguard" && t.EngineID != "amneziawg" || t.Provider == nil || t.Identity.Validate() != nil || !validPlanDigest(t.ReviewSHA256) {
		return false
	}
	if runner, ok := t.Runner.(WGInactivityToolRunner); !ok || !sameNetworkPolicyDependency(runner, runner) {
		return false
	}
	for _, path := range []string{t.IP, t.IPTables, t.IP6Tables} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
	}
	for _, path := range []string{t.WG, t.AWG} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return false
		}
	}
	return true
}

// Metadata/files only: safe under the original tool/Provider Start bracket.
func (r *WGInactivityRead) pureCurrent(ctx context.Context) error {
	if r == nil || r.self != r || !wgInactivityFinite(ctx) || r.closed.Load() || r.life == nil || r.life.Err() != nil || r.manager == nil || r.manager.StateRoot != r.root || r.owned == nil || r.control == nil || !wgInactivityToolsValid(r.tools) {
		return ErrWGOperationOwner
	}
	a, s := r.adapter, &r.shape
	if a == nil || a.ID() != s.ID() || a.StateRoot != s.StateRoot || a.RuntimeConfigPath != s.RuntimeConfigPath || a.Interface != s.Interface || a.Table != s.Table || a.PriorityBase != s.PriorityBase || a.WG != s.WG || a.IP != s.IP || a.IPTables != s.IPTables || a.IP6Tables != s.IP6Tables || a.WGQuick != s.WGQuick || a.NativeOnly != s.NativeOnly || a.Configs != s.Configs || !sameNetworkPolicyDependency(a.Profiles, s.Profiles) || !sameNetworkPolicyDependency(a.Runner, s.Runner) || a.wgCommandTools != s.wgCommandTools {
		return ErrWGOperationOwner
	}
	if s.wgCommandTools != nil {
		bound := r.bound
		if !sameWGCommandShape(a, s, bound) || bound.EngineID != r.tools.EngineID || bound.Provider != r.tools.Provider || bound.Identity != r.tools.Identity || bound.ReviewSHA256 != r.tools.ReviewSHA256 || bound.IP != r.tools.IP || bound.IPTables != r.tools.IPTables || bound.IP6Tables != r.tools.IP6Tables || bound.WG != r.tools.WG || bound.AWG != r.tools.AWG {
			return ErrWGOperationOwner
		}
	}
	if r.manager.executionNetworkIdentity() != r.identity || r.identity != nil && (r.identity.provider != r.tools.Provider || r.identity.value != r.tools.Identity) {
		return ErrWGOperationOwner
	}
	r.manager.registryMu.RLock()
	valid := r.manager.registryGeneration == r.registry && r.manager.Adapters[a.ID()] == a
	r.manager.registryMu.RUnlock()
	info, err := os.Lstat(r.root)
	if !valid || err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(r.anchor, info) {
		return errors.Join(ErrWGOperationOwner, err)
	}
	return nil
}

func (r *WGInactivityRead) current(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if err := r.pureCurrent(ctx); err != nil {
		return err
	}
	if err := r.controlCurrent(ctx, cleanup); err != nil {
		return err
	}
	if err := r.tools.Runner.CheckWG(ctx, r.tools.Identity); err != nil {
		return err
	}
	return errors.Join(r.controlCurrent(ctx, cleanup), r.pureCurrent(ctx))
}

func (r *WGInactivityRead) controlCurrent(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if cleanup != nil {
		return r.control.CurrentForCleanupOperation(ctx, cleanup)
	}
	return r.control.Current(ctx)
}

type wgInactivitySessionKey struct{}
type wgInactivityReadSession struct {
	self    *wgInactivityReadSession
	source  *WGInactivityRead
	cleanup *operationgate.ExclusiveCleanupReview
	ctx     context.Context
	mu      sync.Mutex
	open    bool
	reads   sync.WaitGroup
	roots   wgInactivityRootObservation
}

// WithCurrent retains the actual operation and source through all reads/Wait.
// Escaped contexts cannot read after consume returns. Close cancels and joins
// this same source; it does not release App control or the startup lease.
func (r *WGInactivityRead) WithCurrent(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, consume func(context.Context) error) error {
	if r == nil || r.self != r || !wgInactivityFinite(ctx) || consume == nil {
		return ErrWGOperationOwner
	}
	r.barrier.RLock()
	defer r.barrier.RUnlock()
	if err := r.current(ctx, cleanup); err != nil {
		return err
	}
	cap := cleanup
	if cap == nil {
		var err error
		cap, err = r.control.ReviewExclusiveCleanup(ctx)
		if err != nil {
			return err
		}
	}
	return cap.WithCurrent(ctx, func() (result error) {
		c, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(r.life, cancel)
		defer func() { stop(); cancel() }()
		roots, err := observeWGInactivityRoots(c, r.root, r.adapter.StateRoot)
		if err != nil {
			return err
		}
		defer func() {
			closeErr := roots.close()
			r.readCloseMu.Lock()
			r.readCloseErr = errors.Join(r.readCloseErr, closeErr)
			r.readCloseMu.Unlock()
			result = errors.Join(result, closeErr)
		}()
		s := &wgInactivityReadSession{source: r, cleanup: cleanup, open: true, roots: roots}
		s.self = s
		c = context.WithValue(c, wgInactivitySessionKey{}, s)
		s.ctx = c
		var once sync.Once
		join := func() {
			once.Do(func() {
				s.mu.Lock()
				s.open = false
				s.mu.Unlock()
				cancel()
				s.reads.Wait()
			})
		}
		defer join() // Also revoke/join reads if a trusted consumer panics.
		result = consume(c)
		join()
		return errors.Join(result, r.current(ctx, cleanup), roots.current(ctx))
	})
}

// VerifyRuntimeInactive executes the EXISTING actual receipt/link/RPDB/table
// and process observer, with only its private read runner/path view replaced.
// It grants no future Apply/Stop and never adopts a missing source as absence.
func (r *WGInactivityRead) VerifyRuntimeInactive(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	return r.WithCurrent(ctx, cleanup, func(c context.Context) error {
		return r.VerifyCurrentRuntimeInactive(c)
	})
}

// CurrentFiles is a pure closing bookend for the SAME still-live WithCurrent
// session. It performs no control, Provider, tool or owner callback, and grants
// no inactivity by itself. CORE may use it after its final complete image.
func (r *WGInactivityRead) CurrentFiles(ctx context.Context) error {
	if err := r.pureCurrent(ctx); err != nil {
		return err
	}
	s, _ := ctx.Value(wgInactivitySessionKey{}).(*wgInactivityReadSession)
	if s == nil || s.self != s || s.source != r {
		return ErrWGOperationOwner
	}
	s.mu.Lock()
	open := s.open && s.ctx != nil && s.ctx.Err() == nil
	s.mu.Unlock()
	if !open {
		return ErrWGOperationOwner
	}
	return s.roots.current(ctx)
}

// Use inside WithCurrent BEFORE entering any held Provider/tool inventory
// boundary. It avoids nested WithCurrent; actual command checks and Start/Wait
// still run on every read, followed by the pure session/files bookend.
func (r *WGInactivityRead) VerifyCurrentRuntimeInactive(ctx context.Context) error {
	if err := r.CurrentFiles(ctx); err != nil {
		return err
	}
	view := r.shape
	view.Runner, view.IP, view.IPTables, view.IP6Tables = r, r.tools.IP, r.tools.IPTables, r.tools.IP6Tables
	return errors.Join(view.VerifyRuntimeInactive(ctx), r.CurrentFiles(ctx))
}

func (r *WGInactivityRead) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r == nil || r.self != r || !wgInactivityFinite(ctx) {
		return nil, ErrWGOperationOwner
	}
	s, _ := ctx.Value(wgInactivitySessionKey{}).(*wgInactivityReadSession)
	if s == nil || s.self != s || s.source != r {
		return nil, ErrWGOperationOwner
	}
	s.mu.Lock()
	if !s.open || s.ctx == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, ErrWGOperationOwner
	}
	s.reads.Add(1)
	s.mu.Unlock()
	defer s.reads.Done()
	deadline, _ := ctx.Deadline()
	c, cancel := context.WithDeadline(s.ctx, deadline)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	ctx = c // The original session bounds the command, even for a detached caller.
	actual, valid := wgInactivityReadArguments(r.adapter, r.tools, name, args)
	if !valid {
		return nil, ErrWGOperationOwner
	}
	if err := errors.Join(r.current(ctx, s.cleanup), s.roots.current(ctx)); err != nil {
		return nil, err
	}
	i := &wgInactivityInvocation{source: r, session: s, open: true, name: name, args: actual, review: r.tools.ReviewSHA256}
	i.self = i
	c = context.WithValue(ctx, wgInactivityInvocationKey{}, i)
	defer func() { i.mu.Lock(); i.open = false; i.mu.Unlock() }()
	out, err := r.tools.Runner.RunWG(c, i, name, actual...)
	closing := errors.Join(r.current(ctx, s.cleanup), s.roots.current(ctx))
	if closing != nil {
		return nil, errors.Join(err, closing)
	}
	// Preserve bounded genuine command diagnostics for the existing exact
	// FIB-ENOENT reader. A changed owner/source still returns no observation.
	return slices.Clone(out), err
}

type wgInactivityInvocationKey struct{}
type wgInactivityInvocation struct {
	self         *wgInactivityInvocation
	mu           sync.Mutex
	open, used   bool
	source       *WGInactivityRead
	session      *wgInactivityReadSession
	name, review string
	args         []string
}

func (*wgInactivityInvocation) wgCommandAdmission() {}
func (i *wgInactivityInvocation) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if i == nil || i.self != i || ctx == nil || ctx.Value(wgInactivityInvocationKey{}) != i || ctx.Value(wgInactivitySessionKey{}) != i.session || begin == nil {
		return ErrWGOperationOwner
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.open || i.used || i.name != name || i.review != review || !slices.Equal(i.args, args) {
		return ErrWGOperationOwner
	}
	i.used = true
	i.session.mu.Lock()
	open := i.session.open && i.session.ctx != nil && i.session.ctx.Err() == nil
	i.session.mu.Unlock()
	if !open || i.session.self != i.session || i.session.source != i.source {
		return ErrWGOperationOwner
	}
	if actual, valid := wgInactivityReadArguments(i.source.adapter, i.source.tools, name, args); !valid || !slices.Equal(actual, args) {
		return ErrWGOperationOwner
	}
	if err := errors.Join(i.source.pureCurrent(ctx), i.session.roots.current(ctx)); err != nil {
		return err
	}
	if i.session.cleanup != nil {
		return i.source.control.WithCleanupStart(ctx, i.session.cleanup, begin)
	}
	return i.source.control.WithStart(ctx, begin)
}

func (r *WGInactivityRead) Close() error {
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
	r.readCloseMu.Lock()
	r.closeErr = errors.Join(r.readCloseErr, r.owned.Close())
	r.readCloseMu.Unlock()
	return r.closeErr
}
