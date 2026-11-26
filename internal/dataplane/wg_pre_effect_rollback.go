package dataplane

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Same original Snapshot writer only. No decoded snapshot, absent marker or
// old wgCleanupJoined value can manufacture this pre-effect readback owner.
type wgPreEffectSnapshot struct {
	self         *wgPreEffectSnapshot
	mu           sync.Mutex
	closed       bool
	owner        *wgOperationOwner
	checks       *NetworkPolicyChecks
	source       *WGInactivityRead
	root         string
	dir          *ownedfs.Root
	anchor, info os.FileInfo
	file         *os.File
	image        []byte
	empty        bool
	// Production is the SAME original complete inactivity observer. Package
	// tests replace only the unsupported OS process-reading leaf inside it.
	observe func(context.Context) error
}

func originalWGPhase(ctx context.Context, a *WARPWireGuardAdapter, p Plan, root string) (*wgOperationOwner, bool, error) {
	if ctx == nil || ctx.Value(wgOperationMaterialKey{}) == nil && ctx.Value(wgOperationOwnerKey{}) == nil {
		return nil, false, nil
	}
	o, _ := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	if o == nil || o.self != o || o.adapter != a || o.scope == nil || o.scope.wgOwner != o || o.scope.adapterOwner != a || o.material == nil || ctx.Value(wgOperationMaterialKey{}) != o.material || !nfqws2ActiveSamePlan(o.scope.plan, p) || root != filepath.Join(o.scope.root, a.ID()) {
		return nil, true, ErrWGOperationOwner
	}
	return o, true, nil
}

func (a *WARPWireGuardAdapter) markOriginalWGPhase(ctx context.Context, p Plan, root string, activate bool) error {
	o, present, err := originalWGPhase(ctx, a, p, root)
	if !present || err != nil {
		return err
	}
	o.scope.mu.Lock()
	defer o.scope.mu.Unlock()
	if activate {
		o.scope.wgActivateAttempted = true
	} else {
		o.scope.wgStageAttempted = true
	}
	return nil
}

func (a *WARPWireGuardAdapter) writeOriginalWGSnapshot(ctx context.Context, p Plan, root string, snapshot warpWGSnapshot, image []byte) (bool, error) {
	o, present, err := originalWGPhase(ctx, a, p, root)
	if !present || err != nil {
		return present, err
	}
	if err := o.check(ctx, false); err != nil {
		return true, err
	}
	s := o.scope
	s.mu.Lock()
	available := s.wgSnapshot == nil && !s.wgStageAttempted && !s.wgActivateAttempted && !o.mutationAttempted.Load()
	s.mu.Unlock()
	if !available {
		return true, ErrWGOperationOwner
	}
	if err := s.owned.Check(a.ID()); err != nil {
		return true, err
	}
	dir, anchor, err := openNetworkPolicyObservationRoot(root)
	if err != nil {
		return true, err
	}
	// A legacy link-show error may produce InterfaceWasActive=false. That is
	// NOT proof of initial absence. Completion requires the independent fresh
	// original full observer below; this flag only excludes a known prior link.
	r := &wgPreEffectSnapshot{owner: o, root: root, dir: dir, anchor: anchor, image: bytes.Clone(image), empty: !snapshot.StateExisted && !snapshot.RuntimeExisted && !snapshot.InterfaceWasActive && snapshot.PolicyGeneration == nil}
	r.self = r
	keep := false
	defer func() {
		if !keep {
			_ = r.close()
		}
	}()
	if err := r.onlySnapshot(false); err != nil {
		return true, err
	}
	r.file, err = dir.WriteAtomicRetained("snapshot.json", image, 0600)
	if err != nil {
		return true, err
	}
	if err := syncDataplaneJournalDirectory(dir); err != nil {
		return true, err
	}
	r.info, err = r.file.Stat()
	if err != nil {
		return true, err
	}
	s.manager.registryMu.RLock()
	r.checks = s.manager.wgPreEffectChecks
	s.manager.registryMu.RUnlock()
	if r.checks != nil {
		r.source = r.checks.wgInactivity[a.ID()]
	}
	r.observe = func(c context.Context) error {
		if r.source == nil {
			return ErrRuntimeInactivity
		}
		return r.source.VerifyRuntimeInactive(c, o.material.cleanup)
	}
	// This publication is still under the serialized original Manager phase.
	// Material.Close's writer barrier joins the exact same read/Start owners.
	o.material.barrier.RLock()
	defer o.material.barrier.RUnlock()
	if err := o.check(ctx, false); err != nil {
		return true, err
	}
	if err := r.filesCurrent(); err != nil {
		return true, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.wgSnapshot != nil || s.wgStageAttempted || s.wgActivateAttempted || o.mutationAttempted.Load() {
		return true, ErrWGOperationOwner
	}
	s.wgSnapshot = r
	keep = true
	return true, nil
}

func (r *wgPreEffectSnapshot) onlySnapshot(authored bool) error {
	entries, readErr := r.dir.ReadDir(3)
	if readErr != nil && readErr != io.EOF {
		return errors.Join(ErrWGOperationOwner, readErr)
	}
	if !authored && len(entries) == 0 || authored && len(entries) == 1 && entries[0].Name() == "snapshot.json" {
		return nil
	}
	return ErrWGOperationOwner
}

// No-op rollback is separate from independent verification. Only this exact
// authored never-effect owner avoids the legacy snapshot pathname reader.
// Stage/activation/prior-state paths keep their existing strict rollback.
func (a *WARPWireGuardAdapter) rollbackOriginalWGPreEffect(ctx context.Context, p Plan, root string) (bool, error) {
	o, present, err := originalWGPhase(ctx, a, p, root)
	if !present || err != nil {
		return present, err
	}
	s := o.scope
	s.mu.Lock()
	r := s.wgSnapshot
	never := !s.wgStageAttempted && !s.wgActivateAttempted && !o.mutationAttempted.Load()
	s.mu.Unlock()
	if !never || r == nil || !r.empty {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	o.material.barrier.RLock()
	defer o.material.barrier.RUnlock()
	return true, r.current(ctx)
}

func (r *wgPreEffectSnapshot) filesCurrent() error {
	if r == nil || r.self != r || r.closed || r.owner == nil || r.dir == nil || r.file == nil {
		return ErrWGOperationOwner
	}
	info, err := os.Lstat(r.root)
	if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(r.anchor, info) {
		return ErrWGOperationOwner
	}
	info, err = r.dir.RootInfo()
	if err != nil || !os.SameFile(r.anchor, info) {
		return ErrWGOperationOwner
	}
	info, err = r.owner.scope.owned.Stat(r.owner.adapter.ID())
	if err != nil || !os.SameFile(r.anchor, info) {
		return ErrWGOperationOwner
	}
	info, err = r.dir.Stat("snapshot.json")
	if err != nil || !validNetworkPolicyReceiptFile(info) || !os.SameFile(r.info, info) {
		return ErrWGOperationOwner
	}
	info, err = r.file.Stat()
	if err != nil || !os.SameFile(r.info, info) {
		return ErrWGOperationOwner
	}
	if r.info.Size() < 0 || r.info.Size() > 1<<20 {
		return ErrWGOperationOwner
	}
	// Read only the originally authored regular file. Reopening its pathname
	// could block on a substituted FIFO before a later fstat can reject it.
	data, err := io.ReadAll(io.NewSectionReader(r.file, 0, r.info.Size()+1))
	if err != nil || !bytes.Equal(data, r.image) {
		return ErrWGOperationOwner
	}
	info, err = r.dir.Stat("snapshot.json")
	if err != nil || !validNetworkPolicyReceiptFile(info) || !os.SameFile(r.info, info) || info.Size() != r.info.Size() {
		return ErrWGOperationOwner
	}
	info, err = r.file.Stat()
	if err != nil || !os.SameFile(r.info, info) || info.Size() != r.info.Size() {
		return ErrWGOperationOwner
	}
	return r.onlySnapshot(true)
}

// Full inactivity permits a retained removed generation as evidence of an
// earlier owned Stop. That is not this never-effect participant's provenance:
// any current runtime, receipt, generation or unknown metadata must refuse.
func (r *wgPreEffectSnapshot) runtimeMetadataAbsent() error {
	relative, err := filepath.Rel(r.checks.root, r.owner.adapter.StateRoot)
	if err != nil || !filepath.IsLocal(relative) || relative == "." {
		return ErrWGOperationOwner
	}
	info, err := r.checks.owner.Stat(relative)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !networkPolicyPrivateDirectory(info) {
		return ErrWGOperationOwner
	}
	// Reuse the original inactivity reader's nonblocking, no-follow opener.
	// The held manager root checks both sides; this opens no mutation owner.
	f, err := openWGInactivityObservationFile(r.owner.adapter.StateRoot)
	if err != nil {
		return err
	}
	held, err := f.Stat()
	if err != nil || !networkPolicyPrivateDirectory(held) || !os.SameFile(info, held) {
		return errors.Join(ErrWGOperationOwner, err, f.Close())
	}
	entries, readErr := f.ReadDir(1)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) != 0 {
		return errors.Join(ErrWGOperationOwner, readErr, closeErr)
	}
	current, err := r.checks.owner.Stat(relative)
	if err != nil || !os.SameFile(info, current) {
		return ErrWGOperationOwner
	}
	return nil
}

func (r *wgPreEffectSnapshot) current(ctx context.Context) error {
	if r == nil || r.self != r || !r.empty || r.owner == nil || r.owner.self != r.owner || r.owner.scope == nil || r.owner.material == nil || r.owner.adapter == nil || r.source == nil || r.checks == nil || r.observe == nil {
		return ErrWGOperationOwner
	}
	o, s, c, source := r.owner, r.owner.scope, r.checks, r.source
	s.mu.Lock()
	never := s.open && s.wgSnapshot == r && s.wgOwner == o && s.wgRecords != nil && !s.wgStageAttempted && !s.wgActivateAttempted && !o.mutationAttempted.Load() && len(s.execution.Resources) == 0
	s.mu.Unlock()
	if !never || s.manager != c.manager || c.adapters[o.adapter.ID()] != o.adapter || c.identity != s.networkIdentity || source != c.wgInactivity[o.adapter.ID()] || source.control != o.material.control || source.adapter != o.adapter || !sameNetworkPolicyDependency(source.bound.Runner, o.tools.Runner) {
		return ErrWGOperationOwner
	}
	s.manager.registryMu.RLock()
	original := s.manager.wgPreEffectChecks == c
	s.manager.registryMu.RUnlock()
	if !original {
		return ErrWGOperationOwner
	}
	if err := r.runtimeMetadataAbsent(); err != nil {
		return err
	}
	if err := c.current(ctx); err != nil {
		return err
	}
	if err := source.pureCurrent(ctx); err != nil {
		return err
	}
	if err := o.check(ctx, true); err != nil {
		return err
	}
	if err := s.wgRecords.current(ctx, true); err != nil {
		return err
	}
	return errors.Join(r.filesCurrent(), source.pureCurrent(ctx), c.current(ctx), r.runtimeMetadataAbsent())
}

func (m *Manager) verifyOriginalWGPreEffect(ctx context.Context, p Plan, a *WARPWireGuardAdapter, s *executionResourceScope) (bool, error) {
	if s == nil || s.manager != m || s.wgOwner == nil || s.wgOwner.scope != s || s.wgOwner.adapter != a || !nfqws2ActiveSamePlan(s.plan, p) {
		return false, ErrWGOperationOwner
	}
	s.mu.Lock()
	r := s.wgSnapshot
	s.mu.Unlock()
	if r == nil {
		return false, ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s.wgOwner.material.barrier.RLock()
	defer s.wgOwner.material.barrier.RUnlock()
	if err := r.current(ctx); err != nil {
		return false, err
	}
	if err := r.observe(ctx); err != nil {
		return false, err
	}
	err := r.current(ctx)
	return err == nil, err
}

func (r *wgPreEffectSnapshot) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.file != nil {
		err = r.file.Close()
	}
	if r.dir != nil {
		err = errors.Join(err, r.dir.Close())
	}
	return err
}

// Called only after this compensation cycle's independent WG/resource/LAN
// readbacks passed. Final publication failure discards the returned identity.
func (m *Manager) preEffectWGCompletion(ctx context.Context, p Plan, s *executionResourceScope) (*wgPreEffectSnapshot, error) {
	if s == nil || s.manager != m || s.wgOwner == nil || s.wgOwner.scope != s || !nfqws2ActiveSamePlan(s.plan, p) {
		return nil, ErrWGOperationOwner
	}
	c, err := s.wgOwner.cleanupContext(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	r := s.wgSnapshot
	s.mu.Unlock()
	if r == nil {
		return nil, ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s.wgOwner.material.barrier.RLock()
	defer s.wgOwner.material.barrier.RUnlock()
	if err := r.current(c); err != nil {
		return nil, err
	}
	return r, nil
}
