package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Original empty Snapshot writer only. Neither missing files nor a decoded
// snapshot can construct this review. It observes never-activated retirement;
// it supplies no Start, COMMON receipt, deletion, CAS or forward permission.
type nfqwsPreEffectLANReview struct {
	self                           *nfqwsPreEffectLANReview
	mu                             sync.Mutex
	closed                         bool
	execution                      *nfqws2ActiveExecution
	manager, dir                   *ownedfs.Root
	managerInfo, dirInfo, fileInfo os.FileInfo
	file                           *os.File
	root, relative                 string
	image                          []byte
	// Production fixes this to SAME original participant's full independent
	// negative read. Package tests model only this source/kernel I/O leaf.
	observe func(context.Context) error
	owners  func(context.Context) error
}

func (a *NetworkPolicyAdapter) preEffectNFQParticipant(ctx context.Context, p Plan, root string) (*nfqws2ActiveExecution, bool, error) {
	if ctx == nil || ctx.Value(nfqws2ActiveExecutionKey{}) == nil {
		return nil, false, nil
	}
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || a == nil || a.check() != nil || e == nil || e.self != e || e.gateInventoryCheck == nil || e.lanFrozen.RetireCheck == nil || e.material == nil || e.material.self != e.material || e.gate != a || e.gate.Binding != e.lan || e.lan.Runtime != e.runtime || e.material.manager == nil || e.material.managerRoot != e.material.manager.StateRoot || e.material.adapter == nil || e.material.control == nil || e.cleanup == nil || e.plan.LAN == nil || e.plan.LAN.Mode != LANPolicyNFQWSDirectMode || !nfqws2ActiveSamePlan(e.plan, p) || root != filepath.Join(e.material.managerRoot, "transactions", e.plan.PlanID, NetworkPolicyAdapterID) {
		return nil, true, ErrNFQWSScopedOwner
	}
	e.material.mu.Lock()
	original := !e.material.closed && e.material.executionBound && e.material.execution == e && e.selection != nil && e.material.issuedSelection == e.selection
	e.material.mu.Unlock()
	if !original {
		return nil, true, ErrNFQWSScopedOwner
	}
	e.selection.mu.Lock()
	original = e.selection.self == e.selection && !e.selection.closed && e.selection.prepared == e.material && e.selection.source == e.material.source && nfqws2ActiveSamePlan(e.plan, e.selection.plan)
	e.selection.mu.Unlock()
	if !original {
		return nil, true, ErrNFQWSScopedOwner
	}
	return e, true, nil
}

func (e *nfqws2ActiveExecution) neverActivatedLAN() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.started && !e.launchInvoked && !e.activationAttempted && !e.lanActivationAttempted && e.activationSeal == nil && e.resource == nil && e.prepared == nil && e.binding == nil && !errors.Is(e.preparationErr, ErrExecutionJournal)
}

func (e *nfqws2ActiveExecution) capturePreEffectLAN(ctx context.Context, root string) error {
	if !e.neverActivatedLAN() {
		return ErrNFQWSScopedOwner
	}
	e.mu.Lock()
	duplicate, retired := e.preEffectLAN != nil, e.retired
	e.mu.Unlock()
	if duplicate || retired {
		return ErrNFQWSScopedOwner
	}
	if err := e.material.control.Current(ctx); err != nil {
		return err
	}
	r := &nfqwsPreEffectLANReview{execution: e, root: root, relative: filepath.Join("transactions", e.plan.PlanID, NetworkPolicyAdapterID)}
	r.self = r
	keep := false
	defer func() {
		if !keep {
			_ = r.close()
		}
	}()
	var err error
	r.manager, r.managerInfo, err = openNetworkPolicyObservationRoot(e.material.managerRoot)
	if err != nil {
		return err
	}
	if err := r.manager.Check(r.relative); err != nil {
		return err
	}
	r.dir, r.dirInfo, err = openNetworkPolicyObservationRoot(root)
	if err != nil {
		return err
	}
	if err := r.onlySnapshot(false); err != nil {
		return err
	}
	r.image, err = json.Marshal(networkPolicyGateSnapshot{})
	if err != nil {
		return err
	}
	r.file, err = r.dir.WriteAtomicRetained("snapshot.json", r.image, 0600)
	if err != nil {
		return err
	}
	if err := syncDataplaneJournalDirectory(r.dir); err != nil {
		return err
	}
	r.fileInfo, err = r.file.Stat()
	if err != nil {
		return err
	}
	r.observe = func(c context.Context) error {
		ok, err := e.verifyRollback(c)
		if err != nil || !ok {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		return e.cleanupCurrent(c)
	}
	r.owners = e.cleanupCurrent
	if err := r.current(ctx); err != nil {
		return err
	}
	if err := e.retainPreEffectLAN(r); err != nil {
		return err
	}
	keep = true
	return nil
}

// Serialize final publication with Material.Close. Close either sees this
// original review and joins it, or prevents its publication and the caller
// closes its still-private descriptors. No material lock is held across I/O.
func (e *nfqws2ActiveExecution) retainPreEffectLAN(r *nfqwsPreEffectLANReview) error {
	e.material.mu.Lock()
	defer e.material.mu.Unlock()
	if e.material.closed || !e.material.executionBound || e.material.execution != e || r == nil || r.self != r || r.execution != e {
		return ErrNFQWSScopedOwner
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.preEffectLAN != nil || e.retired || e.lanActivationAttempted {
		return ErrNFQWSScopedOwner
	}
	e.preEffectLAN = r
	return nil
}

// Caller retains r.mu through every read and closing bookend; Close joins it.
func (r *nfqwsPreEffectLANReview) current(ctx context.Context) error {
	if r == nil || r.self != r || r.closed || ctx == nil || ctx.Err() != nil || r.execution == nil || r.manager == nil || r.dir == nil || r.file == nil || r.observe == nil || r.owners == nil {
		return ErrNFQWSScopedOwner
	}
	e := r.execution
	if _, present, err := e.gate.preEffectNFQParticipant(ctx, e.plan, r.root); !present || err != nil || !e.neverActivatedLAN() {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := e.runtimeFrozen.checkTools(ctx, e.plan.LAN); err != nil {
		return err
	}
	for _, held := range []struct {
		root     *ownedfs.Root
		path     string
		original os.FileInfo
	}{{r.manager, e.material.managerRoot, r.managerInfo}, {r.dir, r.root, r.dirInfo}} {
		info, err := os.Lstat(held.path)
		if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(held.original, info) {
			return ErrNFQWSScopedOwner
		}
		info, err = held.root.RootInfo()
		if err != nil || !os.SameFile(held.original, info) {
			return ErrNFQWSScopedOwner
		}
	}
	info, err := r.manager.Stat(r.relative)
	if err != nil || !os.SameFile(r.dirInfo, info) {
		return ErrNFQWSScopedOwner
	}
	info, err = r.dir.Stat("snapshot.json")
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(r.image)) || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 || !os.SameFile(r.fileInfo, info) {
		return ErrNFQWSScopedOwner
	}
	info, err = r.file.Stat()
	if err != nil || !os.SameFile(r.fileInfo, info) {
		return ErrNFQWSScopedOwner
	}
	data, err := r.dir.ReadLimited("snapshot.json", 1<<20)
	if err != nil || !bytes.Equal(data, r.image) {
		return ErrNFQWSScopedOwner
	}
	// Only the authored empty snapshot is allowed before Stage. Unknown files,
	// candidate/receipt/lock or a promoted destination cannot become absence.
	if err := r.onlySnapshot(true); err != nil {
		return err
	}
	for _, relative := range []string{filepath.Join(NetworkPolicyAdapterID, "owner.json"), filepath.Join(NetworkPolicyAdapterID, "receipts", e.plan.PlanID)} {
		if _, err := r.manager.Stat(relative); !errors.Is(err, os.ErrNotExist) {
			return ErrNFQWSScopedOwner
		}
	}
	return ctx.Err()
}

func (r *nfqwsPreEffectLANReview) onlySnapshot(authored bool) error {
	dir, err := r.manager.OpenFile(r.relative, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(3)
	closeErr := dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return errors.Join(ErrNFQWSScopedOwner, readErr, closeErr)
	}
	if !authored && len(entries) == 0 || authored && len(entries) == 1 && entries[0].Name() == "snapshot.json" {
		return nil
	}
	return ErrNFQWSScopedOwner
}

func (a *NetworkPolicyAdapter) inspectPreEffectNFQAbsence(ctx context.Context, p Plan, root string, verify bool) (bool, error) {
	e, present, err := a.preEffectNFQParticipant(ctx, p, root)
	if !present || err != nil {
		return present, err
	}
	e.mu.Lock()
	r, retired := e.preEffectLAN, e.retired
	e.mu.Unlock()
	if r == nil {
		return false, nil
	} // Ordinary strict effects cleanup remains unchanged.
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.execution != e || !retired || !e.neverActivatedLAN() {
		return true, ErrNFQWSScopedOwner
	}
	err = e.cleanup.WithCurrent(ctx, func() error {
		if err := e.material.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		if err := r.current(ctx); err != nil {
			return err
		}
		if err := r.owners(ctx); err != nil {
			return err
		}
		if err := r.current(ctx); err != nil {
			return err
		}
		// This exact Rollback has no effect or receipt to undo. A successful
		// no-op is not verification: only the separate VerifyRollback below
		// performs complete fresh consumer/kernel absence observations.
		if !verify {
			return e.material.control.CurrentForCleanup(ctx)
		}
		if err := r.observe(ctx); err != nil {
			return err
		}
		if err := r.current(ctx); err != nil {
			return err
		}
		if err := e.lanFrozen.RetireCheck(ctx, CloneLANPolicyRuntime(p.LAN)); err != nil {
			return err
		}
		if err := e.gateInventoryCheck(ctx); err != nil {
			return err
		}
		if err := e.runtimeFrozen.inspectDirectRPDB(ctx); err != nil {
			return err
		}
		if err := r.owners(ctx); err != nil {
			return err
		}
		return errors.Join(r.current(ctx), e.material.control.CurrentForCleanup(ctx))
	})
	return true, err
}

func (e *nfqws2ActiveExecution) closePreEffectLAN() error {
	e.mu.Lock()
	r := e.preEffectLAN
	e.mu.Unlock()
	if r == nil {
		return nil
	}
	return r.close()
}
func (r *nfqwsPreEffectLANReview) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.file != nil {
		err = errors.Join(err, r.file.Close())
	}
	if r.dir != nil {
		err = errors.Join(err, r.dir.Close())
	}
	if r.manager != nil {
		err = errors.Join(err, r.manager.Close())
	}
	return err
}
