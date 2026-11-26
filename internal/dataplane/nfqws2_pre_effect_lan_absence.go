package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
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
	if ok && e != nil && e.self == e && e.material != nil && e.material.self == e.material && e.gate == a && root == filepath.Join(e.material.managerRoot, "transactions", e.plan.PlanID, NetworkPolicyAdapterID) && e.plan.LAN != nil && e.plan.LAN.Mode != LANPolicyNFQWSDirectMode {
		return nil, false, nil // Other original LAN modes retain their existing path.
	}
	if !ok || a == nil || a.check() != nil || e == nil || e.self != e || e.gateInventoryCheck == nil || e.lanFrozen.RetireCheck == nil || e.material == nil || e.material.self != e.material || e.gate != a || e.gate.Binding != e.lan || e.lan.Runtime != e.runtime || e.material.manager == nil || e.material.managerRoot != e.material.manager.StateRoot || e.material.adapter == nil || e.material.control == nil || e.cleanup == nil || e.plan.LAN == nil || e.plan.LAN.Mode != LANPolicyNFQWSDirectMode || !nfqws2ActiveSamePlan(e.plan, p) || root != filepath.Join(e.material.managerRoot, "transactions", e.plan.PlanID, NetworkPolicyAdapterID) {
		return nil, true, ErrNFQWSScopedOwner
	}
	e.material.mu.Lock()
	e.mu.Lock()
	selection, seal := e.selection, e.activationSeal
	// BindExecution holds a comparison reader before prepareActivation issues
	// a different sealed selection. Requiring that later receipt at Snapshot
	// rejects the genuine original participant before it can ever activate.
	comparison := selection != nil && selection == e.comparisonSelection && e.material.issuedSelection == nil && seal == nil
	issued := e.comparisonSelection != nil && selection != nil && selection != e.comparisonSelection && e.material.issuedSelection == selection && seal != nil && seal.self == seal && seal.execution == e && seal.selection == selection
	selectionBound := comparison || issued
	source, reference := e.material.source, e.material.reference
	var issuedSpec NFQWSScopedSpec
	if issued {
		// The seal's spec is immutable after publication under e.mu. Do not
		// require consumption or a live activation deadline for strict cleanup.
		issuedSpec = seal.spec.Clone()
		selectionBound = reflect.DeepEqual(e.spec, issuedSpec)
	}
	original := !e.material.closed && e.material.executionBound && e.material.execution == e && selectionBound
	e.mu.Unlock()
	e.material.mu.Unlock()
	if !original {
		return nil, true, ErrNFQWSScopedOwner
	}
	selection.mu.Lock()
	original = selection.self == selection && !selection.closed && selection.source == source
	if comparison {
		original = original && selection.prepared == e.material && nfqws2ActiveSamePlan(e.plan, selection.plan)
	} else {
		// The actual issued constructor has no comparison material/plan.
		// Its original source/reference/spec and issued seal tuple bind it.
		// neverActivatedLAN remains false, so this only reaches ordinary strict
		// cleanup; the authored empty Snapshot supplies no absence grant here.
		original = original && selection.prepared == nil && reflect.DeepEqual(selection.reference, reference) && reflect.DeepEqual(selection.spec, issuedSpec)
	}
	selection.mu.Unlock()
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
	if err := r.snapshotImageCurrent(); err != nil {
		return err
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
	entries, err := r.dir.ReadDir(3)
	if err != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	info, err := r.manager.Stat(r.relative)
	if err != nil || !os.SameFile(r.dirInfo, info) {
		return ErrNFQWSScopedOwner
	}
	if !authored && len(entries) == 0 || authored && len(entries) == 1 && entries[0].Name() == "snapshot.json" {
		return nil
	}
	return ErrNFQWSScopedOwner
}

// Read the already retained regular file, then compare its path again. A
// pathname stat followed by a new O_RDONLY open can block on a replaced FIFO.
func (r *nfqwsPreEffectLANReview) snapshotImageCurrent() error {
	if r == nil || r.file == nil || r.fileInfo == nil || r.dir == nil || len(r.image) == 0 || len(r.image) > 1<<20 {
		return ErrNFQWSScopedOwner
	}
	data := make([]byte, len(r.image)+1)
	n, err := r.file.ReadAt(data, 0)
	if err != io.EOF || n != len(r.image) || !bytes.Equal(data[:n], r.image) {
		return ErrNFQWSScopedOwner
	}
	held, err := r.file.Stat()
	if err != nil || !held.Mode().IsRegular() || held.Size() != int64(len(r.image)) || !os.SameFile(r.fileInfo, held) {
		return ErrNFQWSScopedOwner
	}
	current, err := r.dir.Stat("snapshot.json")
	if err != nil || !current.Mode().IsRegular() || current.Size() != int64(len(r.image)) || runtime.GOOS != "windows" && current.Mode().Perm() != 0600 || !os.SameFile(r.fileInfo, current) {
		return ErrNFQWSScopedOwner
	}
	return nil
}

func (a *NetworkPolicyAdapter) inspectPreEffectNFQAbsence(ctx context.Context, p Plan, root string, verify bool) (bool, error) {
	e, present, err := a.preEffectNFQParticipant(ctx, p, root)
	if !present || err != nil {
		return present, err
	}
	e.mu.Lock()
	r, retired := e.preEffectLAN, e.retired
	e.mu.Unlock()
	if r == nil || !e.neverActivatedLAN() {
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

// Called only by the SAME Manager compensation after ALL consumer/resource/
// gate verifiers passed, before its final journal publications. The returned
// private writer identity is cycle-local; a failed publication discards it.
// It cannot set RollbackVerified, authorize a fresh operation or survive boot.
func (a *NetworkPolicyAdapter) preEffectNFQCompletion(ctx context.Context, p Plan, root string) (*nfqwsPreEffectLANReview, error) {
	if handled, err := a.inspectPreEffectNFQAbsence(ctx, p, root, false); !handled || err != nil {
		return nil, err
	}
	e, _, err := a.preEffectNFQParticipant(ctx, p, root)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.retired || e.preEffectLAN == nil {
		return nil, ErrNFQWSScopedOwner
	}
	return e.preEffectLAN, nil
}

// This entry check supplies only the original cleanup bookend for an exact
// never-effect witness. Its fixed production leaf is e.cleanupCurrent; all
// other executions retain the ordinary strict effects cleanup path.
func (e *nfqws2ActiveExecution) pendingCleanupCurrent(ctx context.Context) error {
	if e != nil {
		// After Stage the original metadata writer owns this directory's
		// description; its fixed production leaf is e.cleanupCurrent.
		if owners := e.pendingDirectPreparationOwners(); owners != nil {
			return owners(ctx)
		}
	}
	if e != nil && e.gate != nil && e.material != nil {
		root := filepath.Join(e.material.managerRoot, "transactions", e.plan.PlanID, NetworkPolicyAdapterID)
		if handled, err := e.gate.inspectPreEffectNFQAbsence(ctx, e.plan, root, false); handled {
			return err
		}
	}
	return e.cleanupCurrent(ctx)
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
