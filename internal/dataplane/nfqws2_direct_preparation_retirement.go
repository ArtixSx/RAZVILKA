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

// Writer states of one original metadata file. Only the witness's own
// retained write moves a state forward; a decoded file or a missing path never
// does. "unknown" is terminal for this witness: the SAME pending owner stays
// retained and no other path may settle it.
const (
	directWriterNone     = ""
	directWriterWritten  = "written"
	directWriterUnknown  = "unknown"
	directWriterUnlinked = "unlinked" // owner.json unlinked; directory sync not yet confirmed
	directWriterRemoved  = "removed"
)

type lanDirectPreparationWitnessKey struct{}

// One actual Manager compensation cycle. Only that cycle's handled gate
// Rollback and VerifyRollback record themselves here; the Manager decides from
// these records alone and never re-evaluates the participant afterwards.
type directPreparationCycle struct {
	self             *directPreparationCycle
	rollback, verify *nfqwsDirectPreparationWitness
}

type directPreparationCycleKey struct{}

func withDirectPreparationCycle(ctx context.Context) (context.Context, *directPreparationCycle) {
	c := &directPreparationCycle{}
	c.self = c
	return context.WithValue(ctx, directPreparationCycleKey{}, c), c
}

// One file image produced by this witness's own WriteAtomicRetained. The held
// descriptor is the staged inode itself, never a file found at the path later.
type nfqwsHeldImage struct {
	file  *os.File
	info  os.FileInfo
	image []byte
}

// nfqwsDirectPreparationWitness is the original writer of exactly this NFQ
// direct participant's LAN metadata: candidate.json (Stage), owner.json and
// the schema 3 preparation (Activate). It exists only after the original empty
// Snapshot writer, whose held roots anchor it. It can retire that metadata
// only after NFQ provably never received a seal, resource, prepared process or
// binding, and only after fresh independent absence of NFQ, every other
// consumer and owned RPDB rules. It supplies no Start, effect, deletion of a
// COMMON receipt, physical-scope bypass for ordinary cleanup, RollbackVerified
// or boot survival.
type nfqwsDirectPreparationWitness struct {
	self      *nfqwsDirectPreparationWitness
	mu        sync.Mutex
	closed    bool
	execution *nfqws2ActiveExecution
	review    *nfqwsPreEffectLANReview // The original empty Snapshot writer.
	root      string                   // transactions/<plan>/lan-policy
	dir       *ownedfs.Root
	dirInfo   os.FileInfo
	ownerPath string
	ownerDir  *ownedfs.Root // <state>/lan-policy, opened by the owner writer.
	ownerInfo os.FileInfo
	candidate nfqwsHeldImage
	owner     nfqwsHeldImage
	prep      nfqwsHeldImage
	// Writer states. lockAttempted records that the original preparation
	// session ran; lockInfo is the inode it actually held, when it opened.
	ownerState, prepState string
	lockAttempted         bool
	lockInfo              os.FileInfo
	// Production fixes these to the SAME original participant's full
	// independent negative read and typed owner checks. Package tests model
	// only these source/kernel leaves, as for nfqwsPreEffectLANReview.
	observe func(context.Context) error
	owners  func(context.Context) error
	// Test-only crash/error boundary injection. Production never sets it.
	fault func(string) error
}

func (w *nfqwsDirectPreparationWitness) faultAt(point string) error {
	if w.fault != nil {
		return w.fault(point)
	}
	return nil
}

// captureDirectPreparation runs inside the original Stage. A participant
// without the original empty Snapshot writer (for example a prior-owner
// replacement) keeps every existing writer and path unchanged.
func (e *nfqws2ActiveExecution) captureDirectPreparation(ctx context.Context, root string, state *networkPolicyGateState) (bool, error) {
	e.mu.Lock()
	r, duplicate, retired, attempted := e.preEffectLAN, e.directPreparation != nil, e.retired, e.lanActivationAttempted
	e.mu.Unlock()
	if r == nil {
		return false, nil
	}
	if duplicate || retired || attempted || state == nil {
		return true, ErrNFQWSScopedOwner
	}
	if err := e.material.control.Current(ctx); err != nil {
		return true, err
	}
	r.mu.Lock()
	original := r.self == r && !r.closed && r.execution == e && r.root == root && r.dirInfo != nil && r.manager != nil
	anchor := r.dirInfo
	r.mu.Unlock()
	if !original {
		return true, ErrNFQWSScopedOwner
	}
	w := &nfqwsDirectPreparationWitness{execution: e, review: r, root: root, ownerPath: e.gate.ownerPath()}
	w.self = w
	keep := false
	defer func() {
		if !keep {
			_ = w.close()
		}
	}()
	var err error
	w.dir, w.dirInfo, err = openNetworkPolicyObservationRoot(root)
	if err != nil {
		return true, err
	}
	if !os.SameFile(anchor, w.dirInfo) {
		return true, ErrNFQWSScopedOwner
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > 1<<20 {
		return true, errors.Join(err, ErrLANPolicyRuntime)
	}
	if err := w.faultAt("candidate-write"); err != nil {
		return true, err
	}
	w.candidate, err = retainedWrite(w.dir, "candidate.json", data)
	if err != nil {
		return true, err
	}
	if err := syncDataplaneJournalDirectory(w.dir); err != nil {
		return true, err
	}
	w.observe = func(c context.Context) error {
		ok, err := e.verifyRollback(c)
		if err != nil || !ok {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		return nil
	}
	w.owners = e.cleanupCurrent
	if err := e.retainDirectPreparation(w); err != nil {
		return true, err
	}
	keep = true
	return true, nil
}

func retainedWrite(root *ownedfs.Root, name string, data []byte) (nfqwsHeldImage, error) {
	file, err := root.WriteAtomicRetained(name, data, 0600)
	if err != nil {
		return nfqwsHeldImage{}, err
	}
	info, err := file.Stat()
	if err != nil {
		return nfqwsHeldImage{}, errors.Join(err, file.Close())
	}
	return nfqwsHeldImage{file: file, info: info, image: append([]byte(nil), data...)}, nil
}

// Serialize publication with Material.Close, as retainPreEffectLAN does.
func (e *nfqws2ActiveExecution) retainDirectPreparation(w *nfqwsDirectPreparationWitness) error {
	e.material.mu.Lock()
	defer e.material.mu.Unlock()
	if e.material.closed || !e.material.executionBound || e.material.execution != e || w == nil || w.self != w || w.execution != e {
		return ErrNFQWSScopedOwner
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.directPreparation != nil || e.preEffectLAN != w.review || e.retired || e.lanActivationAttempted {
		return ErrNFQWSScopedOwner
	}
	e.directPreparation = w
	return nil
}

func (e *nfqws2ActiveExecution) closeDirectPreparation() error {
	e.mu.Lock()
	w := e.directPreparation
	e.mu.Unlock()
	if w == nil {
		return nil
	}
	return w.close()
}

// directPreparationWriter returns the original witness for Activate's owner
// and preparation writers. Its absence keeps the existing writers.
func (a *NetworkPolicyAdapter) directPreparationWriter(ctx context.Context, p Plan, root string) (*nfqwsDirectPreparationWitness, error) {
	e, present, err := a.preEffectNFQParticipant(ctx, p, root)
	if !present || err != nil {
		return nil, err
	}
	e.mu.Lock()
	w := e.directPreparation
	e.mu.Unlock()
	if w == nil {
		return nil, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.self != w || w.closed || w.execution != e || w.root != root || w.ownerState != directWriterNone || w.prepState != directWriterNone || w.lockAttempted {
		return nil, ErrNFQWSScopedOwner
	}
	return w, nil
}

// writeOwner replaces writeNetworkPolicyGate for the original owner.json. The
// owner directory is checked below the original Snapshot writer's manager root.
func (w *nfqwsDirectPreparationWitness) writeOwner(state *networkPolicyGateState) error {
	data, err := json.Marshal(state)
	if err != nil || len(data) > 1<<20 {
		return errors.Join(err, ErrLANPolicyRuntime)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.self != w || w.closed || w.ownerState != directWriterNone || w.ownerDir != nil {
		return ErrNFQWSScopedOwner
	}
	r := w.review
	dir := filepath.Dir(w.ownerPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	w.ownerDir, w.ownerInfo, err = openNetworkPolicyObservationRoot(dir)
	if err != nil {
		return err
	}
	r.mu.Lock()
	anchored := !r.closed && r.manager != nil && filepath.Join(r.execution.material.managerRoot, NetworkPolicyAdapterID) == dir
	var info os.FileInfo
	if anchored {
		info, err = r.manager.Stat(NetworkPolicyAdapterID)
	}
	r.mu.Unlock()
	if !anchored || err != nil || !os.SameFile(info, w.ownerInfo) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	// Any failure from here on may or may not have published a file this
	// writer no longer holds. That result is unknown, never absence.
	w.ownerState = directWriterUnknown
	if err := w.faultAt("owner-write"); err != nil {
		return err
	}
	w.owner, err = retainedWrite(w.ownerDir, "owner.json", data)
	if err != nil {
		return err
	}
	// The exact staged inode is published and held. A failed directory sync
	// leaves durability unknown across a crash, not identity in this process.
	w.ownerState = directWriterWritten
	if err := w.faultAt("owner-sync"); err != nil {
		return err
	}
	return syncDataplaneJournalDirectory(w.ownerDir)
}

func lanDirectPreparationWriter(ctx context.Context, root string) (*nfqwsDirectPreparationWitness, error) {
	value := ctx.Value(lanDirectPreparationWitnessKey{})
	if value == nil {
		return nil, nil
	}
	w, ok := value.(*nfqwsDirectPreparationWitness)
	if !ok || w == nil {
		return nil, ErrPolicyAdditionReceipt
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.self != w || w.closed || w.root != root || w.ownerState != directWriterWritten || w.prepState != directWriterNone || w.lockAttempted {
		return nil, ErrPolicyAdditionReceipt
	}
	return w, nil
}

// openedSession records the lock the original preparation session holds. A
// session on any other directory inode is refused before anything is written.
func (w *nfqwsDirectPreparationWitness) openedSession(s *policyAdditionSession) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.self != w || w.closed || s == nil || s.root == nil || s.lock == nil || s.path != w.root {
		return ErrPolicyAdditionReceipt
	}
	info, err := s.root.RootInfo()
	if err != nil || !os.SameFile(info, w.dirInfo) {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	lock, err := s.lock.Stat()
	if err != nil {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	w.lockInfo = lock
	return nil
}

func (w *nfqwsDirectPreparationWitness) beginSession() {
	w.mu.Lock()
	w.lockAttempted = true
	w.mu.Unlock()
}

// savePreparation replaces policyAdditionSession.save for the original schema
// 3 preparation. It retains the staged inode before rename.
func (w *nfqwsDirectPreparationWitness) savePreparation(ctx context.Context, s *policyAdditionSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.doc.Checksum = policyAdditionChecksum(s.doc)
	data, err := json.Marshal(s.doc)
	if err != nil || len(data) > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.self != w || w.closed || w.prepState != directWriterNone || w.lockInfo == nil {
		return ErrPolicyAdditionReceipt
	}
	w.prepState = directWriterUnknown
	if err := w.faultAt("preparation-write"); err != nil {
		return err
	}
	w.prep, err = retainedWrite(s.root, policyAdditionFile, data)
	if err != nil {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	w.prepState = directWriterWritten
	if err := w.faultAt("preparation-sync"); err != nil {
		return err
	}
	if runtime.GOOS == "linux" && s.root.Sync() != nil {
		return ErrPolicyAdditionReceipt
	}
	s.unsynced = false
	return ctx.Err()
}

// directPreparationParticipant selects the metadata-only retirement. Anything
// short of the exact original never-sealed participant returns handled=false,
// so the ordinary strict path runs unchanged with its own checks.
func (a *NetworkPolicyAdapter) directPreparationParticipant(ctx context.Context, p Plan, root string) (*nfqwsDirectPreparationWitness, *directPreparationCycle, bool) {
	cycle, ok := ctx.Value(directPreparationCycleKey{}).(*directPreparationCycle)
	if !ok || cycle == nil || cycle.self != cycle {
		return nil, nil, false // Only an actual Manager compensation cycle.
	}
	if pair, err := a.replacement(ctx, p); pair != nil || err != nil {
		return nil, nil, false
	}
	e, present, err := a.preEffectNFQParticipant(ctx, p, root)
	if !present || err != nil || e == nil {
		return nil, nil, false
	}
	e.material.mu.Lock()
	e.mu.Lock()
	w := e.directPreparation
	// Every activation receipt is checked explicitly, not only the seal that
	// causally precedes them. LAN Activate WAS attempted: this is not, and does
	// not widen, the never-activated witness.
	eligible := w != nil && w.self == w && w.execution == e && w.review != nil && w.review == e.preEffectLAN &&
		e.lanActivationAttempted && e.retired && !e.started && !e.launchInvoked && e.activationSeal == nil &&
		e.resource == nil && e.prepared == nil && e.binding == nil && e.preparationErr == nil &&
		e.selection != nil && e.selection == e.comparisonSelection &&
		!e.material.closed && e.material.executionBound && e.material.execution == e && e.material.issuedSelection == nil
	e.mu.Unlock()
	e.material.mu.Unlock()
	if !eligible {
		return nil, nil, false
	}
	nfqws2ActiveAdapterMu.Lock()
	idle := e.material.adapter.activeExecution == nil && e.material.adapter.activeProcess == nil
	nfqws2ActiveAdapterMu.Unlock()
	if !idle {
		return nil, nil, false
	}
	return w, cycle, true
}

// retireDirectPreparation completes only this participant's own metadata
// after its complete fresh independent proof. No CleanupGuard, ApplyGuard,
// ScopeCheck, Preflight or Verify runs: the physical boundary of ordinary
// Apply/cleanup is neither consulted nor relaxed by this path.
func (a *NetworkPolicyAdapter) retireDirectPreparation(ctx context.Context, p Plan, root string) (bool, error) {
	w, cycle, handled := a.directPreparationParticipant(ctx, p, root)
	if !handled {
		return false, nil
	}
	if cycle.rollback != nil {
		return true, ErrNFQWSScopedOwner
	}
	// Recorded before any proof or transition: this cycle can no longer
	// publish RollbackVerified, whatever happens next.
	cycle.rollback = w
	want, err := a.gateFor(p)
	if err != nil {
		return true, err
	}
	expected, err := json.Marshal(want)
	if err != nil {
		return true, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.known(); err != nil {
		return true, err
	}
	e := w.execution
	return true, e.cleanup.WithCurrent(ctx, func() error {
		if err := w.prove(ctx, expected); err != nil {
			return err
		}
		if err := w.retirePreparation(ctx, want.LAN); err != nil {
			return err
		}
		if err := w.retireOwner(); err != nil {
			return err
		}
		if err := w.current(ctx, expected); err != nil {
			return err
		}
		return e.material.control.CurrentForCleanup(ctx)
	})
}

// verifyDirectPreparationRetired repeats the complete fresh proof after this
// witness itself removed both files. It never reuses a previous observation.
func (a *NetworkPolicyAdapter) verifyDirectPreparationRetired(ctx context.Context, p Plan, root string) (bool, error) {
	w, cycle, handled := a.directPreparationParticipant(ctx, p, root)
	if !handled {
		return false, nil
	}
	if cycle.rollback != w || cycle.verify != nil {
		return true, ErrNFQWSScopedOwner
	}
	cycle.verify = w
	want, err := a.gateFor(p)
	if err != nil {
		return true, err
	}
	expected, err := json.Marshal(want)
	if err != nil {
		return true, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.retired(); err != nil {
		return true, err
	}
	return true, w.execution.cleanup.WithCurrent(ctx, func() error {
		return w.prove(ctx, expected)
	})
}

// directPreparationUnknown reports a terminal unknown writer result of the
// SAME original witness, so a retry neither repeats nor republishes a
// compensation that can never settle it. It grants nothing.
func (a *NetworkPolicyAdapter) directPreparationUnknown(ctx context.Context, p Plan, root string) bool {
	e, present, err := a.preEffectNFQParticipant(ctx, p, root)
	if !present || err != nil || e == nil {
		return false
	}
	e.mu.Lock()
	w := e.directPreparation
	e.mu.Unlock()
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.self == w && w.execution == e && (w.ownerState == directWriterUnknown || w.prepState == directWriterUnknown)
}

// directPreparationCompletion is called by the SAME Manager compensation
// after every consumer/resource/gate verifier passed, before its final
// journal publications. The witness is cycle-local completion evidence only.
func (a *NetworkPolicyAdapter) directPreparationCompletion(ctx context.Context, p Plan, root string, recorded *directPreparationCycle) (*nfqwsDirectPreparationWitness, error) {
	w, cycle, handled := a.directPreparationParticipant(ctx, p, root)
	if !handled || cycle != recorded || cycle.rollback != w || cycle.verify != w {
		return nil, ErrNFQWSScopedOwner
	}
	want, err := a.gateFor(p)
	if err != nil {
		return nil, err
	}
	expected, err := json.Marshal(want)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.retired(); err != nil {
		return nil, err
	}
	e := w.execution
	err = e.cleanup.WithCurrent(ctx, func() error {
		if err := e.material.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		if err := w.current(ctx, expected); err != nil {
			return err
		}
		if err := w.owners(ctx); err != nil {
			return err
		}
		return errors.Join(w.current(ctx, expected), e.material.control.CurrentForCleanup(ctx))
	})
	if err != nil {
		return nil, err
	}
	return w, nil
}

// Caller holds w.mu.
func (w *nfqwsDirectPreparationWitness) known() error {
	if w.self != w || w.closed || w.observe == nil || w.owners == nil || w.dir == nil || w.candidate.file == nil {
		return ErrNFQWSScopedOwner
	}
	switch w.ownerState {
	case directWriterNone, directWriterWritten, directWriterUnlinked, directWriterRemoved:
	default:
		return ErrPolicyAdditionUnknown
	}
	switch w.prepState {
	case directWriterNone, directWriterWritten, directWriterRemoved:
	default:
		return ErrPolicyAdditionUnknown
	}
	// The preparation can only have been written after this owner.
	if w.prepState != directWriterNone && w.ownerState == directWriterNone {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

// Caller holds w.mu.
func (w *nfqwsDirectPreparationWitness) retired() error {
	if err := w.known(); err != nil {
		return err
	}
	if w.ownerState != directWriterNone && w.ownerState != directWriterRemoved || w.prepState == directWriterWritten {
		return ErrNFQWSScopedOwner
	}
	return nil
}

// prove is the complete fresh independent negative read. Caller holds w.mu
// and the original exclusive cleanup bracket.
func (w *nfqwsDirectPreparationWitness) prove(ctx context.Context, expected []byte) error {
	e := w.execution
	lan := CloneLANPolicyRuntime(e.plan.LAN)
	for _, check := range []func(context.Context) error{
		e.material.control.CurrentForCleanup,
		func(c context.Context) error { return w.current(c, expected) },
		w.owners,
		w.observe,
		func(c context.Context) error { return w.current(c, expected) },
		func(c context.Context) error { return e.lanFrozen.RetireCheck(c, CloneLANPolicyRuntime(lan)) },
		e.gateInventoryCheck,
		e.runtimeFrozen.inspectDirectRPDB,
		func(c context.Context) error { return w.current(c, expected) },
		w.owners,
		e.material.control.CurrentForCleanup,
	} {
		if check == nil {
			return ErrNFQWSScopedOwner
		}
		if err := check(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// current compares every original held root and file image with the paths
// and refuses any other entry in the transaction directory. Caller holds w.mu.
func (w *nfqwsDirectPreparationWitness) current(ctx context.Context, expected []byte) error {
	e := w.execution
	r := w.review
	if w.self != w || w.closed || ctx == nil || ctx.Err() != nil || e == nil || r == nil || w.dir == nil {
		return ErrNFQWSScopedOwner
	}
	if err := e.runtimeFrozen.checkTools(ctx, e.plan.LAN); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.closed || r.execution != e || r.root != w.root || r.manager == nil || r.dir == nil {
		return ErrNFQWSScopedOwner
	}
	for _, held := range []struct {
		root     *ownedfs.Root
		path     string
		original os.FileInfo
	}{{r.manager, e.material.managerRoot, r.managerInfo}, {r.dir, w.root, r.dirInfo}, {w.dir, w.root, r.dirInfo}} {
		info, err := os.Lstat(held.path)
		if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(held.original, info) {
			return ErrNFQWSScopedOwner
		}
		info, err = held.root.RootInfo()
		if err != nil || !os.SameFile(held.original, info) {
			return ErrNFQWSScopedOwner
		}
	}
	if info, err := r.manager.Stat(r.relative); err != nil || !os.SameFile(r.dirInfo, info) {
		return ErrNFQWSScopedOwner
	}
	if err := r.snapshotImageCurrent(); err != nil {
		return err
	}
	if !bytes.Equal(w.candidate.image, expected) {
		return ErrNFQWSScopedOwner
	}
	if err := w.candidate.current(w.dir, "candidate.json"); err != nil {
		return err
	}
	if err := w.listingCurrent(); err != nil {
		return err
	}
	switch w.prepState {
	case directWriterWritten, directWriterRemoved:
		if err := w.prep.current(w.dir, policyAdditionFile); err != nil {
			return err
		}
	case directWriterNone:
		if _, err := w.dir.Stat(policyAdditionFile); !errors.Is(err, os.ErrNotExist) {
			return ErrNFQWSScopedOwner
		}
	default:
		return ErrPolicyAdditionUnknown
	}
	if err := w.ownerCurrent(r, expected); err != nil {
		return err
	}
	// A promoted destination is never this never-sealed preparation.
	if _, err := r.manager.Stat(filepath.Join(NetworkPolicyAdapterID, "receipts", e.plan.PlanID)); !errors.Is(err, os.ErrNotExist) {
		return ErrNFQWSScopedOwner
	}
	return ctx.Err()
}

// Caller holds w.mu and r.mu.
func (w *nfqwsDirectPreparationWitness) ownerCurrent(r *nfqwsPreEffectLANReview, expected []byte) error {
	relative := filepath.Join(NetworkPolicyAdapterID, "owner.json")
	if w.ownerDir == nil {
		// The owner writer never opened its directory, so it never wrote.
		if w.ownerState != directWriterNone {
			return ErrPolicyAdditionUnknown
		}
		if _, err := r.manager.Stat(relative); !errors.Is(err, os.ErrNotExist) {
			return ErrNFQWSScopedOwner
		}
		return nil
	}
	info, err := os.Lstat(filepath.Dir(w.ownerPath))
	if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(w.ownerInfo, info) {
		return ErrNFQWSScopedOwner
	}
	info, err = w.ownerDir.RootInfo()
	if err != nil || !os.SameFile(w.ownerInfo, info) {
		return ErrNFQWSScopedOwner
	}
	info, err = r.manager.Stat(NetworkPolicyAdapterID)
	if err != nil || !os.SameFile(w.ownerInfo, info) {
		return ErrNFQWSScopedOwner
	}
	switch w.ownerState {
	case directWriterWritten:
		if !bytes.Equal(w.owner.image, expected) {
			return ErrNFQWSScopedOwner
		}
		return w.owner.current(w.ownerDir, "owner.json")
	case directWriterNone, directWriterUnlinked, directWriterRemoved:
		if _, err := w.ownerDir.Stat("owner.json"); !errors.Is(err, os.ErrNotExist) {
			return ErrNFQWSScopedOwner
		}
		return nil
	default:
		return ErrPolicyAdditionUnknown
	}
}

// Only the original writers' own entries may exist. Temporary files, FIFOs,
// a promoted destination or any other entry refuse retirement.
func (w *nfqwsDirectPreparationWitness) listingCurrent() error {
	entries, err := w.dir.ReadDir(8)
	if err != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "snapshot.json", "candidate.json":
		case policyAdditionFile:
			if w.prepState == directWriterNone {
				return ErrNFQWSScopedOwner
			}
		case policyAdditionLock:
			if !w.lockAttempted {
				return ErrNFQWSScopedOwner
			}
			info, err := w.dir.Stat(policyAdditionLock)
			if err != nil || !validCloudflareScanLockFile(info) || info.Size() > int64(len(policyAdditionMarker)) || w.lockInfo != nil && !os.SameFile(w.lockInfo, info) {
				return errors.Join(ErrNFQWSScopedOwner, err)
			}
		default:
			return ErrNFQWSScopedOwner
		}
	}
	return nil
}

// Read the retained descriptor, then compare the path again. A pathname open
// after a type check can block on a replaced FIFO; this never opens by name.
func (h nfqwsHeldImage) current(root *ownedfs.Root, name string) error {
	if h.file == nil || h.info == nil || root == nil || len(h.image) == 0 || len(h.image) > policyAdditionMaxBytes {
		return ErrNFQWSScopedOwner
	}
	data := make([]byte, len(h.image)+1)
	n, err := h.file.ReadAt(data, 0)
	if err != io.EOF || n != len(h.image) || !bytes.Equal(data[:n], h.image) {
		return ErrNFQWSScopedOwner
	}
	held, err := h.file.Stat()
	if err != nil || !held.Mode().IsRegular() || held.Size() != int64(len(h.image)) || !os.SameFile(h.info, held) {
		return ErrNFQWSScopedOwner
	}
	path, err := root.Stat(name)
	if err != nil || !path.Mode().IsRegular() || path.Size() != int64(len(h.image)) || runtime.GOOS != "windows" && path.Mode().Perm() != 0600 || !os.SameFile(h.info, path) {
		return ErrNFQWSScopedOwner
	}
	return nil
}

// retirePreparation publishes "removed" through the original anchored
// session and lock, replacing the held image only with this writer's own new
// staged inode. Caller holds w.mu, after prove.
func (w *nfqwsDirectPreparationWitness) retirePreparation(ctx context.Context, lan *LANPolicyRuntimePlan) error {
	if w.prepState != directWriterWritten {
		return nil
	}
	s, err := openPolicyAdditionRootSession(ctx, w.root, w.execution.lan.options)
	if err != nil {
		return err
	}
	defer s.close()
	info, err := s.root.RootInfo()
	if err != nil || !os.SameFile(info, w.dirInfo) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	lock, err := s.lock.Stat()
	if err != nil || w.lockInfo == nil || !os.SameFile(lock, w.lockInfo) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := w.prep.current(w.dir, policyAdditionFile); err != nil {
		return err
	}
	// The held image is the authority; the strict decoder only confirms that
	// this exact image is the original never-promoted active preparation.
	if err := s.decodeDocument(ctx, w.prep.image); err != nil {
		return err
	}
	if err := validateLANDirectPreparation(ctx, s, lan); err != nil {
		return err
	}
	if lanDirectPreparationStatus(s) != (PolicyAdditionStatus{ID: s.doc.ID, Complete: true}) {
		return ErrPolicyAdditionUnknown
	}
	s.doc.Phase = directWriterRemoved
	s.doc.Checksum = policyAdditionChecksum(s.doc)
	data, err := json.Marshal(s.doc)
	if err != nil || len(data) > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	old := w.prep
	if err := w.faultAt("preparation-remove"); err != nil {
		return w.preparationAfterFailure(old, err)
	}
	next, err := retainedWrite(s.root, policyAdditionFile, data)
	if err != nil {
		return w.preparationAfterFailure(old, err)
	}
	w.prep = next
	w.prepState = directWriterRemoved
	_ = old.file.Close()
	if err := w.faultAt("preparation-remove-sync"); err != nil {
		return err
	}
	if runtime.GOOS == "linux" && s.root.Sync() != nil {
		return ErrPolicyAdditionReceipt
	}
	return ctx.Err()
}

// A failed rename leaves the SAME original inode and image at the path, which
// stays retryable. Anything else is an unknown result for this witness.
func (w *nfqwsDirectPreparationWitness) preparationAfterFailure(old nfqwsHeldImage, cause error) error {
	if old.current(w.dir, policyAdditionFile) != nil {
		w.prepState = directWriterUnknown
		return errors.Join(ErrPolicyAdditionUnknown, cause)
	}
	return cause
}

// retireOwner removes exactly the held owner.json. Caller holds w.mu, after
// the preparation reached "removed" (or was never written).
func (w *nfqwsDirectPreparationWitness) retireOwner() error {
	switch w.ownerState {
	case directWriterNone, directWriterRemoved:
		return nil
	case directWriterWritten:
		if w.prepState == directWriterWritten {
			return ErrPolicyAdditionUnknown
		}
		if err := w.owner.current(w.ownerDir, "owner.json"); err != nil {
			return err
		}
		if err := w.faultAt("owner-remove"); err != nil {
			return w.ownerAfterFailure(err)
		}
		if err := w.ownerDir.Remove("owner.json"); err != nil {
			return w.ownerAfterFailure(err)
		}
		w.ownerState = directWriterUnlinked
	case directWriterUnlinked:
	default:
		return ErrPolicyAdditionUnknown
	}
	if _, err := w.ownerDir.Stat("owner.json"); !errors.Is(err, os.ErrNotExist) {
		w.ownerState = directWriterUnknown
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := w.faultAt("owner-remove-sync"); err != nil {
		return err
	}
	if err := syncDataplaneJournalDirectory(w.ownerDir); err != nil {
		return err
	}
	w.ownerState = directWriterRemoved
	_ = w.owner.file.Close()
	w.owner = nfqwsHeldImage{}
	return nil
}

func (w *nfqwsDirectPreparationWitness) ownerAfterFailure(cause error) error {
	if w.owner.current(w.ownerDir, "owner.json") == nil {
		return cause // Still the SAME held inode and image: retryable.
	}
	if _, err := w.ownerDir.Stat("owner.json"); errors.Is(err, os.ErrNotExist) {
		w.ownerState = directWriterUnlinked
		return cause
	}
	w.ownerState = directWriterUnknown
	return errors.Join(ErrPolicyAdditionUnknown, cause)
}

func (w *nfqwsDirectPreparationWitness) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	var err error
	for _, h := range []nfqwsHeldImage{w.candidate, w.owner, w.prep} {
		if h.file != nil {
			err = errors.Join(err, h.file.Close())
		}
	}
	for _, root := range []*ownedfs.Root{w.dir, w.ownerDir} {
		if root != nil {
			err = errors.Join(err, root.Close())
		}
	}
	return err
}
