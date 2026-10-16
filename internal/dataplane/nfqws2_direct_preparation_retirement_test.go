package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The original Stage retains the metadata writer. Production fixes its
// leaves to e.cleanupCurrent and e.verifyRollback; this fixture's NI/source
// leaves are deliberately incomplete, so only those two leaves are modeled.
func (f *preEffectLANFixture) stageDirectPreparation(t *testing.T) *nfqwsDirectPreparationWitness {
	t.Helper()
	f.snapshot(t, false)
	if err := f.e.gate.Stage(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("original Stage", err)
	}
	w := f.e.directPreparation
	if w == nil || w.self != w || w.execution != f.e || w.review != f.e.preEffectLAN || w.observe == nil || w.owners == nil {
		t.Fatal("original Stage retained no metadata writer")
	}
	w.owners = func(c context.Context) error {
		if c.Value(nfqws2ActiveExecutionKey{}) != f.e || !f.e.retired || f.refuse == "owners" {
			return ErrNFQWSScopedOwner
		}
		return f.e.material.control.CurrentForCleanup(c)
	}
	w.observe = func(c context.Context) error {
		f.reads++
		if c.Value(nfqws2ActiveExecutionKey{}) != f.e || !f.e.retired || f.refuse == "read-open" {
			return ErrNFQWSScopedOwner
		}
		if f.afterRead != nil {
			f.afterRead()
		}
		return f.e.material.control.CurrentForCleanup(c)
	}
	return w
}

// Models the NFQ Activate refusal after activationAttempted and before any
// seal, then that never-started participant's successful Rollback.
func (f *preEffectLANFixture) refuseNFQBeforeSeal(t *testing.T) {
	t.Helper()
	f.e.mu.Lock()
	f.e.activationAttempted = true
	f.e.mu.Unlock()
	f.physical = errors.New("modeled notifications.route.tracked")
	f.e.retired = true
	if f.e.activationSeal != nil || f.e.resource != nil || f.e.prepared != nil || f.e.binding != nil || f.e.started || f.e.launchInvoked || f.e.material.issuedSelection != nil {
		t.Fatal("phase model manufactured an activation receipt")
	}
}

// Phase model of native573 with the actual original writers. Snapshot, Stage
// and LAN Activate publish their real files; then the lost physical packet
// fence refuses NFQ Activate after activationAttempted and before any seal.
// Only the NFQ refusal itself and its never-started Rollback are modeled.
func (f *preEffectLANFixture) activateLANThenRefuseNFQ(t *testing.T) *nfqwsDirectPreparationWitness {
	t.Helper()
	w := f.stageDirectPreparation(t)
	if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("original LAN Activate", err)
	}
	if !f.e.lanActivationAttempted || f.e.neverActivatedLAN() {
		t.Fatal("phase model is not the LAN-activated 573 boundary")
	}
	f.refuseNFQBeforeSeal(t)
	return w
}

func directPreparationState(t *testing.T, f *preEffectLANFixture) (owner bool, status PolicyAdditionStatus) {
	t.Helper()
	_, err := os.Lstat(f.e.gate.ownerPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	status, inspectErr := f.e.gate.Binding.Inspect(f.ctx, f.e.plan.LAN, f.root)
	if inspectErr != nil && !errors.Is(inspectErr, os.ErrNotExist) {
		t.Fatal("original preparation unreadable", inspectErr)
	}
	return err == nil, status
}

func requireDirectPreparationActive(t *testing.T, f *preEffectLANFixture, cut string) {
	t.Helper()
	if owner, status := directPreparationState(t, f); !owner || !status.Complete || status.Removed {
		t.Fatal("refused retirement changed the original owner/preparation", cut, owner, status)
	}
}

// Equal bytes at a new inode. Rename the held original away first: Windows
// refuses to replace a path whose file this process still holds open.
func replaceHeldFile(path string, data []byte) error {
	if data == nil {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			return err
		}
	}
	if err := os.Rename(path, path+".old"); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Remove(path + ".old")
}

// Each actual Manager rollback() creates its own cycle; handled gate calls
// record themselves there. These model one cycle per gate Rollback, and the
// following VerifyRollback uses that SAME cycle through f.ctx.
func cycleContext(ctx context.Context) context.Context {
	c, _ := withDirectPreparationCycle(ctx)
	return c
}

func (f *preEffectLANFixture) nextCycle() context.Context {
	f.ctx = cycleContext(f.ctx)
	return f.ctx
}

type directPreparationCounters struct{ reads, cleanup, retires, inventories, rpdb int }

func (f *preEffectLANFixture) counters() directPreparationCounters {
	return directPreparationCounters{f.reads, f.model.cleanup, f.retires, f.inventories, f.model.rpdbReads}
}

func TestNFQWSDirectPreparationRetiresAfterLANActivateBeforeNFQSeal(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.activateLANThenRefuseNFQ(t)
	if owner, status := directPreparationState(t, f); !owner || !status.Complete || status.Removed {
		t.Fatal("LAN Activate did not publish its owner and preparation", owner, status)
	}
	before := f.counters()
	if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err != nil {
		t.Fatal("573: the original metadata-only preparation cannot complete after the physical boundary is lost", err)
	}
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
		t.Fatal("573: retired preparation not freshly verified", ok, err)
	}
	if owner, status := directPreparationState(t, f); owner || !status.Removed || status.Complete {
		t.Fatal("original owner/preparation not retired", owner, status)
	}
	if _, err := os.Stat(filepath.Join(f.root, "snapshot.json")); err != nil {
		t.Fatal("original Snapshot image removed", err)
	}
	after := f.counters()
	// Two complete fresh independent proofs; the physical CleanupGuard is
	// never consulted and therefore never waived for ordinary cleanup.
	if after.cleanup != before.cleanup || after.reads-before.reads != 2 || after.retires-before.retires != 2 || after.inventories-before.inventories < 4 || after.rpdb-before.rpdb < 4 {
		t.Fatal("retirement skipped a fresh observation or borrowed the physical guard", before, after)
	}
	// A repeated compensation re-observes everything; nothing is cached.
	if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err != nil {
		t.Fatal("idempotent retired preparation refused", err)
	}
	if f.reads-after.reads != 1 {
		t.Fatal("repeated compensation reused a previous observation")
	}
}

// Every writer result the original LAN Activate can leave behind.
func TestNFQWSDirectPreparationWriterStates(t *testing.T) {
	for _, cut := range []string{"owner-only", "owner-sync", "session-no-receipt", "receipt-sync"} {
		t.Run(cut, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			w := f.stageDirectPreparation(t)
			wantOwner, wantPrep, wantLock := directWriterWritten, directWriterNone, false
			switch cut {
			case "owner-only":
				f.physical = errors.New("forward boundary lost before the preparation session")
			case "owner-sync":
				w.fault = func(point string) error {
					if point == "owner-sync" {
						return errors.New("modeled owner directory sync failure")
					}
					return nil
				}
			case "session-no-receipt":
				// Preflight inside the opened session refuses an owned RPDB rule.
				f.model.rpdb = "73: from all lookup 254\n"
				wantLock = true
			case "receipt-sync":
				w.fault = func(point string) error {
					if point == "preparation-sync" {
						return errors.New("modeled preparation directory sync failure")
					}
					return nil
				}
				wantPrep, wantLock = directWriterWritten, true
			}
			if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err == nil {
				t.Fatal("modeled LAN Activate failure passed", cut)
			}
			if w.ownerState != wantOwner || w.prepState != wantPrep || w.lockAttempted != wantLock {
				t.Fatal("writer did not record its own result", cut, w.ownerState, w.prepState, w.lockAttempted)
			}
			w.fault = nil
			f.model.rpdb = "0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n"
			f.physical = errors.New("modeled notifications.route.tracked")
			f.e.retired = true
			if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err != nil {
				t.Fatal("original partial preparation not retired", cut, err)
			}
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
				t.Fatal("partial preparation not verified", cut, ok, err)
			}
			owner, status := directPreparationState(t, f)
			if owner || wantPrep == directWriterWritten && !status.Removed || wantPrep == directWriterNone && status != (PolicyAdditionStatus{}) {
				t.Fatal("partial preparation retired incorrectly", cut, owner, status)
			}
		})
	}
}

func cycleOf(ctx context.Context) *directPreparationCycle {
	c, _ := ctx.Value(directPreparationCycleKey{}).(*directPreparationCycle)
	return c
}

// An unknown writer result keeps the SAME witness and declines the
// metadata-only path: only the unchanged strict path may settle that owner.
func TestNFQWSDirectPreparationUnknownWriteDeclinesToStrictPath(t *testing.T) {
	for _, point := range []string{"owner-write", "preparation-write"} {
		t.Run(point, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			w := f.stageDirectPreparation(t)
			w.fault = func(p string) error {
				if p == point {
					return errors.New("modeled crash-boundary write error")
				}
				return nil
			}
			if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err == nil {
				t.Fatal("failed original writer passed")
			}
			f.refuseNFQBeforeSeal(t)
			for i := 0; i < 2; i++ {
				cleanup := f.model.cleanup
				if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil || f.model.cleanup == cleanup || cycleOf(f.ctx).rollback != nil {
					t.Fatal("unknown writer result left the strict path", point, err)
				}
				if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil || cycleOf(f.ctx).verify != nil {
					t.Fatal("unknown writer result verified", point)
				}
			}
			if f.e.directPreparation != w || f.reads != 0 {
				t.Fatal("unknown result replaced the witness or reached the metadata-only proof", f.reads)
			}
		})
	}
}

// Anything but the exact original never-sealed participant keeps the
// ordinary strict path, which still refuses without its physical boundary.
func TestNFQWSDirectPreparationNeedsExactNeverSealedParticipant(t *testing.T) {
	for _, cut := range []string{"seal", "issued", "resource", "prepared", "binding", "started", "launch", "journal-unknown", "not-retired", "replacement", "copied-witness", "foreign-witness", "foreign-review", "active-execution", "active-process", "closed-material"} {
		t.Run(cut, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			w := f.activateLANThenRefuseNFQ(t)
			switch cut {
			case "seal":
				f.e.activationSeal = &nfqws2ActiveActivationSeal{}
			case "issued":
				f.modelIssuedSelection(t, false)
			case "resource":
				f.e.resource = &NFQWSExecutionResource{}
			case "prepared":
				f.e.prepared = &NFQWSPreparedHandle{}
			case "binding":
				f.e.binding = &NFQWSScopedBinding{}
			case "started":
				f.e.started = true
			case "launch":
				f.e.launchInvoked = true
			case "journal-unknown":
				f.e.preparationErr = ErrExecutionJournal
			case "replacement":
				// A replacement pair keeps its own structural path.
				f.ctx = context.WithValue(f.ctx, xraySelectedTCPReplacementKey{}, &xraySelectedTCPReplacement{})
			case "not-retired":
				f.e.retired = false
			case "copied-witness":
				copied := &nfqwsDirectPreparationWitness{self: w, execution: f.e, review: w.review, root: w.root, dir: w.dir, dirInfo: w.dirInfo, ownerPath: w.ownerPath, ownerDir: w.ownerDir, ownerInfo: w.ownerInfo, candidate: w.candidate, owner: w.owner, prep: w.prep, ownerState: w.ownerState, prepState: w.prepState, lockAttempted: w.lockAttempted, lockInfo: w.lockInfo, observe: w.observe, owners: w.owners}
				f.e.directPreparation = copied
				t.Cleanup(func() { _ = w.close() })
			case "foreign-witness":
				w.execution = &nfqws2ActiveExecution{}
				t.Cleanup(func() { w.execution = f.e })
			case "foreign-review":
				w.review = &nfqwsPreEffectLANReview{}
				t.Cleanup(func() { w.review = f.e.preEffectLAN })
			case "active-execution", "active-process":
				nfqws2ActiveAdapterMu.Lock()
				if cut == "active-execution" {
					f.e.material.adapter.activeExecution = f.e
				} else {
					f.e.material.adapter.activeProcess = &nfqws2ActiveOwner{}
				}
				nfqws2ActiveAdapterMu.Unlock()
				t.Cleanup(func() {
					nfqws2ActiveAdapterMu.Lock()
					f.e.material.adapter.activeExecution, f.e.material.adapter.activeProcess = nil, nil
					nfqws2ActiveAdapterMu.Unlock()
				})
			case "closed-material":
				if err := f.e.material.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil || cycleOf(f.ctx).rollback != nil {
				t.Fatal("non-original participant was handled or retired without its physical boundary", cut, err)
			}
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil || cycleOf(f.ctx).verify != nil {
				t.Fatal("non-original participant verified", cut)
			}
			if f.reads != 0 {
				t.Fatal("non-original participant reached the metadata-only proof", cut)
			}
			requireDirectPreparationActive(t, f, cut)
		})
	}
}

// Every original file is identified by its held writer descriptor. Equal
// bytes at a new inode, a missing file or any other entry refuse.
func TestNFQWSDirectPreparationRefusesChangedOriginalFiles(t *testing.T) {
	for _, cut := range []string{"owner-inode", "owner-missing", "preparation-inode", "candidate-inode", "candidate-bytes", "snapshot-inode", "lock-inode", "foreign-entry", "staged-temporary", "promoted-destination", "transaction-directory"} {
		t.Run(cut, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			f.activateLANThenRefuseNFQ(t)
			replace := func(path string, data []byte) {
				t.Helper()
				if err := replaceHeldFile(path, data); err != nil {
					t.Fatal(err)
				}
			}
			switch cut {
			case "owner-inode":
				replace(f.e.gate.ownerPath(), nil)
			case "owner-missing":
				if err := os.Remove(f.e.gate.ownerPath()); err != nil {
					t.Fatal(err)
				}
			case "preparation-inode":
				replace(filepath.Join(f.root, policyAdditionFile), nil)
			case "candidate-inode":
				replace(filepath.Join(f.root, "candidate.json"), nil)
			case "candidate-bytes":
				replace(filepath.Join(f.root, "candidate.json"), []byte("{}"))
			case "snapshot-inode":
				replace(filepath.Join(f.root, "snapshot.json"), nil)
			case "lock-inode":
				replace(filepath.Join(f.root, policyAdditionLock), nil)
			case "foreign-entry":
				if err := os.WriteFile(filepath.Join(f.root, "foreign.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "staged-temporary":
				if err := os.WriteFile(filepath.Join(f.root, ".transaction-unknown"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "promoted-destination":
				if err := os.MkdirAll(filepath.Join(f.e.gate.StateRoot, "receipts", f.e.plan.PlanID), 0700); err != nil {
					t.Fatal(err)
				}
			case "transaction-directory":
				moved := f.root + ".moved"
				if err := os.Rename(f.root, moved); err != nil {
					t.Skip("platform keeps the held directory busy", err)
				}
				if err := os.Mkdir(f.root, 0700); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(f.root); _ = os.Rename(moved, f.root) })
			}
			if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil {
				t.Fatal("changed original file was retired", cut)
			}
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
				t.Fatal("changed original file was verified", cut)
			}
			if f.reads != 0 || f.model.cleanup != 0 {
				t.Fatal("changed file reached an observer or the strict guard", cut, f.reads, f.model.cleanup)
			}
			if cut == "owner-missing" || cut == "transaction-directory" {
				return
			}
			requireDirectPreparationActive(t, f, cut)
		})
	}
}

// No transition happens before the complete fresh proof passes, and the SAME
// witness completes once the refusing observation is clean again.
func TestNFQWSDirectPreparationProofPrecedesEveryTransition(t *testing.T) {
	for _, cut := range []string{"read-open", "owners", "retire", "inventory", "gate-inventory", "rpdb", "tool", "lock-held", "control", "cancel-after-read", "owner-after-read", "receipt-after-read", "foreign-after-read"} {
		t.Run(cut, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			w := f.activateLANThenRefuseNFQ(t)
			ctx := f.ctx
			restore := func() {}
			switch cut {
			case "rpdb":
				f.model.rpdb = "73: from all lookup 254\n"
				restore = func() { f.model.rpdb = "0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n" }
			case "tool":
				original := f.e.runtime.IPTables
				f.e.runtime.IPTables = "/other/iptables"
				restore = func() { f.e.runtime.IPTables = original }
			case "gate-inventory":
				original := f.e.gateInventoryCheck
				f.e.gateInventoryCheck = func(context.Context) error { return ErrBackendInventoryUnknown }
				restore = func() { f.e.gateInventoryCheck = original }
			case "lock-held":
				other, err := openPolicyAdditionRootSession(f.ctx, f.root, f.e.lan.options)
				if err != nil {
					t.Fatal("foreign session", err)
				}
				restore = other.close
			case "control":
				_ = f.e.material.control.Close()
			case "cancel-after-read":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				f.afterRead = cancel
			case "owner-after-read":
				f.afterRead = func() {
					if err := replaceHeldFile(f.e.gate.ownerPath(), nil); err != nil {
						t.Error(err)
					}
				}
			case "receipt-after-read":
				f.afterRead = func() {
					if err := replaceHeldFile(filepath.Join(f.root, policyAdditionFile), nil); err != nil {
						t.Error(err)
					}
				}
			case "foreign-after-read":
				f.afterRead = func() { _ = os.WriteFile(filepath.Join(f.root, "foreign.json"), []byte("{}"), 0600) }
				restore = func() { _ = os.Remove(filepath.Join(f.root, "foreign.json")) }
			default:
				f.refuse = cut
			}
			if err := f.e.gate.Rollback(cycleContext(ctx), f.e.plan, f.root); err == nil {
				t.Fatal("unsettled consumer/kernel/source observation retired the preparation", cut)
			}
			if cut == "lock-held" {
				restore() // The state reader itself needs the lock.
				restore = func() {}
			}
			requireDirectPreparationActive(t, f, cut)
			if w.ownerState != directWriterWritten || w.prepState != directWriterWritten || f.model.cleanup != 0 {
				t.Fatal("refused proof moved a writer state or used the strict guard", cut, w.ownerState, w.prepState)
			}
			switch cut {
			case "control", "cancel-after-read", "owner-after-read", "receipt-after-read":
				return // A changed control/file cannot be revived by a retry.
			}
			f.refuse, f.afterRead = "", nil
			restore()
			if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err != nil {
				t.Fatal("SAME original witness could not complete after a clean observation", cut, err)
			}
			if owner, status := directPreparationState(t, f); owner || !status.Removed {
				t.Fatal("retry did not retire the original preparation", cut, owner, status)
			}
		})
	}
}

// Transition failures keep the SAME witness. A failed rename stays
// retryable; a result that cannot be identified becomes unknown.
func TestNFQWSDirectPreparationTransitionFailures(t *testing.T) {
	for _, point := range []string{"preparation-remove", "preparation-remove-sync", "owner-remove", "owner-remove-sync", "preparation-replaced", "owner-replaced", "owner-swapped"} {
		t.Run(point, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			w := f.activateLANThenRefuseNFQ(t)
			w.fault = func(p string) error {
				switch {
				case p == point:
					return errors.New("modeled transition failure")
				case point == "preparation-replaced" && p == "preparation-remove":
					if err := replaceHeldFile(filepath.Join(f.root, policyAdditionFile), nil); err != nil {
						t.Error(err)
					}
					return errors.New("modeled rename with unknown result")
					case point == "owner-replaced" && p == "owner-remove":
					if err := replaceHeldFile(f.e.gate.ownerPath(), nil); err != nil {
						t.Error(err)
					}
					return errors.New("modeled unlink with unknown result")
				case point == "owner-swapped" && p == "owner-remove":
					// Swapped after the last bookend: the private move must
					// detect a foreign inode and put it back untouched.
					if err := replaceHeldFile(f.e.gate.ownerPath(), nil); err != nil {
						t.Error(err)
					}
				}
				return nil
			}
			if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil {
				t.Fatal("transition failure reported success", point)
			}
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
				t.Fatal("incomplete transition verified", point)
			}
			w.fault = nil
			cleanup := f.model.cleanup
			err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root)
			if strings.HasSuffix(point, "-replaced") || point == "owner-swapped" {
				// An unidentified result declines to the strict path, which
				// cannot settle it without its physical boundary.
				if err == nil || cycleOf(f.ctx).rollback != nil || f.model.cleanup == cleanup || f.e.directPreparation != w {
					t.Fatal("unidentified transition result left the strict path", point, err)
				}
				if _, statErr := os.Stat(f.e.gate.ownerPath()); statErr != nil {
					t.Fatal("unidentified owner.json was removed", point, statErr)
				}
				return
			}
			if err != nil {
				t.Fatal("SAME original witness could not retry its transition", point, err)
			}
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
				t.Fatal("retried transition not verified", point, ok, err)
			}
			if owner, status := directPreparationState(t, f); owner || !status.Removed {
				t.Fatal("retried transition incomplete", point, owner, status)
			}
		})
	}
}

// A replacement with a prior owner, or a participant without the original
// empty Snapshot writer, never acquires the metadata writer.
func TestNFQWSDirectPreparationOnlyAfterOriginalEmptySnapshot(t *testing.T) {
	f := newPreEffectLANFixture(t)
	if err := writeNetworkPolicyGate(filepath.Join(f.root, "snapshot.json"), networkPolicyGateSnapshot{}); err != nil {
		t.Fatal(err)
	}
	if err := f.e.gate.Stage(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("ordinary Stage", err)
	}
	if f.e.directPreparation != nil {
		t.Fatal("decoded snapshot acquired the original metadata writer")
	}
	if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("ordinary Activate", err)
	}
	f.refuseNFQBeforeSeal(t)
	if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil || f.model.cleanup == 0 {
		t.Fatal("participant without the original writer left strict cleanup", err)
	}
	requireDirectPreparationActive(t, f, "no-writer")
}

// A consumer/kernel/source model only, as preEffectPendingConsumer. The
// actual Manager compensation, journal publications and pending owner run.
type directPreparationConsumer struct {
	*fakeAdapter
	f            *preEffectLANFixture
	t            *testing.T
	sealed       bool
	proof        bool
	failValidate bool
	fault        func(f *preEffectLANFixture, point string) error
}

func (a *directPreparationConsumer) Snapshot(context.Context, Plan, string) error { return nil }
func (a *directPreparationConsumer) Stage(context.Context, Plan, string) error {
	a.t.Helper()
	w := a.f.e.directPreparation
	if w == nil {
		return ErrNFQWSScopedOwner
	}
	if a.fault != nil {
		w.fault = func(point string) error { return a.fault(a.f, point) }
	}
	w.owners = func(c context.Context) error {
		if c.Value(nfqws2ActiveExecutionKey{}) != a.f.e || !a.f.e.retired {
			return ErrNFQWSScopedOwner
		}
		return a.f.e.material.control.CurrentForCleanup(c)
	}
	w.observe = func(c context.Context) error {
		a.f.reads++
		if c.Value(nfqws2ActiveExecutionKey{}) != a.f.e || !a.f.e.retired || a.f.refuse == "read-open" {
			return ErrNFQWSScopedOwner
		}
		return a.f.e.material.control.CurrentForCleanup(c)
	}
	return nil
}
func (a *directPreparationConsumer) Validate(context.Context, Plan, string) error {
	if a.failValidate {
		// The boundary is lost after Stage, before LAN Activate.
		a.f.physical = errors.New("modeled notifications.route.tracked")
		return a.f.physical
	}
	return nil
}
func (a *directPreparationConsumer) Activate(context.Context, Plan, string) error {
	a.f.e.mu.Lock()
	a.f.e.activationAttempted = true
	a.f.e.mu.Unlock()
	if a.sealed {
		a.f.modelIssuedSelection(a.t, false)
	}
	a.f.physical = errors.New("modeled notifications.route.tracked")
	return preflightRefusalError{a.f.physical}
}
func (a *directPreparationConsumer) Rollback(context.Context, Plan, string) error {
	a.f.e.retired = true
	return nil
}
func (a *directPreparationConsumer) VerifyRollback(ctx context.Context, _ Plan, _ string) (bool, error) {
	return a.proof, ctx.Err()
}

func directPreparationManager(t *testing.T, sealed bool, refuse string) (*preEffectLANFixture, Execution, error) {
	t.Helper()
	return directPreparationManagerRun(t, &directPreparationConsumer{sealed: sealed}, refuse)
}

func directPreparationManagerRun(t *testing.T, a *directPreparationConsumer, refuse string) (*preEffectLANFixture, Execution, error) {
	t.Helper()
	f := newPreEffectLANFixture(t)
	m := f.e.material.manager
	a.fakeAdapter, a.f, a.t, a.proof = &fakeAdapter{id: "nfqws2"}, f, t, true
	m.Adapters["nfqws2"] = a
	f.e.plan.Adapters = []string{NetworkPolicyAdapterID, "nfqws2"}
	f.e.plan.NetworkProfileID = executionNetwork
	f.e.selection.plan = cloneExecutionResourcePlan(f.e.plan)
	if err := os.Remove(f.root); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(f.root)); err != nil {
		t.Fatal(err)
	}
	m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	f.ctx = WithReviewGuard(f.ctx, func(context.Context) error { return nil })
	f.refuse = refuse
	result, err := m.Apply(f.ctx, f.e.plan, nil)
	return f, result, err
}

func requireDirectPreparationSteps(t *testing.T, result Execution) {
	t.Helper()
	var lan, nfq bool
	for _, step := range result.Steps {
		if step.Phase == "activate" && step.Adapter == NetworkPolicyAdapterID && step.State == "passed" {
			lan = true
		}
		if step.Phase == "activate" && step.Adapter == "nfqws2" && step.State == "failed" {
			nfq = true
		}
	}
	if !lan || !nfq {
		t.Fatal("Manager did not run LAN Activate then the refused NFQ Activate", result.Steps)
	}
}

func TestNFQWSDirectPreparationManagerCompensationSettlesWithoutRollbackVerified(t *testing.T) {
	f, result, err := directPreparationManager(t, false, "")
	if err == nil || result.State != "rolled-back" || result.RollbackVerified || f.e.material.manager.HasPendingManagedNFQWS() {
		t.Fatal("573 compensation did not settle the original metadata", result.State, result.RollbackVerified, err)
	}
	requireDirectPreparationSteps(t, result)
	if owner, status := directPreparationState(t, f); owner || !status.Removed {
		t.Fatal("Manager compensation left the original owner/preparation", owner, status)
	}
	if f.model.cleanup != 0 || f.reads != 2 {
		t.Fatal("Manager compensation used the physical guard or skipped a proof", f.model.cleanup, f.reads)
	}
	readPreEffectTerminal(t, f)
}

func TestNFQWSDirectPreparationPendingOwnerCompletesOnRetry(t *testing.T) {
	f, result, err := directPreparationManager(t, false, "read-open")
	m := f.e.material.manager
	if err == nil || result.State != "rollback-failed" || result.RollbackVerified || !m.HasPendingManagedNFQWS() {
		t.Fatal("refused first proof was not retained as the SAME pending owner", result.State, err)
	}
	requireDirectPreparationActive(t, f, "first-cycle")
	f.refuse = ""
	if err := m.JoinPendingManagedNFQWS(f.ctx); err != nil || m.HasPendingManagedNFQWS() {
		t.Fatal("SAME pending owner could not complete its own metadata through the public Join", err)
	}
	if owner, status := directPreparationState(t, f); owner || !status.Removed {
		t.Fatal("pending completion left the original owner/preparation", owner, status)
	}
	readPreEffectTerminal(t, f)
}

func TestNFQWSDirectPreparationSealedParticipantKeepsStrictCompensation(t *testing.T) {
	f, result, err := directPreparationManager(t, true, "")
	m := f.e.material.manager
	if err == nil || result.State != "rollback-failed" || result.RollbackVerified || !m.HasPendingManagedNFQWS() {
		t.Fatal("sealed participant left strict compensation", result.State, err)
	}
	if f.reads != 0 || f.model.cleanup == 0 {
		t.Fatal("sealed participant reached the metadata-only proof", f.reads, f.model.cleanup)
	}
	if err := m.JoinPendingManagedNFQWS(f.ctx); err == nil || !m.HasPendingManagedNFQWS() {
		t.Fatal("sealed participant completed without its physical boundary")
	}
	requireDirectPreparationActive(t, f, "sealed")
}

// The handled gate path exists only inside an actual Manager compensation
// cycle, and records itself exactly once per cycle.
func TestNFQWSDirectPreparationRequiresOneManagerCycle(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.activateLANThenRefuseNFQ(t)
	plain := f.ctx
	if err := f.e.gate.Rollback(plain, f.e.plan, f.root); err == nil || f.reads != 0 || f.model.cleanup == 0 {
		t.Fatal("gate Rollback outside a Manager cycle left strict cleanup", err)
	}
	cleanup := f.model.cleanup
	if ok, err := f.e.gate.VerifyRollback(f.nextCycle(), f.e.plan, f.root); ok || err == nil || f.reads != 0 {
		t.Fatal("VerifyRollback without its cycle's Rollback verified", ok, err)
	}
	c := f.nextCycle()
	if err := f.e.gate.Rollback(c, f.e.plan, f.root); err != nil {
		t.Fatal("original cycle refused", err)
	}
	if err := f.e.gate.Rollback(c, f.e.plan, f.root); err == nil {
		t.Fatal("second handled Rollback in the SAME cycle accepted")
	}
	if ok, err := f.e.gate.VerifyRollback(c, f.e.plan, f.root); err != nil || !ok {
		t.Fatal("cycle verify refused", ok, err)
	}
	if ok, err := f.e.gate.VerifyRollback(c, f.e.plan, f.root); ok || err == nil {
		t.Fatal("second handled VerifyRollback in the SAME cycle accepted")
	}
	if f.model.cleanup != cleanup {
		t.Fatal("handled cycle consulted the physical guard")
	}
}

// The private one-use command is issued before the seal; without a seal it
// cannot be consumed, so its presence alone does not block retirement.
func TestNFQWSDirectPreparationRetiresWithCommandBeforeSeal(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.activateLANThenRefuseNFQ(t)
	f.e.material.command.ID = "0123456789abcdef0123456789abcdef"
	if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err != nil {
		t.Fatal("unsealed command blocked metadata retirement", err)
	}
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
		t.Fatal(ok, err)
	}
}

// A transition result this writer cannot identify keeps the SAME pending
// owner; every retry declines to the strict path and retires nothing.
func TestNFQWSDirectPreparationPendingUnknownKeepsSameOwner(t *testing.T) {
	a := &directPreparationConsumer{fault: func(f *preEffectLANFixture, point string) error {
		if point != "preparation-remove" {
			return nil
		}
		if err := replaceHeldFile(filepath.Join(f.root, policyAdditionFile), nil); err != nil {
			return err
		}
		return errors.New("modeled rename with unknown result")
	}}
	f, result, err := directPreparationManagerRun(t, a, "")
	m := f.e.material.manager
	if err == nil || result.State != "rollback-failed" || result.RollbackVerified || !m.HasPendingManagedNFQWS() {
		t.Fatal("unknown transition was not retained", result.State, err)
	}
	reads := f.reads
	for i := 0; i < 2; i++ {
		if err := m.JoinPendingManagedNFQWS(f.ctx); err == nil || !m.HasPendingManagedNFQWS() {
			t.Fatal("unknown transition settled", err)
		}
	}
	if f.reads != reads {
		t.Fatal("unknown transition re-entered the metadata-only proof")
	}
	if _, err := os.Stat(f.e.gate.ownerPath()); err != nil {
		t.Fatal("owner retired after an unknown preparation result", err)
	}
}

// The production witness leaves are exactly the participant's own cleanup
// and full NFQ absence readers; the fixture's incomplete NI/source leaves
// therefore refuse, and nothing is retired.
func TestNFQWSDirectPreparationProductionLeavesAreTheOriginalReaders(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.snapshot(t, false)
	if err := f.e.gate.Stage(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal(err)
	}
	if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal(err)
	}
	f.refuseNFQBeforeSeal(t)
	w := f.e.directPreparation
	if err := f.e.cleanupCurrent(f.ctx); err == nil {
		t.Fatal("fixture unexpectedly completes the original owners")
	}
	if err := w.owners(f.ctx); err == nil {
		t.Fatal("production owner leaf is not the original cleanup reader")
	}
	if err := w.observe(f.ctx); err == nil {
		t.Fatal("production observe leaf is not the original NFQ absence reader")
	}
	if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil {
		t.Fatal("incomplete original readers retired the preparation")
	}
	requireDirectPreparationActive(t, f, "production-leaves")
}

// Same inode, same size, different bytes: the held image comparison refuses.
func TestNFQWSDirectPreparationRefusesInPlaceEdits(t *testing.T) {
	for _, cut := range []string{"owner", "preparation", "candidate"} {
		t.Run(cut, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			f.activateLANThenRefuseNFQ(t)
			path := map[string]string{"owner": f.e.gate.ownerPath(), "preparation": filepath.Join(f.root, policyAdditionFile), "candidate": filepath.Join(f.root, "candidate.json")}[cut]
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt([]byte{' '}, info.Size()-2); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil || f.reads != 0 {
				t.Fatal("same-inode edit was retired", cut, err)
			}
			if _, err := os.Stat(f.e.gate.ownerPath()); err != nil {
				t.Fatal("owner removed after a refused proof", cut, err)
			}
		})
	}
}

// An owner that appears after Stage is never this preparation's owner.
func TestNFQWSDirectPreparationRefusesPriorOwner(t *testing.T) {
	f := newPreEffectLANFixture(t)
	w := f.stageDirectPreparation(t)
	other, err := f.e.gate.gateFor(f.e.plan)
	if err != nil {
		t.Fatal(err)
	}
	other.PlanID = "dp-fedcba9876543210"
	if err := writeNetworkPolicyGate(f.e.gate.ownerPath(), other); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(f.e.gate.ownerPath())
	if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err == nil {
		t.Fatal("Activate replaced a prior owner")
	}
	if w.ownerState != directWriterNone || w.ownerDir != nil {
		t.Fatal("prior owner was attributed to the original writer", w.ownerState)
	}
	f.refuseNFQBeforeSeal(t)
	if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil || f.reads != 0 {
		t.Fatal("prior owner was retired or ignored", err)
	}
	if after, _ := os.ReadFile(f.e.gate.ownerPath()); string(after) != string(before) {
		t.Fatal("prior owner changed")
	}
}

// Only the lock this writer created is accepted; a foreign lock refuses even
// after its holder released it.
func TestNFQWSDirectPreparationRefusesForeignLock(t *testing.T) {
	f := newPreEffectLANFixture(t)
	w := f.stageDirectPreparation(t)
	other, err := openPolicyAdditionRootSession(f.ctx, f.root, f.e.lan.options)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err == nil {
		t.Fatal("preparation session adopted a foreign lock")
	}
	if w.lockAttempted || w.lockInfo != nil || w.ownerState != directWriterWritten {
		t.Fatal("foreign lock was attributed to the original writer", w.lockAttempted, w.ownerState)
	}
	f.refuseNFQBeforeSeal(t)
	for _, release := range []bool{false, true} {
		if release {
			other.close()
		}
		if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil || f.reads != 0 {
			t.Fatal("foreign lock accepted", release, err)
		}
		if _, err := os.Stat(f.e.gate.ownerPath()); err != nil {
			t.Fatal("owner retired beside a foreign lock", err)
		}
	}
}

// A missing original lock refuses and is never recreated by retirement.
func TestNFQWSDirectPreparationRefusesMissingLock(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.activateLANThenRefuseNFQ(t)
	lock := filepath.Join(f.root, policyAdditionLock)
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil || f.reads != 0 {
			t.Fatal("missing original lock accepted", err)
		}
		if _, err := os.Stat(lock); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("retirement recreated a lock", err)
		}
	}
	requireDirectPreparationActive(t, f, "missing-lock")
}

// A later cycle can verify only after its own handled Rollback.
func TestNFQWSDirectPreparationVerifyNeedsItsOwnCycleRollback(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.activateLANThenRefuseNFQ(t)
	if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := f.e.gate.VerifyRollback(f.nextCycle(), f.e.plan, f.root); ok || err == nil {
		t.Fatal("verification without its cycle's Rollback accepted")
	}
}

// The physical boundary can also be lost after Stage and before LAN Activate
// (Validate, Canary or the Manager's network check). Only candidate.json was
// published; the never-activated Snapshot witness refuses that extra entry.
func TestNFQWSDirectPreparationRetiresAfterStageBeforeLANActivate(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.stageDirectPreparation(t)
	f.physical = errors.New("modeled notifications.route.tracked")
	f.e.retired = true
	if !f.e.neverActivatedLAN() {
		t.Fatal("phase model is not before LAN Activate")
	}
	if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err != nil {
		t.Fatal("post-Stage refusal cannot complete without its physical boundary", err)
	}
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
		t.Fatal("post-Stage refusal not verified", ok, err)
	}
	if owner, status := directPreparationState(t, f); owner || status != (PolicyAdditionStatus{}) {
		t.Fatal("post-Stage retirement left LAN metadata", owner, status)
	}
	if f.model.cleanup != 0 || f.reads != 2 {
		t.Fatal("post-Stage retirement used the physical guard or skipped a proof", f.model.cleanup, f.reads)
	}
}

func TestNFQWSDirectPreparationPostStageRefusesForeignEntries(t *testing.T) {
	for _, cut := range []string{"owner", "preparation", "lock"} {
		t.Run(cut, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			f.stageDirectPreparation(t)
			switch cut {
			case "owner":
				state, _ := f.e.gate.gateFor(f.e.plan)
				if err := writeNetworkPolicyGate(f.e.gate.ownerPath(), state); err != nil {
					t.Fatal(err)
				}
			case "preparation":
				if err := os.WriteFile(filepath.Join(f.root, policyAdditionFile), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.WriteFile(filepath.Join(f.root, policyAdditionLock), []byte(policyAdditionMarker), 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.physical = errors.New("modeled notifications.route.tracked")
			f.e.retired = true
			if err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root); err == nil || f.reads != 0 {
				t.Fatal("foreign post-Stage entry retired", cut, err)
			}
		})
	}
}

func TestNFQWSDirectPreparationManagerSettlesPostStageRefusal(t *testing.T) {
	f, result, err := directPreparationManagerRun(t, &directPreparationConsumer{failValidate: true}, "")
	m := f.e.material.manager
	if err == nil || result.State != "rolled-back" || result.RollbackVerified || m.HasPendingManagedNFQWS() {
		t.Fatal("post-Stage refusal did not settle", result.State, err)
	}
	for _, step := range result.Steps {
		if step.Phase == "activate" {
			t.Fatal("post-Stage model crossed into Activate", step)
		}
	}
	if f.model.cleanup != 0 || f.reads != 2 {
		t.Fatal("post-Stage compensation used the physical guard or skipped a proof", f.model.cleanup, f.reads)
	}
	readPreEffectTerminal(t, f)
}
