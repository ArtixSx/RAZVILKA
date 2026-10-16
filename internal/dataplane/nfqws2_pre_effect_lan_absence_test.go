package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

type preEffectLANFixture struct {
	e                           *nfqws2ActiveExecution
	ctx                         context.Context
	root                        string
	model                       *networkPolicyDirectAbsenceModel
	reads, retires, inventories int
	refuse                      string
	afterRead                   func()
	physical                    error
}

// Actual original Gate/control, registered adapters, Snapshot writer, retained
// file/directory inodes and typed NI brackets. Only NI/kernel/source leaves are
// explicit models. No public factory, native process or packet permission is
// claimed. The original production observer is separately tested to refuse
// this deliberately incomplete source model.
func newPreEffectLANFixture(t *testing.T) *preEffectLANFixture {
	t.Helper()
	f := &preEffectLANFixture{model: &networkPolicyDirectAbsenceModel{rpdb: "0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n"}}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	var admission operationgate.Gate
	ctx, release, err := admission.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := admission.ReviewControlEpoch(ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, lm, _ := lanDirectReceiptFixture(t)
	b.Runtime.Runner = f.model
	b.Runtime.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error { return f.physical }
	b.ApplyGuard = func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error { return f.physical }
	b.CleanupGuard = func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error {
		f.model.cleanup++
		return f.physical
	}
	b.RetireCheck = func(c context.Context, p *LANPolicyRuntimePlan) error {
		f.retires++
		if c.Value(nfqws2ActiveExecutionKey{}) != f.e || !reflect.DeepEqual(p, lm.plan) || f.refuse == "retire" {
			return ErrNetworkPolicyConsumers
		}
		return c.Err()
	}
	identity, _ := networkPolicyIdentityFixture()
	identity.mode = LANPolicyNFQWSDirectMode
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: LANPolicyNFQWSDirectMode, Binding: b, InventoryCheck: func(c context.Context, got netidentity.Identity, p *LANPolicyRuntimePlan) error {
		f.inventories++
		if got != identity.value || c.Value(nfqws2ActiveExecutionKey{}) != f.e || f.refuse == "inventory" {
			return ErrBackendInventoryUnknown
		}
		return c.Err()
	}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	m := New(privateScopedXrayFixtureDir(t))
	a := NewNFQWS2Adapter()
	a.Runner = &nfqwsFakeRunner{}
	for _, adapter := range []Adapter{gate, a} {
		if err := m.Register(adapter); err != nil {
			t.Fatal(err)
		}
	}
	p, spec, _ := nfqwsScopedFixture(t)
	p.PlanID, p.LAN = "dp-0123456789abcdef", lm.plan
	p.Routes[0].NetworkPolicyRole = "override"
	material := &NFQWSActiveMaterial{manager: m, managerRoot: m.StateRoot, adapter: a, control: control, executionBound: true}
	material.self = material
	selection := &NFQWSScopedSelection{prepared: material, plan: cloneExecutionResourcePlan(p)}
	selection.self = selection
	// BindExecution retains this comparison selection in execution.selection.
	// issuedSelection is produced later by prepareActivation, not by binding.
	e := &nfqws2ActiveExecution{material: material, selection: selection, comparisonSelection: selection, plan: p, spec: spec, cleanup: cleanup, gate: gate, lan: gate.Binding, runtime: gate.Binding.Runtime, runtimeFrozen: *gate.Binding.Runtime, lanFrozen: *gate.Binding, gateInventoryCheck: gate.InventoryCheck}
	e.self = e
	material.execution = e
	f.e, f.ctx, f.root = e, context.WithValue(ctx, nfqws2ActiveExecutionKey{}, e), filepath.Join(m.StateRoot, "transactions", p.PlanID, NetworkPolicyAdapterID)
	if err := os.MkdirAll(f.root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = material.Close() })
	return f
}

func (f *preEffectLANFixture) snapshot(t *testing.T, modelSource bool) {
	t.Helper()
	if err := f.e.gate.Snapshot(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("original Snapshot", err)
	}
	if f.e.preEffectLAN == nil {
		t.Fatal("Snapshot did not retain its authored empty image")
	}
	if modelSource {
		f.modelSource()
	}
}

func TestNFQWSPreEffectSnapshotBeforeActivationSelectionIsIssued(t *testing.T) {
	f := newPreEffectLANFixture(t)
	if f.e.material.issuedSelection != nil || f.e.activationSeal != nil {
		t.Fatal("fixture manufactured a future activation receipt")
	}
	f.snapshot(t, false)
	if f.e.material.issuedSelection != nil || f.e.activationSeal != nil || !f.e.neverActivatedLAN() {
		t.Fatal("Snapshot produced activation authority")
	}
}

func TestNFQWSPreEffectSnapshotRejectsInvalidSelectionTransition(t *testing.T) {
	for _, kind := range []string{"missing-comparison", "replaced-comparison", "premature-issued", "seal-without-issued", "issued-with-foreign-seal"} {
		t.Run(kind, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			switch kind {
			case "missing-comparison":
				f.e.comparisonSelection = nil
			case "replaced-comparison":
				copy := &NFQWSScopedSelection{prepared: f.e.material, source: f.e.selection.source, plan: cloneExecutionResourcePlan(f.e.plan)}
				copy.self = copy
				f.e.selection = copy
			case "premature-issued":
				f.e.material.issuedSelection = f.e.selection
			case "seal-without-issued":
				f.e.activationSeal = &nfqws2ActiveActivationSeal{}
			case "issued-with-foreign-seal":
				f.e.material.issuedSelection = f.e.selection
				seal := &nfqws2ActiveActivationSeal{selection: f.e.selection}
				seal.self = seal
				f.e.activationSeal = seal
			}
			if err := f.e.gate.Snapshot(f.ctx, f.e.plan, f.root); err == nil || f.e.preEffectLAN != nil {
				t.Fatal("invalid comparison/activation transition produced an original Snapshot")
			}
			if _, err := os.Stat(filepath.Join(f.root, "snapshot.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid participant wrote snapshot", err)
			}
		})
	}
}

// Explicit phase model, not a native issuance or a reconstructed authority.
// ReviewNFQWSScopedSelection's real constructor leaves prepared=nil/plan zero;
// only reviewNFQWSScopedPreparedSelection fills those comparison-only fields.
// Keep that exact distinction while the fixture's source/NI leaves remain its
// deliberately incomplete models. No Current/Start permission is claimed.
func (f *preEffectLANFixture) modelIssuedSelection(t *testing.T, consumed bool) {
	t.Helper()
	old := f.e.selection
	selection := &NFQWSScopedSelection{source: old.source, reference: old.reference, spec: f.e.spec.Clone()}
	selection.self = selection
	seal := &nfqws2ActiveActivationSeal{execution: f.e, selection: selection, spec: selection.spec.Clone(), consumed: consumed}
	seal.self = seal
	f.e.material.issuedSelection = selection
	f.e.selection, f.e.activationSeal = selection, seal
	f.e.activationAttempted, f.e.lanActivationAttempted = true, true
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNFQWSPreEffectIssuedSelectionReachesStrictCleanupWithoutNoEffectGrant(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		t.Run(map[bool]string{false: "issued-before-consume", true: "consumed"}[consumed], func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			f.snapshot(t, true)
			f.modelIssuedSelection(t, consumed)
			f.e.retired = true
			originalSnapshot := f.e.preEffectLAN
			if err := f.e.gate.Snapshot(f.ctx, f.e.plan, f.root); err == nil || f.e.preEffectLAN != originalSnapshot {
				t.Fatal("issued selection acquired or replaced a no-effect Snapshot")
			}
			if f.e.selection.prepared != nil || !reflect.DeepEqual(f.e.selection.plan, Plan{}) {
				t.Fatal("phase model manufactured comparison-only fields")
			}
			if handled, err := f.e.gate.inspectPreEffectNFQAbsence(f.ctx, f.e.plan, f.root, false); handled || err != nil {
				t.Fatal("actual issued shape blocked strict fallback", handled, err)
			}
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
				t.Fatal("issued phase blocked ordinary strict cleanup", err)
			}
			if f.reads != 0 || f.model.cleanup != 2 || f.retires != 1 || f.model.rpdbReads != 2 {
				t.Fatal("issued phase borrowed no-effect proof", f.reads, f.model.cleanup, f.retires, f.model.rpdbReads)
			}
			f.physical = ErrReviewChanged
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
				t.Fatal("issued phase waived strict physical scope")
			}
		})
	}
}

func TestNFQWSPreEffectIssuedPendingCleanupPreservesStrictCancellation(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.snapshot(t, true)
	f.modelIssuedSelection(t, true)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	ordinary := f.e.cleanupCurrent(ctx)
	if !errors.Is(ordinary, context.Canceled) {
		t.Fatal("fixture did not reach original canceled cleanup", ordinary)
	}
	if pending := f.e.pendingCleanupCurrent(ctx); !errors.Is(pending, context.Canceled) {
		t.Fatal("pending issued cleanup was intercepted before strict fallback", pending)
	}
	if f.reads != 0 {
		t.Fatal("pending issued cleanup called no-effect observer")
	}
}

func TestNFQWSPreEffectIssuedSelectionRejectsCopiesAndMissingClaims(t *testing.T) {
	for _, cut := range []string{"copied-selection", "closed-selection", "different-source", "different-reference", "selection-spec", "execution-spec", "seal-spec", "copied-seal", "foreign-seal-execution", "foreign-seal-selection", "missing-issued", "missing-seal", "missing-comparison", "comparison-as-issued", "prepared-claim", "missing-execution-binding"} {
		t.Run(cut, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			f.snapshot(t, true)
			f.modelIssuedSelection(t, true)
			f.e.retired = true
			selection, seal := f.e.selection, f.e.activationSeal
			switch cut {
			case "copied-selection":
				copy := &NFQWSScopedSelection{self: selection, source: selection.source, reference: selection.reference, spec: selection.spec.Clone()}
				f.e.selection = copy
			case "closed-selection":
				if err := selection.Close(); err != nil {
					t.Fatal(err)
				}
			case "different-source":
				selection.source = &strategylab.SelectedCandidateReview{}
			case "different-reference":
				selection.reference.CandidateID = "different"
			case "selection-spec":
				selection.spec.Queue++
			case "execution-spec":
				f.e.spec.Queue++
			case "seal-spec":
				seal.spec.Queue++
			case "copied-seal":
				copy := &nfqws2ActiveActivationSeal{self: seal, execution: f.e, selection: selection, spec: seal.spec.Clone()}
				f.e.activationSeal = copy
			case "foreign-seal-execution":
				seal.execution = &nfqws2ActiveExecution{}
			case "foreign-seal-selection":
				seal.selection = f.e.comparisonSelection
			case "missing-issued":
				f.e.material.issuedSelection = nil
			case "missing-seal":
				f.e.activationSeal = nil
			case "missing-comparison":
				f.e.comparisonSelection = nil
			case "comparison-as-issued":
				f.e.comparisonSelection = selection
			case "prepared-claim":
				selection.prepared = f.e.material
			case "missing-execution-binding":
				f.e.material.executionBound = false
			}
			if handled, err := f.e.gate.inspectPreEffectNFQAbsence(f.ctx, f.e.plan, f.root, false); !handled || err == nil {
				t.Fatal("invalid original issued tuple fell through to strict cleanup", cut, handled, err)
			}
			if f.reads != 0 || f.model.cleanup != 0 || f.retires != 0 || f.model.rpdbReads != 0 {
				t.Fatal("invalid tuple reached no-effect or strict kernel observers", cut)
			}
		})
	}
}

func (f *preEffectLANFixture) modelSource() {
	f.e.preEffectLAN.owners = func(c context.Context) error {
		if c.Value(nfqws2ActiveExecutionKey{}) != f.e || !f.e.retired || !f.e.neverActivatedLAN() {
			return ErrNFQWSScopedOwner
		}
		return f.e.material.control.CurrentForCleanup(c)
	}
	f.e.preEffectLAN.observe = func(c context.Context) error {
		f.reads++
		if c.Value(nfqws2ActiveExecutionKey{}) != f.e || !f.e.retired || !f.e.neverActivatedLAN() || f.refuse == "read-open" || f.refuse == "read-close" {
			return ErrNFQWSScopedOwner
		}
		if f.afterRead != nil {
			f.afterRead()
		}
		return f.e.material.control.CurrentForCleanup(c)
	}
}

func (f *preEffectLANFixture) fenceBeforeStage(t *testing.T) {
	t.Helper()
	f.physical = errors.New("modeled original physical packet fence revoked")
	f.e.material.manager.FreshProfile = func(context.Context) (string, error) { return "", f.physical }
	// Same Manager read barrier used before entering Stage. No Stage, Activate,
	// candidate/preparation receipt or native invocation has run.
	if err := f.e.material.manager.checkPlanNetwork(f.ctx, f.e.plan); err == nil {
		t.Fatal("forward fence silently passed")
	}
	// Models preceding NFQ Rollback+VerifyRollback successful negative reads;
	// production still performs its full fresh e.verifyRollback in independent
	// LAN VerifyRollback; a no-op Rollback never supplies verification authority.
	f.e.retired = true
}

func TestNFQWSPreEffectLANRetiresAfterSnapshotBeforeStageAndRetries(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.snapshot(t, true)
	f.fenceBeforeStage(t)
	for i := 0; i < 2; i++ {
		p := f.e.plan
		if i > 0 {
			p = nfqwsRetryResult(p)
		} // Partial prior rollback already retired NFQ.
		if err := f.e.gate.Rollback(f.ctx, p, f.root); err != nil {
			t.Fatal("never-entered LAN borrowed revoked positive scope", err)
		}
		if ok, err := f.e.gate.VerifyRollback(f.ctx, p, f.root); err != nil || !ok {
			t.Fatal("fresh negative retirement", ok, err)
		}
	}
	if f.reads != 2 || f.retires != 2 || f.model.rpdbReads != 4 || f.model.cleanup != 0 || f.inventories < 4 {
		t.Fatal("missing independent negative read or borrowed cleanup", f.reads, f.retires, f.inventories, f.model)
	}
	if err := f.e.gate.Stage(f.ctx, f.e.plan, f.root); err == nil {
		t.Fatal("absence revived forward authority")
	}
	entries, err := os.ReadDir(f.root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "snapshot.json" {
		t.Fatal("retirement wrote metadata/effects", entries, err)
	}
}

func TestNFQWSPreEffectLANRequiresOriginalSourceBeyondSnapshot(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.snapshot(t, false)
	f.fenceBeforeStage(t)
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
		t.Fatal("authored snapshot manufactured source/kernel owners")
	}
}

func TestNFQWSPreEffectLANNoOpRollbackDoesNotVerifyAbsence(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.snapshot(t, true)
	f.fenceBeforeStage(t)
	f.refuse = "read-open"
	if err := f.e.gate.Rollback(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("identity-only no-op", err)
	}
	if f.reads != 0 || f.retires != 0 || f.model.rpdbReads != 0 {
		t.Fatal("no-op unexpectedly claimed full verification")
	}
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
		t.Fatal("successful no-op was reused as verification")
	}
}

func TestNFQWSPreEffectLANWitnessDoesNotReplaceStrictEffectsCleanup(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.snapshot(t, true)
	f.e.retired, f.e.activationAttempted = true, true
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); err != nil || !ok {
		t.Fatal("old snapshot blocked ordinary strict effects cleanup", err)
	}
	if f.reads != 0 || f.model.cleanup != 2 || f.retires != 1 || f.model.rpdbReads != 2 {
		t.Fatal("effects path borrowed no-effect verification", f.reads, f.model.cleanup, f.retires, f.model.rpdbReads)
	}
	f.physical = ErrReviewChanged
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
		t.Fatal("effects cleanup waived strict retained scope")
	}
}

func TestNFQWSPreEffectLANOtherOriginalModesKeepSnapshotPath(t *testing.T) {
	f := newPreEffectLANFixture(t)
	p := cloneExecutionResourcePlan(f.e.plan)
	var err error
	p.LAN, err = CompileLANPolicyRuntime(p.LAN.Generation, p.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	f.e.plan = p
	f.e.selection.plan = cloneExecutionResourcePlan(p)
	// Preserve existing shared-LAN behavior; this purpose cannot issue a
	// never-effect witness for any other mode, even with an original context.
	f.e.gate.identity.mode = ""
	if err := f.e.gate.Snapshot(f.ctx, p, f.root); err != nil {
		t.Fatal("unrelated original mode was intercepted", err)
	}
	if f.e.preEffectLAN != nil {
		t.Fatal("other mode acquired no-effect witness")
	}
}

func TestNFQWSPreEffectLANRefusesUnknownOrAttemptedEffects(t *testing.T) {
	for _, kind := range []string{"candidate", "preparation", "promoted", "owner", "snapshot-bytes", "snapshot-inode", "closed", "control", "selection", "material-binding", "review-copy", "not-retired", "resource", "prepared", "seal", "nfq-activate", "lan-activate", "journal-unknown", "read-open", "read-close", "retire", "inventory", "rpdb", "owner-after-read", "receipt-after-read", "cancel-after-read", "DTO", "copy", "digest"} {
		t.Run(kind, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			f.snapshot(t, true)
			f.fenceBeforeStage(t)
			write := func(path string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, p := f.ctx, cloneExecutionResourcePlan(f.e.plan)
			switch kind {
			case "candidate":
				write(filepath.Join(f.root, "candidate.json"))
			case "preparation":
				write(filepath.Join(f.root, policyAdditionFile))
			case "promoted":
				write(filepath.Join(f.e.gate.StateRoot, "receipts", p.PlanID, policyAdditionFile))
			case "owner":
				state, _ := f.e.gate.gateFor(p)
				if err := writeNetworkPolicyGate(f.e.gate.ownerPath(), state); err != nil {
					t.Fatal(err)
				}
			case "snapshot-bytes":
				write(filepath.Join(f.root, "snapshot.json"))
			case "snapshot-inode":
				if err := os.Rename(filepath.Join(f.root, "snapshot.json"), filepath.Join(f.root, "old.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.root, "snapshot.json"), f.e.preEffectLAN.image, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(f.root, "old.json")); err != nil {
					t.Fatal(err)
				}
			case "closed":
				_ = f.e.material.Close()
			case "control":
				_ = f.e.material.control.Close()
			case "material-binding":
				f.e.material.execution = nil
				t.Cleanup(func() { f.e.material.execution = f.e })
			case "review-copy":
				original := f.e.preEffectLAN
				f.e.preEffectLAN = &nfqwsPreEffectLANReview{self: original, execution: f.e}
				t.Cleanup(func() { _ = original.close() })
			case "selection":
				_ = f.e.selection.Close()
			case "not-retired":
				f.e.retired = false
			case "resource":
				f.e.resource = &NFQWSExecutionResource{}
			case "prepared":
				f.e.prepared = &NFQWSPreparedHandle{}
			case "seal":
				f.e.activationSeal = &nfqws2ActiveActivationSeal{}
			case "nfq-activate":
				f.e.activationAttempted = true
			case "lan-activate":
				if err := f.e.gate.Activate(ctx, p, f.root); err == nil {
					t.Fatal("revoked forward Activate passed")
				}
				if !f.e.lanActivationAttempted {
					t.Fatal("Activate attempt lost")
				}
			case "journal-unknown":
				f.e.preparationErr = ErrExecutionJournal
			case "rpdb":
				f.model.rpdb = "73: from all lookup 254\n"
			case "owner-after-read":
				f.afterRead = func() { write(f.e.gate.ownerPath()) }
			case "receipt-after-read":
				f.afterRead = func() { write(filepath.Join(f.root, policyAdditionFile)) }
			case "cancel-after-read":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				f.afterRead = cancel
			case "DTO":
				ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, p)
			case "copy":
				copy := &nfqws2ActiveExecution{self: f.e, material: f.e.material}
				ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, copy)
			case "digest":
				p.Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			default:
				f.refuse = kind
			}
			if ok, err := f.e.gate.VerifyRollback(ctx, p, f.root); ok || err == nil {
				t.Fatal("unknown/effect was certified absent", kind)
			}
		})
	}
}

func TestNFQWSPreEffectLANMissingSnapshotOrPriorNeverIssuesReview(t *testing.T) {
	for _, kind := range []string{"missing", "prior", "existing-empty-snapshot"} {
		t.Run(kind, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			switch kind {
			case "prior":
				state, _ := f.e.gate.gateFor(f.e.plan)
				if err := writeNetworkPolicyGate(f.e.gate.ownerPath(), state); err != nil {
					t.Fatal(err)
				}
			case "existing-empty-snapshot":
				if err := writeNetworkPolicyGate(filepath.Join(f.root, "snapshot.json"), networkPolicyGateSnapshot{}); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "missing" && f.e.gate.Snapshot(f.ctx, f.e.plan, f.root) == nil {
				t.Fatal("prior/decoded empty file became writer witness")
			}
			f.fenceBeforeStage(t)
			if f.e.preEffectLAN != nil {
				t.Fatal("missing original issuance")
			}
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
				t.Fatal("cold absence bypassed strict cleanup")
			}
		})
	}
}

func TestNFQWSPreEffectLANRetainedRootsRefuseReplacement(t *testing.T) {
	for _, kind := range []string{"manager", "transaction", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			f.snapshot(t, true)
			f.fenceBeforeStage(t)
			target := f.root
			if kind == "manager" {
				target = f.e.material.managerRoot
			}
			moved := target + "-original"
			if err := os.Rename(target, moved); err != nil {
				t.Skip("platform cannot rename held root", err)
			}
			if kind == "symlink" {
				if err := os.Symlink(moved, target); err != nil {
					if restoreErr := os.Rename(moved, target); restoreErr != nil {
						t.Fatal(restoreErr)
					}
					t.Skip("platform cannot create symlink", err)
				}
			} else {
				if err := os.MkdirAll(f.root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.root, "snapshot.json"), f.e.preEffectLAN.image, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
				t.Fatal("replacement inherited original retirement")
			}
			if f.reads != 0 {
				t.Fatal("replacement reached source observations")
			}
		})
	}
}

func TestNFQWSPreEffectLANCloseJoinsOriginalObservation(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.snapshot(t, true)
	f.fenceBeforeStage(t)
	entered, leave := make(chan struct{}), make(chan struct{})
	f.e.preEffectLAN.observe = func(context.Context) error { close(entered); <-leave; return ErrNFQWSScopedOwner }
	readDone := make(chan struct{})
	go func() { defer close(readDone); _, _ = f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root) }()
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal("original observation did not enter")
	}
	closeStarted, closeDone := make(chan struct{}), make(chan struct{})
	go func() { close(closeStarted); _ = f.e.material.Close(); close(closeDone) }()
	<-closeStarted
	select {
	case <-closeDone:
		t.Fatal("Close released retained files during observation")
	case <-time.After(30 * time.Millisecond):
	}
	close(leave)
	select {
	case <-closeDone:
	case <-f.ctx.Done():
		t.Fatal("Close did not join observation")
	}
	<-readDone
	if ok, err := f.e.gate.VerifyRollback(f.ctx, f.e.plan, f.root); ok || err == nil {
		t.Fatal("closed material revived retirement")
	}
}

func TestNFQWSPreEffectLANClosePreventsLateCapturePublication(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.snapshot(t, true)
	r := f.e.preEffectLAN
	// Exact intermediate disk/descriptor image after successful r.current,
	// before capture's final publication. Close must prevent a late install.
	if err := r.current(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.e.preEffectLAN = nil
	defer r.close()
	if err := f.e.material.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.e.retainPreEffectLAN(r); err == nil || f.e.preEffectLAN != nil {
		t.Fatal("completed Close lost late private descriptors", err)
	}
}
