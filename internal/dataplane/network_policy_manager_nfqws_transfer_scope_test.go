package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Explicit process/queue/common-receipt model for the original registrar's
// one-use transitions. No real child, provider or active-owner factory exists
// in this fixture; actual lease3 observation remains the NFQ owner's work.
type networkPolicyActiveScopeModel struct {
	f                       *executionNFQWSFixture
	r                       *NFQWSExecutionResource
	ctx                     context.Context
	command                 nfqws2ActiveProcessCommand
	observation             NFQWSActiveObservation
	running, captureReceipt bool
	reads                   []nfqwsExecutionActiveReadbackMode
	onRead                  func(nfqwsExecutionActiveReadbackMode)
}

func networkPolicyActiveScopeFixture(t *testing.T) *networkPolicyActiveScopeModel {
	t.Helper()
	f := executionNFQWSManagerFixture(t)
	// Active commands use the actual runtime/nfqws2 owner layout. The older
	// timed registrar fixture deliberately uses an arbitrary private root.
	f.m.StateRoot = filepath.Join(t.TempDir(), "runtime")
	if err := f.m.recordLocked(f.p); err != nil {
		t.Fatal(err)
	}
	command, spec, _ := nfqws2ActiveCommandFixture(t)
	command.StateRoot = filepath.Join(f.m.StateRoot, "nfqws2")
	spec.CommandSHA256 = nfqws2ActiveCommandDigest(command)
	f.spec = spec
	identity, current := networkPolicyIdentityFixture()
	*current, identity.value = *spec.NetworkIdentity, *spec.NetworkIdentity
	binding, _, _ := lanReceiptBindingFixture(t)
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Binding: binding, InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error { return nil }}, identity)
	if err != nil || f.m.Register(gate) != nil {
		t.Fatal(err)
	}
	if err := f.m.beginOperation(f.ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.m.endOperation)
	e := Execution{PlanID: f.p.PlanID, Digest: f.p.Digest, State: "applying", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	root := filepath.Join(f.m.StateRoot, "transactions", f.p.PlanID)
	if err := f.m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	scope, err := f.m.newExecutionResourceScope(f.ctx, f.p, "nfqws2", &e, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { scope.close() })
	x := &networkPolicyActiveScopeModel{f: f, command: command}
	ctx := context.WithValue(scope.context(), nfqwsExecutionReadbackKey{}, nfqwsExecutionReadback(func(ctx context.Context, p *NFQWSScopedPlan, root string, mode nfqwsExecutionReadbackMode) error {
		if mode != nfqwsExecutionBeforeStart || x.running || x.r == nil || p != x.r.Plan() || root != x.r.Root() {
			return ErrNFQWSScopedOwner
		}
		return ctx.Err()
	}))
	ctx = context.WithValue(ctx, nfqwsExecutionActiveReadbackKey{}, nfqwsExecutionActiveReadback(func(ctx context.Context, p *NFQWSScopedPlan, root string, mode nfqwsExecutionActiveReadbackMode, obs NFQWSActiveObservation) error {
		x.reads = append(x.reads, mode)
		if !x.running || x.r == nil || p != x.r.Plan() || root != x.r.Root() || obs != x.observation || mode == nfqwsExecutionActiveBeforeTransfer && !x.captureReceipt {
			return ErrNFQWSScopedOwner
		}
		if x.onRead != nil {
			x.onRead(mode)
		}
		return ctx.Err()
	}))
	x.r, err = AcquireNFQWSExecutionResource(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	x.ctx = ctx
	return x
}

func (x *networkPolicyActiveScopeModel) prepare(t *testing.T) {
	t.Helper()
	if err := x.r.configureActive(x.ctx, x.command); err != nil {
		t.Fatal(err)
	}
	if err := x.r.BeforeStart(x.ctx, x.r.Binding()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(x.ctx, 10*time.Second)
	defer cancel()
	if err := x.r.WithStart(ctx, x.r.Binding(), func() error { x.running = true; return nil }); err != nil {
		t.Fatal(err)
	}
	model := nfqwsScopedModel{p: x.r.Plan(), running: true}
	proof := model.proof(false)
	x.observation = NFQWSActiveObservation{Binding: x.r.Binding(), NetworkIdentity: x.command.NetworkIdentity, Receipt: proof.Receipt, Child: proof.Child}
	if err := x.r.PreparedActive(x.ctx, x.r.Binding(), x.observation); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkPolicyManagerTransferRequiresIndependentActiveProofAndBothIntentRecords(t *testing.T) {
	x := networkPolicyActiveScopeFixture(t)
	x.prepare(t)
	if err := x.r.Prepared(x.ctx, x.r.Binding()); err == nil {
		t.Fatal("active owner borrowed legacy lease2 Prepared")
	}
	x.captureReceipt = true
	if err := x.r.BeginTransfer(x.ctx); err != nil {
		t.Fatal(err)
	}
	if got := x.f.latest(t).Resources[0]; got.Phase != "transfer-intent" || got.State != "prepared" || got.NFQWS.Mode != nfqws2ActiveProcessMode || got.NFQWS.Observation != nil {
		t.Fatal("intent confused with ACK/ACTIVE", got)
	}
	var transaction *Execution
	if found, err := readOptionalJournal(filepath.Join(x.r.scope.root, "execution.json"), &transaction); err != nil || !found || transaction == nil || transaction.Resources[0].Phase != "transfer-intent" {
		t.Fatal("intent missing transaction record", err)
	}
	if err := x.r.BeginTransfer(x.ctx); err == nil {
		t.Fatal("transfer intent replayed")
	}
	if len(x.reads) != 2 || x.reads[0] != nfqwsExecutionActiveBeforeCapture || x.reads[1] != nfqwsExecutionActiveBeforeTransfer {
		t.Fatal("independent proof order", x.reads)
	}
	if err := x.f.m.CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("intent lost recovery fence", err)
	}
}

func TestNetworkPolicyManagerTransferProofFailureIsConsumedWithoutMetadataACK(t *testing.T) {
	x := networkPolicyActiveScopeFixture(t)
	x.prepare(t)
	if err := x.r.BeginTransfer(x.ctx); err == nil {
		t.Fatal("unproved capture/common receipt became transfer intent")
	}
	x.captureReceipt = true
	if err := x.r.BeginTransfer(x.ctx); err == nil || len(x.reads) != 2 {
		t.Fatal("failed transfer proof was replayed", err, x.reads)
	}
	if x.f.latest(t).Resources[0].Phase != "capture-ready" {
		t.Fatal("failure fabricated provisionalACK")
	}
}

func TestNetworkPolicyManagerActiveScopeRefusesRootAndInstanceSubstitution(t *testing.T) {
	for _, fault := range []string{"manager-root", "registered-instance", "missing-reader", "temporary-attempt"} {
		t.Run(fault, func(t *testing.T) {
			x := networkPolicyActiveScopeFixture(t)
			switch fault {
			case "manager-root":
				x.f.m.StateRoot = t.TempDir()
			case "registered-instance":
				x.f.m.registryMu.Lock()
				x.f.m.Adapters["nfqws2"] = &fakeAdapter{id: "nfqws2"}
				x.f.m.registryMu.Unlock()
			case "missing-reader":
				x.ctx = context.WithValue(x.ctx, nfqwsExecutionActiveReadbackKey{}, nfqwsExecutionActiveReadback(nil))
			case "temporary-attempt":
				x.r.scope.execution.ResourcePlanID = x.r.scope.plan.PlanID
			}
			if err := x.r.configureActive(x.ctx, x.command); err == nil {
				t.Fatal("invalid original scope acquired active mode", fault)
			}
			if len(x.f.model.calls) != 0 {
				t.Fatal("binding refusal performed effects")
			}
		})
	}
}

func TestNetworkPolicyManagerTransferClosingProofCannotDetachOriginalScope(t *testing.T) {
	for _, fault := range []string{"cancel", "manager-root", "registered-instance"} {
		t.Run(fault, func(t *testing.T) {
			x := networkPolicyActiveScopeFixture(t)
			x.prepare(t)
			x.captureReceipt = true
			x.onRead = func(mode nfqwsExecutionActiveReadbackMode) {
				if mode != nfqwsExecutionActiveBeforeTransfer {
					t.Fatal("unexpected proof phase")
				}
				switch fault {
				case "cancel":
					x.r.scope.cancel()
				case "manager-root":
					x.f.m.StateRoot = t.TempDir()
				case "registered-instance":
					x.f.m.registryMu.Lock()
					x.f.m.Adapters["nfqws2"] = &fakeAdapter{id: "nfqws2"}
					x.f.m.registryMu.Unlock()
				}
			}
			if err := x.r.BeginTransfer(context.WithoutCancel(x.ctx)); err == nil {
				t.Fatal("closing proof changed original scope but published intent", fault)
			}
			if x.r.scope.execution.Resources[0].Phase != "capture-ready" || !x.r.transferUsed {
				t.Fatal("closing refusal lost one-use recovery fence")
			}
			x.onRead = nil
			if err := x.r.BeginTransfer(context.WithoutCancel(x.ctx)); err == nil || len(x.reads) != 2 {
				t.Fatal("closing refusal replayed owner observation", err, x.reads)
			}
		})
	}
}

func TestNetworkPolicyManagerTransferPartialIntentWriteRemainsFenced(t *testing.T) {
	for _, failed := range []string{"transaction", "latest"} {
		t.Run(failed, func(t *testing.T) {
			x := networkPolicyActiveScopeFixture(t)
			x.prepare(t)
			x.captureReceipt = true
			transaction := filepath.Join(x.r.scope.root, "execution.json")
			latest := filepath.Join(x.f.m.StateRoot, "latest-execution.json")
			blocked, retained := transaction, latest
			if failed == "latest" {
				blocked, retained = latest, transaction
			}
			// A directory at exactly one private model journal path models an
			// atomic replacement failure; the other actual record still writes.
			if err := os.Rename(blocked, blocked+".before-intent"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			if err := x.r.BeginTransfer(x.ctx); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("one missing durable record reported intent success", err)
			}
			var record *Execution
			if found, err := readOptionalJournal(retained, &record); err != nil || !found || record == nil || record.Resources[0].Phase != "transfer-intent" || record.Resources[0].State != "prepared" {
				t.Fatal("partial intent lost original reference", err)
			}
			if x.r.scope.failure == nil || x.r.BeginTransfer(x.ctx) == nil || len(x.reads) != 2 {
				t.Fatal("partial write replayed consumed transfer")
			}
			if err := New(x.f.m.StateRoot).CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("partial intent admitted cold recovery", err)
			}
		})
	}
}
