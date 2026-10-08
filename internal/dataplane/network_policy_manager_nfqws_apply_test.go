package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// The Manager writer, original Gate/control files and sealed producer protocol
// run here. Process/queue/COMMON/physical observations are explicit models;
// these fixtures do not launch a child or grant a production App route.
type nfqwsApplyTransferFixture struct {
	r       *NFQWSExecutionResource
	ctx     context.Context
	control *operationgate.ControlEpochReview
	model   *nfqws2ActiveModel
}

func nfqwsApplyTransferBoundFixture(t *testing.T) *nfqwsApplyTransferFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
	ctx = WithReviewGuard(ctx, control.Current)
	manager := New(t.TempDir())
	adapter := NewNFQWS2Adapter()
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	command, spec, _ := nfqws2ActiveCommandFixture(t)
	command.StateRoot, command.ControlRoot = adapter.StateRoot, controlRoot
	command.Owner, err = adapter.owner()
	if err != nil {
		t.Fatal(err)
	}
	epoch := control.Reference()
	command.InstallationID, command.Sequence = epoch.InstallationID, epoch.Sequence
	spec.CommandSHA256 = nfqws2ActiveCommandDigest(command)
	plan, _, _ := nfqwsScopedFixture(t)
	plan.PlanID, plan.NetworkProfileID, plan.Adapters = "dp-0123456789abcdef", "wan-0123456789ab", []string{"nfqws2"}
	plan.Routes[0].NetworkPolicyRole = "override"
	manager.FreshProfile = func(context.Context) (string, error) { return plan.NetworkProfileID, nil }
	identity, current := networkPolicyIdentityFixture()
	*current, identity.value = *spec.NetworkIdentity, *spec.NetworkIdentity
	lan, _, _ := lanReceiptBindingFixture(t)
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Binding: lan, InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error { return nil }}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(gate); err != nil {
		t.Fatal(err)
	}
	if err := manager.beginOperation(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.endOperation)
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	root := filepath.Join(manager.StateRoot, "transactions", plan.PlanID)
	if err := manager.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	scope, err := manager.newExecutionResourceScope(ctx, plan, adapter.ID(), &execution, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scope.close() })
	ctx = scope.contextWith(ctx)
	ctx = context.WithValue(ctx, nfqwsExecutionReadbackKey{}, nfqwsExecutionReadback(func(c context.Context, _ *NFQWSScopedPlan, _ string, _ nfqwsExecutionReadbackMode) error {
		return c.Err()
	}))
	ctx = context.WithValue(ctx, nfqwsExecutionActiveReadbackKey{}, nfqwsExecutionActiveReadback(func(c context.Context, _ *NFQWSScopedPlan, _ string, _ nfqwsExecutionActiveReadbackMode, _ NFQWSActiveObservation) error {
		return c.Err()
	}))
	r, err := AcquireNFQWSExecutionResource(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.configureActive(ctx, command); err != nil {
		t.Fatal(err)
	}
	if err := r.BeforeStart(ctx, r.Binding()); err != nil {
		t.Fatal(err)
	}
	start, finish := context.WithTimeout(ctx, 5*time.Second)
	if err := r.WithStart(start, r.Binding(), func() error { return nil }); err != nil {
		finish()
		t.Fatal(err)
	}
	finish()
	proof := (&nfqwsScopedModel{p: r.Plan(), running: true}).proof(false)
	proof.Child.Executable = command.Program.Path
	helper := components.NFQWSSupervisionIdentity{BootID: proof.Receipt.BootID, Start: proof.Receipt.Start, PID: proof.Receipt.PID, Group: proof.Receipt.Group}
	base, err := nfqws2ActiveFrameBase(command, r.Binding(), helper)
	if err != nil {
		t.Fatal(err)
	}
	model := &nfqws2ActiveModel{done: make(chan struct{}), lease: nfqws2ActiveProcessLease{Version: 3, StateRoot: command.StateRoot, Owner: command.Owner, Command: command, CommandSHA256: spec.CommandSHA256,
		Binding: r.Binding(), Transfer: "none", Receipt: proof.Receipt, Child: proof.Child}}
	if err := nfqws2ValidateActiveLease(model.lease); err != nil {
		t.Fatal("modeled running lease", err)
	}
	transport := &nfqws2ActiveModelTransport{}
	for _, kind := range []string{"transfer-ack", "active"} {
		frame := base
		frame.Kind, frame.Child = kind, proof.Child
		transport.frames = append(transport.frames, frame)
	}
	transport.onReceive = func(index int) {
		model.mu.Lock()
		defer model.mu.Unlock()
		model.lease.Transfer = "provisional"
		if index == 1 {
			model.lease.Transfer = "final"
		}
	}
	activation, activationCancel := context.WithDeadline(ctx, command.ActivationDeadline)
	t.Cleanup(activationCancel)
	owner := &nfqws2ActiveOwner{adapter: adapter, command: command, activation: activation, activationCancel: activationCancel,
		panel: context.Background(), base: base, child: proof.Child, transport: transport, done: model.done, state: "prepared"}
	prepared := &NFQWSPreparedHandle{owner: owner}
	owner.prepared = prepared
	owner.admission = nfqws2ActiveProcessAdmission{Binding: r.Binding(), Spec: spec, Current: r.Current, WithTransfer: r.WithTransfer, PublishTransferACK: r.PublishTransferACK}
	owner.read = func(c context.Context, live bool) (nfqws2ActiveProcessLease, error) {
		model.mu.Lock()
		defer model.mu.Unlock()
		if live && model.lease.Receipt.State != "running" {
			return nfqws2ActiveProcessLease{}, ErrNFQWSManagedProcessUnknown
		}
		return model.lease, c.Err()
	}
	owner.result = func() (nfqws2ActiveProcessLease, error) {
		model.mu.Lock()
		defer model.mu.Unlock()
		return model.lease, nil
	}
	var stop sync.Once
	owner.signal = func() {
		stop.Do(func() {
			model.mu.Lock()
			model.signals++
			model.lease.Receipt.State, model.lease.Receipt.Reaped, model.lease.Receipt.ExitCode = "reaped", 1, 125
			model.lease.Receipt.DirectReaped, model.lease.Receipt.WaitECHILD, model.lease.Receipt.Cancelled, model.lease.Acknowledged = true, true, true, true
			model.mu.Unlock()
			close(model.done)
		})
	}
	model.owner, model.prepared, model.transport = owner, prepared, transport
	if err := adapter.retainNFQWSActiveProcess(owner); err != nil {
		t.Fatal(err)
	}
	owner.watches()
	t.Cleanup(func() { owner.abort(); owner.endRequestWatch() })
	guards := nfqwsExecutionTransferGuards{control: control, originalCleanup: cleanup,
		committed: func(c context.Context, h *NFQWSActiveHandle, obs NFQWSActiveObservation) error {
			return h.VerifyOwnerObservation(c, obs)
		},
		cleanup: func(c context.Context, h *NFQWSActiveHandle, obs NFQWSActiveObservation) error {
			return h.VerifyCleanupObservation(c, obs)
		}}
	ctx = context.WithValue(ctx, nfqwsExecutionTransferGuardsKey{}, guards)
	if err := r.bindPrepared(ctx, prepared, model.lease.observation()); err != nil {
		t.Fatal("original prepared association", err)
	}
	if err := r.PreparedActive(ctx, r.Binding(), model.lease.observation()); err != nil {
		t.Fatal(err)
	}
	return &nfqwsApplyTransferFixture{r: r, ctx: ctx, control: control, model: model}
}

func TestNFQWSApplyOriginalHandleCannotTransferBeforeManagerPostCASBarrier(t *testing.T) {
	f := nfqwsApplyTransferBoundFixture(t)
	if err := f.r.BeginTransfer(f.ctx); err != nil {
		t.Fatal(err)
	}
	guards := f.r.transferGuards
	if h, err := f.model.prepared.CommitPrepared(f.ctx, guards.committed, guards.cleanup); err == nil || h != nil {
		t.Fatal("pre-CAS caller obtained a final owner", err)
	}
	if len(f.model.transport.sent) != 0 || f.r.transferACK || f.r.finalOwner != nil {
		t.Fatal("closed Manager barrier sent a transfer or fabricated ACK")
	}
}

func TestNFQWSApplyPostCASAuthenticatesBothACKRecordsAndFinalHandleButKeepsTerminalClosed(t *testing.T) {
	f := nfqwsApplyTransferBoundFixture(t)
	if err := f.r.scope.beginNFQWSTransfer(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.r.scope.commitNFQWSTransfer(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(f.r.scope.root, "execution.json"), filepath.Join(f.r.scope.managerRoot, "latest-execution.json")} {
		var record *Execution
		if exists, err := readOptionalJournal(path, &record); err != nil || !exists || record.Resources[0].Phase != "transfer-ack" || record.Resources[0].NFQWS.Observation == nil {
			t.Fatal("provisional ACK lost a durable record", err)
		}
	}
	if f.r.finalOwner == nil || !f.model.owner.finalACK || !f.model.owner.detached {
		t.Fatal("real sealed protocol did not return its original final handle")
	}
	if err := validateExecutionResources(*f.r.scope.execution, true); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("provisional metadata became terminal ACTIVE", err)
	}
	if err := f.r.scope.commitNFQWSTransfer(f.ctx); err == nil {
		t.Fatal("Manager post-CAS barrier replayed")
	}
}

func TestNFQWSApplyLostFinalACKRetainsOriginalProvisionalOwnerAndBothRecords(t *testing.T) {
	f := nfqwsApplyTransferBoundFixture(t)
	f.model.transport.frames = f.model.transport.frames[:1]
	if err := f.r.scope.beginNFQWSTransfer(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.r.scope.commitNFQWSTransfer(f.ctx); err == nil || f.r.finalOwner != nil {
		t.Fatal("lost final ACK produced a live grant", err)
	}
	if !f.r.transferACK || f.r.scope.execution.Resources[0].Phase != "transfer-ack" || f.model.owner.adapter.activeProcess != f.model.owner || f.model.signals != 1 {
		t.Fatal("lost final ACK dropped the original holder or skipped its sole stop")
	}
}

func TestNFQWSApplyStopRevokesForwardButOriginalFiniteCleanupSurvives(t *testing.T) {
	f := nfqwsApplyTransferBoundFixture(t)
	if _, err := operationgate.RequestSelfUpdateStop(f.ctx, f.r.activeCommand.ControlRoot, strings.Repeat("c", 32), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.r.Current(f.ctx, f.r.Binding()); err == nil {
		t.Fatal("durable Stop permitted forward use")
	}
	cleanup, finish := context.WithTimeout(context.Background(), 3*time.Second)
	defer finish()
	f.r.scope.mu.Lock()
	err := f.r.check(cleanup, false)
	f.r.scope.mu.Unlock()
	if err != nil {
		t.Fatal("original retained cleanup inherited revoked forward authority", err)
	}
	copy := *f.r.transferGuards.originalCleanup
	f.r.transferGuards.originalCleanup = &copy
	f.r.scope.mu.Lock()
	err = f.r.check(cleanup, false)
	f.r.scope.mu.Unlock()
	if err == nil {
		t.Fatal("copied cleanup review recreated the original capability")
	}
}

func TestNFQWSApplyKeepsSameIssuerAcrossPhasesAndFencesUnknownPriorOnRollback(t *testing.T) {
	// Actual registered NFQ adapter, Manager phases, file snapshots and both
	// journals; package runner/kernel/resource inactivity are explicit models.
	// This proves issuer/rollback ordering, not managed Native activation.
	plan, spec, _ := nfqwsScopedFixture(t)
	plan.PlanID, plan.NetworkProfileID, plan.Ready = "dp-0123456789abcdef", "wan-0123456789ab", true
	plan.SchemaVersion, plan.Adapters = SchemaVersion, []string{NetworkPolicyAdapterID, "nfqws2"}
	plan.Routes[0].NetworkPolicyRole = "override"
	root := t.TempDir()
	manager := New(filepath.Join(root, "state"))
	manager.FreshProfile = func(context.Context) (string, error) { return plan.NetworkProfileID, nil }
	adapter := NewNFQWS2Adapter()
	adapter.ConfigPath, adapter.InitPath = filepath.Join(root, "nfqws2.conf"), filepath.Join(root, "init")
	adapter.UserListPath, adapter.IPSetListPath, adapter.IPTablesSave = filepath.Join(root, "user.list"), filepath.Join(root, "ipset.list"), "iptables-save-model"
	for path, content := range map[string]string{adapter.ConfigPath: "ISP_INTERFACE=eth3\n", adapter.InitPath: "#!/bin/sh\n", adapter.UserListPath: "manual.example\n", adapter.IPSetListPath: ""} {
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
	}
	lan, _, _ := lanReceiptBindingFixture(t)
	gate := &NetworkPolicyAdapter{Binding: lan, InventoryCheck: func(context.Context) error { return nil }}
	for _, participant := range []Adapter{adapter, gate} {
		if err := manager.Register(participant); err != nil {
			t.Fatal(err)
		}
	}
	var resource *NFQWSExecutionResource
	restarts, stops, health, commits := 0, 0, 0, 0
	live := false
	base := &nfqwsFakeRunner{}
	adapter.Runner = networkCleanupRunner(func(c context.Context, command string, args ...string) ([]byte, error) {
		if command == adapter.InitPath && len(args) == 1 && args[0] == "status" && !live {
			return []byte("model service stopped"), errors.New("model service stopped")
		}
		if command == adapter.IPTablesSave && !live {
			return []byte(""), nil
		}
		if command == adapter.InitPath && len(args) == 1 && args[0] == "restart" {
			restarts++
			live = true
			if restarts == 1 {
				c = context.WithValue(c, nfqwsExecutionReadbackKey{}, nfqwsExecutionReadback(func(check context.Context, _ *NFQWSScopedPlan, _ string, _ nfqwsExecutionReadbackMode) error {
					return check.Err()
				}))
				var err error
				resource, err = AcquireNFQWSExecutionResource(c, spec)
				if err != nil {
					return nil, err
				}
			}
		}
		if command == adapter.InitPath && len(args) == 1 && args[0] == "stop" {
			stops++
			live = false
			if err := resource.SettleRemoved(c); err != nil {
				return nil, err
			}
		}
		return base.Run(c, command, args...)
	})
	adapter.HealthProbe = func(c context.Context, _ string) error {
		health++
		return resource.Current(c, resource.Binding())
	}
	plan.Routes[0].ProbeURL = "https://model.invalid/probe"
	lan.RetireCheck = func(context.Context, *LANPolicyRuntimePlan) error {
		if resource == nil || resource.scope.execution.Resources[0].State != "removed" {
			return ErrNetworkPolicyConsumers
		}
		return nil
	}
	ctx, finish := context.WithTimeout(context.Background(), 10*time.Second)
	defer finish()
	ctx = WithReviewGuard(ctx, func(c context.Context) error { return c.Err() })
	cause := errors.New("actual desired-state callback refused CAS")
	execution, err := manager.Apply(ctx, plan, func() (func() error, error) {
		commits++
		if err := resource.Current(ctx, resource.Binding()); err != nil {
			t.Fatal("health closed the original activation issuer before CAS", err)
		}
		return nil, cause
	})
	// The prior package has no instance lease. Existing independent rollback
	// correctly refuses to declare that external runtime restored, even after
	// the original modeled resource is removed. Keep the actual LAN owner.
	if !errors.Is(err, cause) || !errors.Is(err, ErrNetworkPolicyConsumers) || resource == nil || health == 0 || commits != 1 || restarts != 1 || stops != 1 || execution.RollbackVerified || execution.State != "rollback-failed" {
		t.Fatal("actual phase/cleanup order", err, health, commits, restarts, stops, execution.State, execution.RollbackVerified, execution.Steps)
	}
	if resource.Current(ctx, resource.Binding()) == nil || resource.scope.execution.Resources[0].State != "removed" {
		t.Fatal("issuer survived Apply or original rollback was not settled")
	}
	if owner, err := gate.readOwner(); err != nil || owner == nil {
		t.Fatal("unknown prior consumer lost the physical LAN boundary", err)
	}
}
