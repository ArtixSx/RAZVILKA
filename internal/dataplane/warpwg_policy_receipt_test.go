package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
)

func testWGPolicyReceiptOptions() policyAdditionOptions {
	return policyAdditionOptions{boot: func() (string, error) { return "test-WG-boot", nil }}
}

// Keep all committed-profile writes inside the fixture's temporary root while
// exercising the actual adapter methods through Manager.Apply.
type wgReceiptManagerAdapter struct{ *WARPWireGuardAdapter }

type wgReceiptAdmissionAdapter struct {
	*wgReceiptManagerAdapter
	afterCanary func()
}

// The fixture supplies Canary acceptance so it can change the independent
// module inventory between Validate and the real fresh Activate admission.
func (a *wgReceiptAdmissionAdapter) Canary(context.Context, RoutePlan, string) error {
	a.afterCanary()
	return nil
}

func (a *wgReceiptManagerAdapter) Snapshot(ctx context.Context, plan Plan, root string) error {
	if err := a.WARPWireGuardAdapter.Snapshot(ctx, plan, root); err != nil {
		return err
	}
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	snapshot.ProfilePath = filepath.Join(a.StateRoot, "fixture-profile.conf")
	snapshot.Profile, snapshot.ProfileExisted, err = optionalFile(snapshot.ProfilePath)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(snapshot)
	return os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0600)
}

type wgReceiptCollisionRunner struct {
	*warpFakeRunner
	family, table int
	inserted      bool
}

func (r *wgReceiptCollisionRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	family, plain := 4, args
	if len(plain) > 0 && plain[0] == "-6" {
		family, plain = 6, plain[1:]
	}
	if !r.inserted && family == r.family && strings.HasPrefix(strings.Join(plain, " "), "route add default ") && strings.Contains(strings.Join(plain, " "), fmt.Sprintf("table %d ", r.table)) {
		r.inserted = true
		metric := "0"
		if family == 6 {
			metric = "1024"
		}
		if r.policy.defaults == nil {
			r.policy.defaults = map[string]string{}
		}
		r.policy.defaults[fmt.Sprintf("%d/%d", family, r.table)] = "default dev rz-wg proto boot metric " + metric + "\n"
	}
	return r.warpFakeRunner.Run(ctx, name, args...)
}

func wgReceiptFixture(t *testing.T) (*WARPWireGuardAdapter, *warpFakeRunner, Plan, string) {
	t.Helper()
	a, runner, plan, transaction := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	a.CanaryProbe = func(context.Context, string, string) error { return nil }
	a.HealthProbe = func(context.Context, string) error { return nil }
	runner.routeDevice = a.interfaceName()
	plan.Routes[0].Domains = nil
	plan.Routes[0].CIDRs = []string{"1.1.1.1/32", "2606:4700:4700::1111/128"}
	plan.SchemaVersion, plan.PlanID, plan.Digest, plan.Ready, plan.Adapters = SchemaVersion, "wg-receipt-fixture", strings.Repeat("a", 64), true, []string{a.ID()}
	return a, runner, plan, transaction
}

func commitWGReceiptFixture(t *testing.T, a *WARPWireGuardAdapter, plan Plan, transaction string) (PolicyState, warpWGPolicyReference) {
	t.Helper()
	wrapper := &wgReceiptManagerAdapter{a}
	ctx := context.Background()
	for _, step := range []func(context.Context, Plan, string) error{wrapper.Snapshot, a.Stage, a.Activate, a.Commit} {
		if err := step(ctx, plan, transaction); err != nil {
			t.Fatal(err)
		}
	}
	state, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		t.Fatal(err)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil {
		t.Fatal(err)
	}
	return state, ref
}

func TestWGPolicyReceiptManagerLateEEXISTPreservesForeignDefaults(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			a, runner, plan, _ := wgReceiptFixture(t)
			collision := &wgReceiptCollisionRunner{warpFakeRunner: runner, family: family, table: a.table()}
			a.Runner = collision
			manager := New(t.TempDir())
			if err := manager.Register(&wgReceiptManagerAdapter{a}); err != nil {
				t.Fatal(err)
			}
			execution, err := manager.Apply(context.Background(), plan, nil)
			if err == nil || !errors.Is(err, ErrPolicyAdditionUnknown) || execution.State != "rollback-failed" || execution.RollbackVerified || !collision.inserted {
				t.Fatal("late collision was accepted or guessed away", execution, err)
			}
			key := fmt.Sprintf("%d/%d", family, a.table())
			if runner.policy.defaults[key] == "" {
				t.Fatal("concurrent identical foreign default deleted")
			}
			transaction := filepath.Join(manager.StateRoot, "transactions", plan.PlanID, a.ID())
			state, err := a.readStagedPolicy(transaction)
			if err != nil {
				t.Fatal(err)
			}
			ref, exists, err := a.readWGPolicyReference(transaction, state, false)
			if err != nil || !exists {
				t.Fatal(err)
			}
			status, err := a.inspectWGPolicyReference(context.Background(), ref, transaction)
			if err != nil || !status.Unknown {
				t.Fatal("unknown result lost", status, err)
			}
			fresh := *a
			fresh.policyReceiptOptions.fault = nil
			runner.calls = nil
			if err := fresh.Rollback(context.Background(), plan, transaction); !errors.Is(err, ErrPolicyAdditionUnknown) {
				t.Fatal(err)
			}
			if runner.policy.defaults[key] == "" || len(receiptMutationCalls(runner.calls)) != 0 {
				t.Fatal("restart cleanup adopted unknown tuple", runner.calls)
			}
		})
	}
}

func TestWGPolicyReceiptUnknownSelectorFencesDefaultsAndInterface(t *testing.T) {
	a, runner, plan, _ := wgReceiptFixture(t)
	crash := errors.New("simulated loss before added acknowledgement")
	a.policyReceiptOptions.fault = func(point string, index int) error {
		if point == "add" && index == 3 {
			return crash
		}
		return nil
	}
	manager := New(t.TempDir())
	manager.Register(&wgReceiptManagerAdapter{a})
	execution, err := manager.Apply(context.Background(), plan, nil)
	if err == nil || execution.State != "rollback-failed" || execution.RollbackVerified {
		t.Fatal(execution, err)
	}
	for _, family := range []int{4, 6} {
		if runner.policy.defaults[fmt.Sprintf("%d/%d", family, a.table())] == "" {
			t.Fatal("unknown selector lost its default fence", family)
		}
	}
	if !runner.active {
		t.Fatal("unknown selector lost its interface and opened fallback")
	}
}

func TestWGPolicyReceiptManagerAWGFreshAdmissionFailureHasNoCleanupAuthority(t *testing.T) {
	wg, runner, _, _ := wgReceiptFixture(t)
	a := NewAmneziaWGAdapter(wg.Configs, t.TempDir())
	a.Runner, a.IP, a.policyReceiptOptions = runner, "ip", testWGPolicyReceiptOptions()
	if _, err := a.Configs.Stage(a.ID(), "main", awgNativeFixture()); err != nil {
		t.Fatal(err)
	}
	caps := compatibleAWGTestCapabilities(t, a)
	a.AWGCapabilities = func(context.Context) awgprofile.Capabilities { return caps }
	plan := Plan{SchemaVersion: SchemaVersion, PlanID: "awg-receipt-admission", Digest: strings.Repeat("b", 64), Ready: true, Adapters: []string{a.ID()}, EngineDrafts: []string{a.ID() + "/main"}, Routes: []Route{{Resolved: a.ID(), ServiceName: "fixture", CIDRs: []string{"1.1.1.1/32"}, ProbeURL: "https://fixture.invalid/"}}}
	wrapper := &wgReceiptAdmissionAdapter{wgReceiptManagerAdapter: &wgReceiptManagerAdapter{a}, afterCanary: func() {
		caps.ModuleInitState = "going"
		runner.policy.defaults = map[string]string{fmt.Sprintf("4/%d", a.table()): "default dev rz-awg proto boot metric 0\n", fmt.Sprintf("6/%d", a.table()): "default dev rz-awg proto boot metric 1024\n"}
		runner.calls = nil
	}}
	manager := New(t.TempDir())
	if err := manager.Register(wrapper); err != nil {
		t.Fatal(err)
	}
	execution, err := manager.Apply(context.Background(), plan, nil)
	if err == nil || execution.State != "rolled-back" || execution.RollbackVerified {
		t.Fatal("fresh AWG admission failure accepted", execution, err)
	}
	transaction := filepath.Join(manager.StateRoot, "transactions", plan.PlanID, a.ID())
	if regularFile(filepath.Join(transaction, "wg-activation-started")) || len(receiptMutationCalls(runner.calls)) != 0 || runner.active || len(runner.policy.defaults) != 2 {
		t.Fatal("pre-admission staged policy became cleanup authority", runner.calls)
	}
}

func TestWGPolicyReceiptCommitRetainsAuthorityAfterTransactionRemoval(t *testing.T) {
	a, runner, plan, transaction := wgReceiptFixture(t)
	state, ref := commitWGReceiptFixture(t, a, plan, transaction)
	source, exists, err := a.readWGPolicyReference(transaction, state, false)
	if err != nil || !exists || source.ID != ref.ID {
		t.Fatal(source, err)
	}
	if err := os.RemoveAll(transaction); err != nil {
		t.Fatal(err)
	} // fixture-owned directory
	fresh := *a
	if err := fresh.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.active || len(runner.policy.entries) != 0 || len(runner.policy.defaults) != 0 {
		t.Fatal("retained generation failed cleanup")
	}
	status, err := a.inspectWGPolicyReference(context.Background(), ref, "")
	if err != nil || !status.Removed || status.Unknown {
		t.Fatal(status, err)
	}
}

func TestWGPolicyReceiptRollbackAfterCommitUsesRecipientAndFreshPriorGeneration(t *testing.T) {
	a, runner, plan, first := wgReceiptFixture(t)
	_, previous := commitWGReceiptFixture(t, a, plan, first)
	previousRuntime, err := os.ReadFile(a.RuntimeConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	newProfile := strings.Replace(testOwnWireGuardProfile(""), "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=", "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=", 1)
	if _, err := a.Configs.Stage(a.ID(), "main", newProfile); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(filepath.Dir(first), "second")
	wrapper := &wgReceiptManagerAdapter{a}
	if err := wrapper.Snapshot(context.Background(), plan, second); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(context.Background(), plan, second); err != nil {
		t.Fatal(err)
	}
	if err := a.Activate(context.Background(), plan, second); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(context.Background(), plan, second); err != nil {
		t.Fatal(err)
	}
	state, _, _ := a.loadPolicyState()
	candidate, err := a.committedWGPolicyReference(state)
	if err != nil || candidate.ID == previous.ID {
		t.Fatal(candidate, err)
	}
	if err := a.Rollback(context.Background(), plan, second); err != nil {
		t.Fatal(err)
	}
	state, _, _ = a.loadPolicyState()
	restored, err := a.committedWGPolicyReference(state)
	if err != nil || restored.ID == previous.ID || restored.ID == candidate.ID {
		t.Fatal("prior receipt replayed", restored, err)
	}
	if err := verifyPolicyEvidence(context.Background(), a.Runner, a.ip(), state); err != nil {
		t.Fatal(err)
	}
	for _, retired := range []warpWGPolicyReference{previous, candidate} {
		status, err := a.inspectWGPolicyReference(context.Background(), retired, "")
		if err != nil || !status.Removed {
			t.Fatal("retired generation retained cleanup grant", status, err)
		}
	}
	if !runner.active {
		t.Fatal("previous runtime not restored")
	}
	if restoredRuntime, err := os.ReadFile(a.RuntimeConfigPath); err != nil || string(restoredRuntime) != string(previousRuntime) {
		t.Fatal("different previous peer was not restored", err)
	}
	runner.calls = nil
	starts := runner.starts
	fresh := *a
	if err := fresh.Rollback(context.Background(), plan, second); err != nil {
		t.Fatal("settled rollback retry", err)
	}
	repeated, err := a.committedWGPolicyReference(state)
	if err != nil || repeated.ID != restored.ID || starts != runner.starts || len(receiptMutationCalls(runner.calls)) != 0 {
		t.Fatal("settled rollback replayed or changed generation", repeated, err, runner.calls)
	}
}

func wgReceiptRollbackFailureFixture(t *testing.T, cut string) (*WARPWireGuardAdapter, *warpFakeRunner, Plan, string, warpWGPolicyReference) {
	t.Helper()
	a, runner, plan, first := wgReceiptFixture(t)
	_, previous := commitWGReceiptFixture(t, a, plan, first)
	newProfile := strings.Replace(testOwnWireGuardProfile(""), "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=", "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=", 1)
	if _, err := a.Configs.Stage(a.ID(), "main", newProfile); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(filepath.Dir(first), "second")
	_, candidate := commitWGReceiptFixture(t, a, plan, second)
	injected := false
	a.policyReceiptOptions.fault = func(point string, index int) error {
		if !injected && point == cut {
			injected = true
			if cut == "wg-rollback-reference" {
				// A real definite WriteAtomic failure: rename cannot replace a
				// directory with the final marker. No journal acknowledgement exists.
				return os.Mkdir(filepath.Join(second, wgPolicyRollbackFile), 0700)
			}
			return &os.PathError{Op: "remove", Path: filepath.Join(a.StateRoot, wgPolicyOperationDirectory), Err: os.ErrPermission}
		}
		return nil
	}
	if err := a.Rollback(context.Background(), plan, second); err == nil || !injected {
		t.Fatal("rollback publication cut not exercised", err)
	}
	if cut == "wg-rollback-reference" {
		if err := os.Remove(filepath.Join(second, wgPolicyRollbackFile)); err != nil {
			t.Fatal(err)
		}
	}
	a.policyReceiptOptions.fault = nil
	snapshot, err := readWarpWGSnapshot(second)
	if err != nil {
		t.Fatal(err)
	}
	restoration, exists, err := a.readWGPolicyReferenceNamed(second, wgPolicyRestorationFile, snapshot.State, true)
	if err != nil || !exists || restoration.RollbackOwner == "" || restoration.ID == previous.ID || restoration.ID == candidate.ID {
		t.Fatal("pre-publication transaction binding missing", restoration, err)
	}
	state, _, _ := a.loadPolicyState()
	current, err := a.committedWGPolicyReference(state)
	if err != nil || current.Checksum != restoration.Checksum || policyAdditionHash(state) != policyAdditionHash(restoration.Policy) {
		t.Fatal("restoration was not published before failure", current, err)
	}
	for _, retired := range []warpWGPolicyReference{previous, candidate} {
		if status, err := a.inspectWGPolicyReference(context.Background(), retired, ""); err != nil || !status.Removed || status.Unknown {
			t.Fatal("retired receipt unsettled", status, err)
		}
	}
	if raw, err := os.ReadFile(a.RuntimeConfigPath); err != nil || string(raw) != string(snapshot.RuntimeConfig) || !runner.active {
		t.Fatal("old runtime was not restored before failure", err)
	}
	return a, runner, plan, second, restoration
}

func TestWGPolicyReceiptRollbackPublicationCutsResumeWithoutReplay(t *testing.T) {
	for _, cut := range []string{"wg-rollback-reference", "wg-operation-remove"} {
		t.Run(cut, func(t *testing.T) {
			a, runner, plan, transaction, restoration := wgReceiptRollbackFailureFixture(t, cut)
			starts := runner.starts
			runner.calls = nil
			fresh := *a
			for retry := 0; retry < 2; retry++ {
				if err := fresh.Rollback(context.Background(), plan, transaction); err != nil {
					t.Fatal("new process rollback resume", err)
				}
			}
			state, _, _ := a.loadPolicyState()
			current, err := a.committedWGPolicyReference(state)
			if err != nil || current.Checksum != restoration.Checksum || starts != runner.starts || len(receiptMutationCalls(runner.calls)) != 0 {
				t.Fatal("rollback resume replayed mutation", current, err, runner.calls)
			}
			marker, exists, err := a.readWGPolicyReferenceNamed(transaction, wgPolicyRollbackFile, state, true)
			if err != nil || !exists || marker.Checksum != restoration.Checksum || a.checkWGPolicyOperation() != nil {
				t.Fatal("rollback resume failed settlement", marker, err)
			}
			if err := verifyPolicyEvidence(context.Background(), a.Runner, a.ip(), state); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWGPolicyReceiptRollbackResumeNeverAdoptsMissingUnknownOrLaterGeneration(t *testing.T) {
	for _, damage := range []string{"missing binding", "wrong owner", "corrupt final marker", "missing recipient", "removed recipient", "unknown recipient", "missing source", "new boot", "later generation"} {
		t.Run(damage, func(t *testing.T) {
			a, runner, plan, transaction, restoration := wgReceiptRollbackFailureFixture(t, "wg-operation-remove")
			switch damage {
			case "missing binding":
				if err := os.Remove(filepath.Join(transaction, wgPolicyRestorationFile)); err != nil {
					t.Fatal(err)
				}
			case "wrong owner":
				damaged := restoration
				damaged.RollbackOwner = strings.Repeat("f", 64)
				if err := writeWGPolicyReferenceNamed(context.Background(), transaction, wgPolicyRestorationFile, damaged); err != nil {
					t.Fatal(err)
				}
			case "corrupt final marker":
				if err := os.WriteFile(filepath.Join(transaction, wgPolicyRollbackFile), []byte("{broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing recipient":
				if err := os.Remove(filepath.Join(a.wgPolicyGenerationRoot(restoration, ""), policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "removed recipient":
				if err := a.removeWGPolicyReference(context.Background(), restoration, ""); err != nil {
					t.Fatal(err)
				}
			case "unknown recipient":
				a.policyReceiptOptions.fault = func(point string, index int) error {
					if point == "cleanup-intent" {
						return errors.New("fixture lost cleanup acknowledgement")
					}
					return nil
				}
				if err := a.removeWGPolicyReference(context.Background(), restoration, ""); err == nil {
					t.Fatal("unknown cleanup cut missing")
				}
				a.policyReceiptOptions.fault = nil
			case "missing source":
				if err := os.Remove(filepath.Join(a.StateRoot, wgPolicyOperationDirectory, wgPolicyCandidateDirectory, policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "new boot":
				a.policyReceiptOptions.boot = func() (string, error) { return "WG-new-boot", nil }
			case "later generation":
				if err := a.removeSettledWGPolicyOperation(context.Background(), restoration); err != nil {
					t.Fatal(err)
				}
				commitWGReceiptFixture(t, a, plan, filepath.Join(filepath.Dir(transaction), "later"))
			}
			runtimeBefore, err := os.ReadFile(a.RuntimeConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			starts := runner.starts
			runner.calls = nil
			fresh := *a
			if err := fresh.Rollback(context.Background(), plan, transaction); err == nil {
				t.Fatal("unbound/unknown restoration accepted")
			}
			runtimeAfter, err := os.ReadFile(a.RuntimeConfigPath)
			if err != nil || string(runtimeBefore) != string(runtimeAfter) || starts != runner.starts || len(receiptMutationCalls(runner.calls)) != 0 || !runner.active {
				t.Fatal("unknown restoration mutated runtime", err, runner.calls)
			}
		})
	}
}

func TestWGPolicyReceiptRollbackInterruptedRestorationNeverUsesCandidateMarkers(t *testing.T) {
	a, runner, plan, first := wgReceiptFixture(t)
	commitWGReceiptFixture(t, a, plan, first)
	second := filepath.Join(filepath.Dir(first), "second")
	commitWGReceiptFixture(t, a, plan, second)
	cut := errors.New("fixture interrupted restoration transfer")
	a.policyReceiptOptions.fault = func(point string, index int) error {
		if point == "promotion-copy" {
			return cut
		}
		return nil
	}
	if err := a.Rollback(context.Background(), plan, second); !errors.Is(err, cut) {
		t.Fatal("restoration transfer cut missing", err)
	}
	if regularFile(filepath.Join(second, wgPolicyRestorationFile)) || a.checkWGPolicyOperation() == nil || !runner.active || len(runner.policy.defaults) != 2 {
		t.Fatal("unknown restoration not retained")
	}
	fresh := *a
	fresh.policyReceiptOptions.fault = nil
	starts := runner.starts
	runner.calls = nil
	if err := fresh.Rollback(context.Background(), plan, second); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal("unknown restoration replayed", err)
	}
	if starts != runner.starts || len(receiptMutationCalls(runner.calls)) != 0 || !runner.active || len(runner.policy.defaults) != 2 {
		t.Fatal("candidate markers retired unknown restoration", runner.calls)
	}
}

func TestWGPolicyReceiptStaleRollbackCannotRetireRecoveryGeneration(t *testing.T) {
	a, runner, plan, transaction := wgReceiptFixture(t)
	_, original := commitWGReceiptFixture(t, a, plan, transaction)
	// Deliberate fixture kernel loss does not acknowledge receipt removal.
	runner.active, runner.policy.entries, runner.policy.defaults, runner.endpoint = false, nil, map[string]string{}, wgEndpointKernelFake{}
	fresh := *a
	if err := fresh.Reconcile(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	state, _, _ := a.loadPolicyState()
	recovered, err := a.committedWGPolicyReference(state)
	if err != nil || recovered.ID == original.ID {
		t.Fatal("recovery replayed original generation", recovered, err)
	}
	runner.calls = nil
	if err := a.Rollback(context.Background(), plan, transaction); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal("stale transaction accepted", err)
	}
	if len(receiptMutationCalls(runner.calls)) != 0 || !runner.active {
		t.Fatal("stale transaction mutated recovered runtime", runner.calls)
	}
	status, err := a.inspectWGPolicyReference(context.Background(), recovered, "")
	if err != nil || !status.Complete || status.Unknown {
		t.Fatal("current receipt retired by stale transaction", status, err)
	}
}

func TestWGPolicyReceiptStaleActivateCannotReplaceLaterGeneration(t *testing.T) {
	for _, prior := range []bool{false, true} {
		t.Run(fmt.Sprint(prior), func(t *testing.T) {
			a, runner, plan, transaction := wgReceiptFixture(t)
			if prior {
				commitWGReceiptFixture(t, a, plan, transaction)
			}
			stale := filepath.Join(filepath.Dir(transaction), "stale")
			wrapper := &wgReceiptManagerAdapter{a}
			if err := wrapper.Snapshot(context.Background(), plan, stale); err != nil {
				t.Fatal(err)
			}
			if err := a.Stage(context.Background(), plan, stale); err != nil {
				t.Fatal(err)
			}
			if prior {
				runner.active, runner.policy.entries, runner.policy.defaults, runner.endpoint = false, nil, map[string]string{}, wgEndpointKernelFake{}
				if err := a.Reconcile(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
			} else {
				commitWGReceiptFixture(t, a, plan, transaction)
			}
			state, _, _ := a.loadPolicyState()
			current, err := a.committedWGPolicyReference(state)
			if err != nil {
				t.Fatal(err)
			}
			runtimeBefore, err := os.ReadFile(a.RuntimeConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			runner.calls = nil
			if err := a.Activate(context.Background(), plan, stale); !errors.Is(err, ErrPolicyAdditionUnknown) {
				t.Fatal("stale activation accepted", err)
			}
			runtimeAfter, err := os.ReadFile(a.RuntimeConfigPath)
			if err != nil || string(runtimeBefore) != string(runtimeAfter) || len(receiptMutationCalls(runner.calls)) != 0 || !runner.active || regularFile(filepath.Join(stale, "wg-activation-started")) {
				t.Fatal("stale activation changed current generation", err, runner.calls)
			}
			if status, err := a.inspectWGPolicyReference(context.Background(), current, ""); err != nil || !status.Complete || status.Unknown {
				t.Fatal("current generation retired by stale activation", status, err)
			}
		})
	}
}

func TestWGPolicyReceiptRefreshUsesFreshGenerationAndFencesUnknown(t *testing.T) {
	for _, outcome := range []string{"success", "failed health", "unknown selector"} {
		t.Run(outcome, func(t *testing.T) {
			a, runner, plan, transaction := wgReceiptFixture(t)
			oldState, oldRef := commitWGReceiptFixture(t, a, plan, transaction)
			newPlan := plan
			newPlan.Routes = append([]Route(nil), plan.Routes...)
			newPlan.Routes[0].CIDRs = []string{"8.8.8.8/32", "2001:4860:4860::8888/128"}
			sentinel := errors.New("fixture refresh health failure")
			if outcome == "failed health" {
				a.HealthProbe = func(context.Context, string) error { return sentinel }
			}
			if outcome == "unknown selector" {
				a.policyReceiptOptions.fault = func(point string, index int) error {
					if point == "add" && index == 3 {
						return sentinel
					}
					return nil
				}
			}
			changed, err := a.RefreshPolicy(context.Background(), newPlan)
			if outcome == "unknown selector" {
				if changed || !errors.Is(err, ErrPolicyAdditionUnknown) || !runner.active || len(runner.policy.defaults) != 2 {
					t.Fatal("unknown refresh retired defaults/runtime", changed, err, runner.policy.defaults)
				}
				fresh := *a
				fresh.policyReceiptOptions.fault = nil
				runner.calls = nil
				if err := fresh.Reconcile(context.Background(), plan); !errors.Is(err, ErrPolicyAdditionUnknown) || len(receiptMutationCalls(runner.calls)) != 0 {
					t.Fatal("pending unknown operation replayed", err, runner.calls)
				}
				if err := fresh.Deactivate(context.Background()); !errors.Is(err, ErrPolicyAdditionUnknown) || !runner.active || len(runner.policy.defaults) != 2 {
					t.Fatal("Stop guessed unknown refresh away", err, runner.policy.defaults)
				}
				return
			}
			if outcome == "success" && (err != nil || !changed) || outcome == "failed health" && (!errors.Is(err, sentinel) || changed) {
				t.Fatal("refresh result", changed, err)
			}
			state, _, _ := a.loadPolicyState()
			ref, err := a.committedWGPolicyReference(state)
			if err != nil || ref.ID == oldRef.ID {
				t.Fatal("refresh/restoration replayed old grant", ref, err)
			}
			if outcome == "failed health" && !samePolicy(state, oldState) || outcome == "success" && samePolicy(state, oldState) {
				t.Fatal("refresh published wrong policy", state)
			}
			if status, err := a.inspectWGPolicyReference(context.Background(), oldRef, ""); err != nil || !status.Removed || status.Unknown {
				t.Fatal("old refresh generation remains active", status, err)
			}
			if err := verifyPolicyEvidence(context.Background(), a.Runner, a.ip(), state); err != nil {
				t.Fatal("fresh generation not present", err)
			}
			if err := a.checkWGPolicyOperation(); err != nil {
				t.Fatal("settled operation directory retained", err)
			}
		})
	}
}

func TestWGPolicyReceiptCorruptPriorSnapshotFencesCandidateCleanup(t *testing.T) {
	for _, damage := range []string{"checksum", "directory ID", "policy binding"} {
		t.Run(damage, func(t *testing.T) {
			a, runner, plan, first := wgReceiptFixture(t)
			commitWGReceiptFixture(t, a, plan, first)
			second := filepath.Join(filepath.Dir(first), "second")
			commitWGReceiptFixture(t, a, plan, second)
			snapshot, err := readWarpWGSnapshot(second)
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "checksum":
				snapshot.PolicyGeneration.Checksum = strings.Repeat("0", 64)
			case "directory ID":
				snapshot.PolicyGeneration.ID = "../untrusted"
				snapshot.PolicyGeneration.Checksum = wgPolicyReferenceChecksum(*snapshot.PolicyGeneration)
			case "policy binding":
				snapshot.PolicyGeneration.Policy.Prefixes = []string{"8.8.8.8/32"}
				snapshot.PolicyGeneration.Policy.Rules = nil
				snapshot.PolicyGeneration.Checksum = wgPolicyReferenceChecksum(*snapshot.PolicyGeneration)
			}
			data, _ := json.Marshal(snapshot)
			if err := os.WriteFile(filepath.Join(second, "snapshot.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			runner.calls = nil
			if err := a.Rollback(context.Background(), plan, second); !errors.Is(err, ErrPolicyAdditionReceipt) {
				t.Fatal("corrupt snapshot accepted", err)
			}
			if len(receiptMutationCalls(runner.calls)) != 0 || !runner.active {
				t.Fatal("candidate cleanup preceded snapshot validation", runner.calls)
			}
		})
	}
}

func TestWGPolicyReceiptNewBootRequiresIndependentAbsence(t *testing.T) {
	for _, foreignFamily := range []int{0, 4, 6} {
		t.Run(fmt.Sprint(foreignFamily), func(t *testing.T) {
			a, runner, plan, transaction := wgReceiptFixture(t)
			boot := "WG-boot-before"
			a.policyReceiptOptions.boot = func() (string, error) { return boot, nil }
			_, oldRef := commitWGReceiptFixture(t, a, plan, transaction)
			runner.active, runner.policy.entries, runner.policy.defaults, runner.endpoint = false, nil, map[string]string{}, wgEndpointKernelFake{}
			boot = "WG-boot-after"
			if foreignFamily != 0 {
				metric := "0"
				if foreignFamily == 6 {
					metric = "1024"
				}
				runner.policy.defaults[fmt.Sprintf("%d/%d", foreignFamily, a.table())] = "default dev rz-wg proto boot metric " + metric + "\n"
			}
			runner.calls = nil
			fresh := *a
			err := fresh.Reconcile(context.Background(), plan)
			if foreignFamily != 0 {
				if !errors.Is(err, ErrPolicyAdditionUnknown) || len(receiptMutationCalls(runner.calls)) != 0 {
					t.Fatal("new boot adopted matching foreign tuple", err, runner.calls)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			state, _, _ := a.loadPolicyState()
			newRef, err := a.committedWGPolicyReference(state)
			if err != nil || newRef.ID == oldRef.ID || newRef.Boot != boot {
				t.Fatal("new boot reused old grant", newRef, err)
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "route del default") && strings.Contains(call, fmt.Sprintf("table %d", a.table())) || strings.Contains(call, "rule del") && strings.Contains(call, fmt.Sprintf("lookup %d", a.table())) {
					t.Fatal("old boot cleanup executed", call)
				}
			}
		})
	}
}

func TestWGPolicyReceiptMissingCorruptAndRemovedRecipientNeverFallback(t *testing.T) {
	for _, damage := range []string{"missing reference", "missing receipt", "corrupt reference", "removed recipient"} {
		t.Run(damage, func(t *testing.T) {
			a, runner, plan, transaction := wgReceiptFixture(t)
			_, ref := commitWGReceiptFixture(t, a, plan, transaction)
			switch damage {
			case "missing reference":
				os.Remove(filepath.Join(a.StateRoot, wgPolicyReferenceFile))
			case "missing receipt":
				os.Remove(filepath.Join(a.wgPolicyGenerationRoot(ref, ""), policyAdditionFile))
			case "corrupt reference":
				os.WriteFile(filepath.Join(a.StateRoot, wgPolicyReferenceFile), []byte("{broken"), 0600)
			case "removed recipient":
				if err := a.removeWGPolicyReference(context.Background(), ref, ""); err != nil {
					t.Fatal(err)
				}
				if err := a.Commit(context.Background(), plan, transaction); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("commit accepted removed recipient", err)
				}
				return
			}
			runner.calls = nil
			if err := a.Deactivate(context.Background()); err == nil {
				t.Fatal("missing authority accepted")
			}
			if len(receiptMutationCalls(runner.calls)) != 0 || !runner.active {
				t.Fatal("legacy cleanup fallback", runner.calls)
			}
		})
	}
}
