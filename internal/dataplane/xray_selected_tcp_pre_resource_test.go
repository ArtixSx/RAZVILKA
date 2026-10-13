package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Full transaction using actual original Manager/registration,
// material, source, control and journal owners. Complete backend/physical facts
// use the existing PRIVATE trusted collector/fixture leaf. No native command,
// actual router coverage or public successful collector DTO is constructed.
func newXrayPreResourceManagerFixture(t *testing.T, advance bool, mode string, audits ...func(*NetworkPolicyChecks, context.Context, *xraySelectedTCPPreResource)) (*xrayOperationFixture, Plan, context.Context, error, *int) {
	t.Helper()
	x := newXrayOperationFixture(t, func(spec *XraySelectedTCPRedirectSpec) {
		*spec = xraySelectedTCPFixtureOneClient(t, *spec, "mac")
		var err error
		spec.LAN, err = CompileXraySelectedTCPLANPolicyRuntime(spec.Generation, spec.LAN.Ingress)
		if err != nil {
			t.Fatal(err)
		}
	})
	x.originalScope(t)
	p := cloneExecutionResourcePlan(x.scope.plan)
	proof := x.material.material.proof
	if err := x.scope.close(); err != nil {
		t.Fatal(err)
	}
	if err := x.material.Close(); err != nil {
		t.Fatal(err)
	}
	p.Ready, p.Adapters = true, []string{NetworkPolicyAdapterID, "xray"}
	image := nfqwsDirectStockReviewedVendorFixture()
	originalProvider := netidentity.NewProcProvider()
	// This concrete Xray profile has exactly this registered consumer. The
	// full managed-list profile separately requires BOTH genuine WG sessions;
	// missing/UNKNOWN sessions remain a refusal, never modeled as successful.
	identity := &networkPolicyIdentity{mode: mode, value: image.Scope.Network, provider: originalProvider}
	identity.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		before := identity.value
		if err := use(ctx, before); err != nil {
			return err
		}
		if before != identity.value {
			return ErrNetworkPolicyIdentity
		}
		return ctx.Err()
	}
	binding, model, _ := lanReceiptBindingFixture(t)
	model.plan = CloneLANPolicyRuntime(p.LAN)
	image.IPTables, image.IP6Tables = binding.Runtime.IPTables, binding.Runtime.IP6Tables
	originalLAN := CloneLANPolicyRuntime(p.LAN)
	guard := func(ctx context.Context, got *LANPolicyRuntimePlan, _ LANPolicyEffect) error {
		if !reflect.DeepEqual(got, originalLAN) {
			return ErrReviewChanged
		}
		return ctx.Err()
	}
	binding.ApplyGuard, binding.CleanupGuard = guard, guard
	var checks *NetworkPolicyChecks
	binding.Runtime.ScopeCheck = func(ctx context.Context, lan *LANPolicyRuntimePlan) error {
		stock, stockErr := checks.xraySelectedTCPStockExecution(ctx)
		if stock == nil || stock.pre == nil || stockErr != nil {
			return ErrNetworkPolicyConsumers
		}
		for _, audit := range audits {
			audit(checks, ctx, stock.pre)
		}
		return nil
	}
	binding.RetireCheck = func(ctx context.Context, lan *LANPolicyRuntimePlan) error {
		return checks.RetireCheck(ctx, lan)
	}
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: identity.mode, Binding: binding,
		InventoryCheck: func(ctx context.Context, got netidentity.Identity, lan *LANPolicyRuntimePlan) error {
			return checks.InventoryCheck(ctx, got, lan)
		}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.manager.Register(gate); err != nil {
		t.Fatal(err)
	}
	reads := 0
	checks, err = x.manager.bindNetworkPolicyChecks(gate, func(_ context.Context, got netidentity.Identity) (BackendInventorySnapshot, error) {
		reads++
		if got != image.Scope.Network {
			return BackendInventorySnapshot{}, ErrNetworkPolicyIdentity
		}
		return nfqwsDirectStockTestClone(image), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = checks.Close() })
	inventory := &BackendInventory{review: strings.Repeat("a", 64), reader: backendInventoryReader{
		Provider: originalProvider, IPTables: gate.Binding.Runtime.IPTables, IP6Tables: gate.Binding.Runtime.IP6Tables, Runner: gate.Binding.Runtime.Runner}}
	checks.inventory = inventory
	x.material, err = ReviewXrayOperationMaterial(x.ctx, x.manager, x.control, x.adapter, proof, x.spec)
	if err != nil {
		t.Fatal(err)
	}
	// Fail AFTER the actual LAN Stage publishes its candidate, at the original
	// Manager's closing forward guard. Cleanup uses the same original material's
	// pre-issued context and must not borrow this deliberately revoked forward
	// eligibility. No Xray Stage/resource/native action has happened at the cut.
	beforeResource := errors.New("fixture forward cut after original LAN Stage")
	candidatePath := filepath.Join(x.manager.StateRoot, "transactions", p.PlanID, NetworkPolicyAdapterID, "candidate.json")
	ctx := WithReviewGuard(x.ctx, func(ctx context.Context) error {
		if !advance && !x.material.IsCleanupContext(ctx) {
			if info, err := os.Lstat(candidatePath); err == nil && info.Mode().IsRegular() {
				return beforeResource
			}
		}
		return ctx.Err()
	})
	ctx, err = x.material.BindExecution(ctx, context.Background(), p, inventory, gate, checks,
		func(ctx context.Context, _ Plan) error { return ctx.Err() }, func(ctx context.Context, _ Plan) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	x.manager.FreshProfile = func(context.Context) (string, error) { return p.NetworkProfileID, nil }
	return x, p, ctx, beforeResource, &reads
}

func TestXrayPreResourceOriginalManagerLANStageAndOrdinaryRollback(t *testing.T) {
	x, p, ctx, beforeResource, reads := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode)
	result, err := x.manager.Apply(ctx, p, nil)
	if !errors.Is(err, beforeResource) || errors.Is(err, ErrLANPolicyRuntime) || result.State != "rolled-back" {
		t.Logf("cut=%t lan=%t backend=%t review=%t consumer=%t owner=%t stage=%s", errors.Is(err, beforeResource), errors.Is(err, ErrLANPolicyRuntime), errors.Is(err, ErrBackendInventoryUnknown), errors.Is(err, ErrReviewChanged), errors.Is(err, ErrNetworkPolicyConsumers), errors.Is(err, ErrXrayOperationOwner), LANPolicyPreflightFailureStage(err))
		for _, step := range result.Steps {
			t.Logf("adapter=%s phase=%s state=%s", step.Adapter, step.Phase, step.State)
		}
		t.Fatalf("original transaction did not reach LAN Stage then ordinary rollback: state=%s", result.State)
	}
	if result.RollbackVerified || len(result.Resources) != 0 || x.material.execution.resource != nil || x.model.starts != 0 || x.model.stops != 0 || *reads < 4 {
		t.Fatal("pre-resource transaction claimed native effects/cleanup or skipped fresh stock bookends")
	}
	if len(result.Steps) != 7 {
		t.Fatal("unexpected original snapshot/stage/reverse rollback order")
	}
	want := [][3]string{{NetworkPolicyAdapterID, "snapshot", "passed"}, {"xray", "snapshot", "passed"},
		{NetworkPolicyAdapterID, "stage", "failed"}, {"xray", "rollback", "passed"}, {"xray", "verify-rollback", "passed"},
		{NetworkPolicyAdapterID, "rollback", "passed"}, {NetworkPolicyAdapterID, "verify-rollback", "passed"}}
	for i, step := range result.Steps {
		if [3]string{step.Adapter, step.Phase, step.State} != want[i] {
			t.Fatal("original forward/reverse transaction order changed")
		}
	}
	if x.manager.HasPendingManagedXraySelectedTCP() {
		t.Fatal("proved never-issued resource was retained as an unknown native owner")
	}
}

func TestXrayPreResourceOriginalManagerReachesIssuerWithoutRelocking(t *testing.T) {
	var cleanup context.Context
	x, p, ctx, _, _ := newXrayPreResourceManagerFixture(t, true, LANPolicyXraySelectedTCPMode,
		func(_ *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
			if cleanup == nil {
				var err error
				cleanup, err = pre.context(ctx, true)
				if err != nil {
					t.Fatal("original pre-issued cleanup context refused")
				}
			}
		})
	result, err := x.manager.Apply(ctx, p, nil)
	pre := x.material.execution.preResource
	if pre == nil || !pre.attempted.Load() || x.material.execution.preparing || x.model.starts != 0 || x.model.stops != 0 {
		t.Fatal("original Xray Stage did not enter its sticky actual issuer boundary")
	}
	stageReached := false
	for _, step := range result.Steps {
		if step.Adapter == "xray" && step.Phase == "stage" {
			stageReached = true
			if step.State != "failed" {
				t.Fatal("fixture with no actual executable claimed successful Xray publication")
			}
		}
	}
	if !stageReached || err == nil || result.State != "rollback-failed" || result.RollbackVerified ||
		(!errors.Is(err, ErrExecutionJournal) && !errors.Is(err, errXraySelectedTCPRuntime)) {
		t.Logf("stage=%t journal=%t runtime=%t owner=%t", stageReached, errors.Is(err, ErrExecutionJournal), errors.Is(err, errXraySelectedTCPRuntime), errors.Is(err, ErrXrayOperationOwner))
		t.Fatal("original issuer did not reach a strict file/executable refusal with compensation fenced")
	}
	if cleanup == nil || pre.unused(cleanup, x.material.execution) == nil {
		t.Fatal("attempted materialization fell back to never-issued cleanup")
	}
	// The real issuer published the private config before its executable/file
	// refusal. Moving this private fixture directory away cannot erase the
	// actual attempt history or turn its absent readback into unused proof.
	root := pre.owner.scope.root
	resources := filepath.Join(root, "execution-resources")
	if entries, err := os.ReadDir(resources); err != nil || len(entries) != 1 {
		t.Fatal("actual original config publication did not precede strict refusal")
	}
	if err := os.Rename(resources, filepath.Join(root, "attempted-resource")); err != nil {
		t.Fatal("private fixture could not present later absent resource path")
	}
	if pre.unused(cleanup, x.material.execution) == nil {
		t.Fatal("later absence erased the sticky original materialization attempt")
	}
}

func TestXrayPreResourceManagedListKeepsUnknownWGSessionsFenced(t *testing.T) {
	x, p, ctx, beforeResource, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyManagedListMode)
	result, err := x.manager.Apply(ctx, p, nil)
	if !errors.Is(err, beforeResource) || !errors.Is(err, ErrRuntimeInactivity) || result.State != "rollback-failed" || result.RollbackVerified ||
		x.model.starts != 0 || x.model.stops != 0 {
		t.Fatal("pre-resource proof bypassed the full profile's genuine WG session requirement")
	}
}

func TestXrayPreResourceFinalStockLeafRequiresOriginalScopeAndStableImage(t *testing.T) {
	audited := false
	audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
		if audited {
			return
		}
		audited = true
		cleanup, err := pre.context(ctx, true)
		if err != nil || checks.retiredWGInventory(cleanup, pre.execution.plan.LAN) != nil {
			t.Fatal("final stock leaf refused its actual original cleanup owner")
		}
		for _, changed := range []context.Context{
			context.WithValue(cleanup, xrayOperationOwnerKey{}, (*xrayOperationOwner)(nil)),
			context.WithValue(cleanup, xraySelectedTCPExecutionKey{}, (*xraySelectedTCPExecution)(nil)),
			context.WithValue(cleanup, xraySelectedTCPPreResourceKey{}, &xraySelectedTCPPreResource{self: pre.self, owner: pre.owner, execution: pre.execution}),
			context.WithValue(cleanup, xraySelectedTCPExecutionKey{}, &xraySelectedTCPExecution{}),
		} {
			if checks.retiredWGInventory(changed, pre.execution.plan.LAN) == nil {
				t.Fatal("missing or copied original owner acquired stock comparison")
			}
		}
		originalRead := checks.read
		calls := 0
		checks.read = func(ctx context.Context, got netidentity.Identity) (BackendInventorySnapshot, error) {
			image, err := originalRead(ctx, got)
			calls++
			if calls == 2 {
				image.NFTGeneration++
			}
			return image, err
		}
		err = checks.retiredWGInventory(cleanup, pre.execution.plan.LAN)
		checks.read = originalRead
		if !errors.Is(err, ErrBackendInventoryUnknown) {
			t.Fatal("changed final full image supplied a stock settlement")
		}
		if checks.retiredWGInventory(ctx, pre.execution.plan.LAN) == nil {
			t.Fatal("forward context claimed retired stock cleanup")
		}
	}
	x, p, ctx, cut, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
	result, err := x.manager.Apply(ctx, p, nil)
	if !audited || !errors.Is(err, cut) || result.State != "rolled-back" {
		t.Fatal("original Manager did not exercise the final held stock leaf")
	}
}

func TestXrayPreResourceRejectsChangedOriginalMetadata(t *testing.T) {
	audited := false
	audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
		if audited {
			return
		}
		audited = true
		cleanup, err := pre.context(ctx, true)
		if err != nil || pre.unused(cleanup, pre.execution) != nil {
			t.Fatal("original never-issued owner refused its held cleanup proof")
		}
		e, s := pre.execution, pre.owner.scope
		mutations := []struct {
			name   string
			change func() func()
		}{
			{"execution-plan", func() func() {
				old := e.plan.Digest
				e.plan.Digest = strings.Repeat("c", 64)
				return func() { e.plan.Digest = old }
			}},
			{"scope-plan", func() func() {
				old := s.plan.Digest
				s.plan.Digest = strings.Repeat("c", 64)
				return func() { s.plan.Digest = old }
			}},
			{"journal-digest", func() func() {
				old := s.execution.Digest
				s.execution.Digest = strings.Repeat("c", 64)
				return func() { s.execution.Digest = old }
			}},
			{"journal-plan-id", func() func() {
				old := s.execution.PlanID
				s.execution.PlanID = "dp-ffffffffffffffff"
				return func() { s.execution.PlanID = old }
			}},
			{"resource-plan-id", func() func() {
				s.execution.ResourcePlanID = s.plan.PlanID
				return func() { s.execution.ResourcePlanID = "" }
			}},
			{"binding", func() func() { e.bound = false; return func() { e.bound = true } }},
			{"started", func() func() { e.started = true; return func() { e.started = false } }},
			{"retired", func() func() { e.retired = true; return func() { e.retired = false } }},
			{"preparing", func() func() { e.preparing = true; return func() { e.preparing = false } }},
			{"retained", func() func() { s.retained = true; return func() { s.retained = false } }},
			{"pending", func() func() { s.pending = true; return func() { s.pending = false } }},
			{"network-identity", func() func() {
				old := s.networkIdentity
				s.networkIdentity = &networkPolicyIdentity{}
				return func() { s.networkIdentity = old }
			}},
			{"registry", func() func() {
				old := s.manager.registryGeneration
				s.manager.registryGeneration++
				return func() { s.manager.registryGeneration = old }
			}},
			{"manager-root", func() func() {
				old := s.manager.StateRoot
				s.manager.StateRoot = t.TempDir()
				return func() { s.manager.StateRoot = old }
			}},
			{"anchored-root", func() func() { old := s.root; s.root = t.TempDir(); return func() { s.root = old } }},
			{"closed-collector", func() func() { checks.closed.Store(true); return func() { checks.closed.Store(false) } }},
		}
		for _, mutation := range mutations {
			t.Run(mutation.name, func(t *testing.T) {
				restore := mutation.change()
				defer restore()
				if pre.current(cleanup) == nil {
					t.Fatal("changed original metadata supplied never-issued cleanup")
				}
			})
		}
		copyPre := &xraySelectedTCPPreResource{owner: pre.owner, execution: e}
		copyPre.self = copyPre
		copyOwner := &xrayOperationOwner{material: pre.owner.material, scope: s}
		copyOwner.self = copyOwner
		for _, changed := range []context.Context{
			ctx, // Forward eligibility is never the original cleanup proof.
			context.WithValue(cleanup, xraySelectedTCPPreResourceKey{}, copyPre),
			context.WithValue(cleanup, xrayOperationOwnerKey{}, copyOwner),
			context.WithValue(cleanup, xrayOperationMaterialKey{}, &XrayOperationMaterial{}),
			context.WithValue(cleanup, xraySelectedTCPExecutionKey{}, &xraySelectedTCPExecution{}),
		} {
			if pre.unused(changed, e) == nil {
				t.Fatal("foreign/forward context acquired original never-issued proof")
			}
		}
		cancelled, cancel := context.WithCancel(cleanup)
		cancel()
		if pre.unused(cancelled, e) == nil {
			t.Fatal("cancelled cleanup acquired never-issued proof")
		}
		// These files are only in the actual Manager's private test transaction.
		// Empty maps/absent native children cannot override publication evidence.
		if err := s.owned.MkdirAll("xray", 0700); err != nil {
			t.Fatal("private adapter directory refused")
		}
		if err := s.owned.WriteAtomic("xray/foreign-snapshot", []byte("private fixture"), 0600); err != nil {
			t.Fatal("private file evidence refused")
		}
		if pre.unused(cleanup, e) == nil {
			t.Fatal("nonempty original adapter directory acquired unused proof")
		}
		if err := os.Remove(filepath.Join(s.root, "xray", "foreign-snapshot")); err != nil {
			t.Fatal("private fixture file could not be removed")
		}
		if err := s.owned.MkdirAll("execution-resources", 0700); err != nil {
			t.Fatal("private resource intent directory refused")
		}
		if pre.unused(cleanup, e) == nil {
			t.Fatal("existing resource intent directory acquired unused proof")
		}
		if err := os.Remove(filepath.Join(s.root, "execution-resources")); err != nil {
			t.Fatal("empty private fixture intent directory could not be removed")
		}
		originalGuard := s.guard
		s.guard = func(context.Context) error { return ErrReviewChanged }
		err = pre.unused(cleanup, e)
		s.guard = originalGuard
		if err == nil {
			t.Fatal("changed original physical/control guard acquired unused proof")
		}
	}
	x, p, ctx, cut, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
	result, err := x.manager.Apply(ctx, p, nil)
	if !audited || !errors.Is(err, cut) || result.State != "rolled-back" {
		t.Fatal("metadata refusal checks changed the original ordinary rollback")
	}
}

func TestXrayPreResourceClosedOwnersCannotFallback(t *testing.T) {
	for _, closeOwner := range []string{"material", "registration", "control", "scope"} {
		t.Run(closeOwner, func(t *testing.T) {
			audited := false
			audit := func(_ *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
				if audited {
					return
				}
				audited = true
				cleanup, err := pre.context(ctx, true)
				if err != nil {
					t.Fatal("original cleanup owner refused before revocation")
				}
				switch closeOwner {
				case "material":
					err = pre.owner.material.Close()
				case "registration":
					err = pre.owner.material.registration.Close()
				case "control":
					err = pre.owner.material.control.Close()
				case "scope":
					err = pre.owner.scope.close()
				}
				if err != nil || pre.unused(cleanup, pre.execution) == nil {
					t.Fatal("closed original owner supplied never-issued fallback")
				}
			}
			x, p, ctx, _, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
			result, err := x.manager.Apply(ctx, p, nil)
			if !audited || err == nil || result.State != "canary-failed" || result.RollbackVerified || len(result.Resources) != 0 || x.model.starts != 0 || x.model.stops != 0 {
				t.Fatal("closed owner escaped the original Manager refusal")
			}
		})
	}
}

func TestXrayPreResourceOriginalIssuerPreparationPreventsConcurrentClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var held atomic.Bool
	x, p, ctx, _, _ := newXrayPreResourceManagerFixture(t, true, LANPolicyXraySelectedTCPMode,
		func(_ *NetworkPolicyChecks, _ context.Context, pre *xraySelectedTCPPreResource) {
			s := pre.owner.scope
			if held.Load() {
				return
			}
			originalGuard := s.guard
			s.guard = func(ctx context.Context) error {
				e := pre.execution
				e.mu.Lock()
				preparing := e.preparing
				e.mu.Unlock()
				if preparing && !e.material.IsCleanupContext(ctx) && held.CompareAndSwap(false, true) {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return originalGuard(ctx)
			}
		})
	finished := make(chan error, 1)
	go func() {
		result, err := x.manager.Apply(ctx, p, nil)
		if err == nil || result.State != "rollback-failed" || result.RollbackVerified {
			finished <- errors.New("original blocked issuer escaped strict refusal")
			return
		}
		finished <- nil
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("actual original preparing issuer did not reach its live guard")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- x.material.Close() }()
	select {
	case err := <-closeResult:
		if !errors.Is(err, ErrPolicyAdditionUnknown) || x.material.closed.Load() {
			t.Fatal("concurrent Close released the original preparing issuer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Close waited across the original live preparing issuer")
	}
	xraySelectedTCPExecutions.Lock()
	original := xraySelectedTCPExecutions.live[x.adapter] == x.material.execution
	xraySelectedTCPExecutions.Unlock()
	if !original || x.control.Current(ctx) != nil {
		t.Fatal("concurrent Close erased the original association/control")
	}
	// Release the guard without closing the channel twice in the failure path.
	release <- struct{}{}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("original issuer did not preserve refusal after concurrent Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual original issuer did not join after its held guard")
	}
	if !x.material.execution.preResource.attempted.Load() || x.model.starts != 0 || x.model.stops != 0 {
		t.Fatal("concurrent Close erased actual attempt history or caused native effects")
	}
}

func TestXrayPreResourceStockGrantsNoActiveConsumerRows(t *testing.T) {
	audited := false
	audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
		if audited {
			return
		}
		audited = true
		consumers, err := checks.singleXraySelectedTCPConsumers(ctx, pre.execution.plan.LAN)
		if err != nil || len(consumers) != 0 {
			t.Fatal("never-issued stock comparison acquired an active consumer")
		}
		if checks.ConsumerCheck(ctx, pre.execution.plan.LAN) == nil {
			t.Fatal("stock observation replaced required actual native/COMMON consumer")
		}
		cleanup, err := pre.context(ctx, true)
		if err != nil {
			t.Fatal("original cleanup context refused")
		}
		originalRead := checks.read
		defer func() { checks.read = originalRead }()
		for _, failure := range []string{"project-body", "incomplete", "foreign-tool-review", "unknown-read"} {
			t.Run(failure, func(t *testing.T) {
				checks.read = func(ctx context.Context, got netidentity.Identity) (BackendInventorySnapshot, error) {
					image, err := originalRead(ctx, got)
					switch failure {
					case "project-body":
						image.Rows = append(image.Rows, BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "RZX_foreign", "-j", "RETURN"}})
					case "incomplete":
						image.Coverage.RegisteredTablesComplete = false
					case "foreign-tool-review":
						image.Scope.ToolReviewID = strings.Repeat("f", 64)
					case "unknown-read":
						return BackendInventorySnapshot{}, ErrBackendInventoryUnknown
					}
					return image, err
				}
				if checks.retiredWGInventory(cleanup, pre.execution.plan.LAN) == nil || checks.InventoryCheck(ctx, checks.network, pre.execution.plan.LAN) == nil {
					t.Fatal("unknown/foreign full image acquired a pre-resource allowance")
				}
			})
		}
	}
	x, p, ctx, cut, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
	result, err := x.manager.Apply(ctx, p, nil)
	if !audited || !errors.Is(err, cut) || result.State != "rolled-back" {
		t.Fatal("negative inventory models changed the original ordinary rollback")
	}
}
