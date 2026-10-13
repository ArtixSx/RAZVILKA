//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type xrayPreparedInventoryEntryKey struct{}

type xrayPreparedManagerFixture struct {
	x       *xrayOperationFixture
	checks  *NetworkPolicyChecks
	plan    Plan
	ctx     context.Context
	cut     error
	inside  int
	outside int
	reads   int
}

// Actual original Manager, material/issuer, registration, private files and
// journal run. Only NI/kernel/physical command facts are private fixture models.
// Unlike the cold fixture, this ScopeCheck accepts the SAME actually issued r.
func newXrayPreparedManagerFixture(t *testing.T, audit func(*xrayPreparedManagerFixture, context.Context, *XraySelectedTCPExecutionResource)) *xrayPreparedManagerFixture {
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
	// The original Linux issuer validates and holds this bounded ELF model.
	// No version command, native syscall or process controller may execute it.
	if err := os.WriteFile(x.material.binary, xraySelectedTCPELFModel(), 0700); err != nil {
		t.Fatal(err)
	}
	p.Ready, p.Adapters = true, []string{NetworkPolicyAdapterID, "xray"}
	f := &xrayPreparedManagerFixture{x: x, plan: p, cut: errors.New("fixture forward refusal after original LAN validate")}
	image := nfqwsDirectStockReviewedVendorFixture()
	provider := netidentity.NewProcProvider()
	identity := &networkPolicyIdentity{mode: LANPolicyXraySelectedTCPMode, value: image.Scope.Network, provider: provider}
	identity.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		// Tag only the actual collector aggregate. The fixture's one-consumer
		// adapter also has an outer identity wrapper; production shared LIST
		// runs full owner/inventory bookends outside that wrapper. This models
		// the collector's 16-unit limit, not native timing or the whole Apply.
		if ctx.Value(xrayPreparedInventoryEntryKey{}) != nil && ctx.Value(xrayInventoryBudgetKey{}) == nil {
			ctx = context.WithValue(ctx, xrayInventoryBudgetKey{}, &xrayInventoryBudget{})
		}
		err := use(ctx, identity.value)
		return errors.Join(err, ctx.Err())
	}
	binding, model, _ := lanReceiptBindingFixture(t)
	model.plan = CloneLANPolicyRuntime(p.LAN)
	image.IPTables, image.IP6Tables = binding.Runtime.IPTables, binding.Runtime.IP6Tables
	guard := func(ctx context.Context, got *LANPolicyRuntimePlan, _ LANPolicyEffect) error {
		if !reflect.DeepEqual(got, p.LAN) {
			return ErrReviewChanged
		}
		return ctx.Err()
	}
	binding.ApplyGuard, binding.CleanupGuard = guard, guard
	audited := false
	binding.Runtime.ScopeCheck = func(ctx context.Context, lan *LANPolicyRuntimePlan) error {
		stock, err := f.checks.xraySelectedTCPStockExecution(ctx)
		if err != nil || stock == nil {
			return errors.Join(ErrNetworkPolicyConsumers, err)
		}
		if stock.pre == nil && (stock.resource == nil || stock.resource != x.material.execution.resource) {
			return ErrXrayOperationOwner
		}
		if stock.resource != nil && audit != nil && !audited {
			audited = true
			audit(f, ctx, stock.resource)
			return f.cut
		}
		return ctx.Err()
	}
	binding.RetireCheck = func(ctx context.Context, lan *LANPolicyRuntimePlan) error { return f.checks.RetireCheck(ctx, lan) }
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: identity.mode, Binding: binding,
		InventoryCheck: func(ctx context.Context, got netidentity.Identity, lan *LANPolicyRuntimePlan) error {
			return f.checks.InventoryCheck(context.WithValue(ctx, xrayPreparedInventoryEntryKey{}, true), got, lan)
		}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = x.manager.Register(gate); err != nil {
		t.Fatal(err)
	}
	f.checks, err = x.manager.bindNetworkPolicyChecks(gate, func(ctx context.Context, got netidentity.Identity) (BackendInventorySnapshot, error) {
		f.reads++
		if got != image.Scope.Network {
			return BackendInventorySnapshot{}, ErrNetworkPolicyIdentity
		}
		return nfqwsDirectStockTestClone(image), ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.checks.Close() })
	inventory := &BackendInventory{review: strings.Repeat("a", 64), reader: backendInventoryReader{Provider: provider,
		IPTables: gate.Binding.Runtime.IPTables, IP6Tables: gate.Binding.Runtime.IP6Tables, Runner: gate.Binding.Runtime.Runner}}
	f.checks.inventory = inventory
	x.material, err = ReviewXrayOperationMaterial(x.ctx, x.manager, x.control, x.adapter, proof, x.spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithReviewGuard(x.ctx, func(ctx context.Context) error {
		e := x.material.execution
		if e != nil && e.resource != nil && !x.material.IsCleanupContext(ctx) {
			if budget, ok := ctx.Value(xrayInventoryBudgetKey{}).(*xrayInventoryBudget); ok {
				f.inside++
				budget.physical += 6 * time.Millisecond
				if budget.physical > 16*time.Millisecond {
					return context.DeadlineExceeded
				}
			} else {
				f.outside++
			}
			e.resource.scope.mu.Lock()
			steps := e.resource.scope.execution.Steps
			cut := len(steps) != 0 && steps[len(steps)-1].Adapter == NetworkPolicyAdapterID && steps[len(steps)-1].Phase == "validate" && steps[len(steps)-1].State == "passed"
			e.resource.scope.mu.Unlock()
			if cut {
				return f.cut
			}
		}
		return ctx.Err()
	})
	f.ctx, err = x.material.BindExecution(ctx, context.Background(), p, inventory, gate, f.checks,
		func(ctx context.Context, _ Plan) error { return ctx.Err() }, func(ctx context.Context, _ Plan) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	x.manager.FreshProfile = func(context.Context) (string, error) { return p.NetworkProfileID, nil }
	return f
}

func assertXrayPreparedOriginalRollback(t *testing.T, f *xrayPreparedManagerFixture, result Execution) {
	t.Helper()
	if result.State != "rolled-back" || len(result.Resources) != 1 || result.Resources[0].State != "unused" || result.Resources[0].Phase != "unused" {
		t.Fatalf("original prepared resource did not settle through rollback: state=%s resources=%d", result.State, len(result.Resources))
	}
	r := f.x.material.execution.resource
	if r == nil || r.owner == nil || r.material != f.x.material || r.versionUsed || r.versionChild != nil || r.startUsed || r.startACK || r.child != nil || r.selectorUsed || f.x.model.starts != 0 || f.x.model.stops != 0 {
		t.Fatal("original never-started retirement reached a native/version/effect issuer")
	}
	for _, adapter := range []string{"xray", NetworkPolicyAdapterID} {
		for _, phase := range []string{"rollback", "verify-rollback"} {
			found := false
			for _, step := range result.Steps {
				if step.Adapter == adapter && step.Phase == phase && step.State == "passed" {
					found = true
				}
			}
			if !found {
				t.Fatal("original reverse restoration/readback missing", adapter, phase)
			}
		}
	}
}

func TestXrayPreparedInventoryOriginalManagerStageValidateRollback(t *testing.T) {
	f := newXrayPreparedManagerFixture(t, nil)
	result, err := f.x.manager.Apply(f.ctx, f.plan, nil)
	// Assert original cleanup even for the old-source negative overlay, before
	// rejecting its prematurely failed LAN Validate coordinate.
	assertXrayPreparedOriginalRollback(t, f, result)
	for _, want := range []struct{ adapter, phase string }{{NetworkPolicyAdapterID, "snapshot"}, {"xray", "snapshot"}, {NetworkPolicyAdapterID, "stage"}, {"xray", "stage"}, {NetworkPolicyAdapterID, "validate"}} {
		found := false
		for _, step := range result.Steps {
			if step.Adapter == want.adapter && step.Phase == want.phase {
				found = step.State == "passed"
			}
		}
		if !found {
			t.Fatalf("actual post-resource phase refused: adapter=%s phase=%s deadline=%t inside=%d", want.adapter, want.phase, errors.Is(err, context.DeadlineExceeded), f.inside)
		}
	}
	if !errors.Is(err, f.cut) || errors.Is(err, context.DeadlineExceeded) || f.inside != 0 {
		t.Fatal("post-resource full physical guards still ran inside the collector", f.inside, f.outside, err)
	}
	for _, step := range result.Steps {
		if step.Phase == "activate" {
			t.Fatal("fixture reached Activate instead of its original forward refusal")
		}
	}
}

func TestXrayPreparedInventoryBookendsAndTrueFinalImage(t *testing.T) {
	f := newXrayPreparedManagerFixture(t, func(f *xrayPreparedManagerFixture, ctx context.Context, r *XraySelectedTCPExecutionResource) {
		beforeInside, beforeOutside, beforeReads := f.inside, f.outside, f.reads
		var saved context.Context
		original := f.checks.read
		f.checks.read = func(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
			saved = ctx
			return original(ctx, identity)
		}
		defer func() { f.checks.read = original }()
		if err := f.checks.InventoryCheck(context.WithValue(ctx, xrayPreparedInventoryEntryKey{}, true), f.checks.network, f.plan.LAN); err != nil {
			t.Fatal(err)
		}
		if f.inside != beforeInside || f.outside-beforeOutside != 2 || f.reads-beforeReads != 3 {
			t.Fatal("prepared read changed original bookends or complete images", f.inside-beforeInside, f.outside-beforeOutside, f.reads-beforeReads)
		}
		if _, err := f.checks.xraySelectedTCPStockExecution(saved); err == nil {
			t.Fatal("closed prepared session supplied a stock observation")
		}
		if r != f.x.material.execution.resource {
			t.Fatal("prepared read replaced the actual original resource")
		}
	})
	result, err := f.x.manager.Apply(f.ctx, f.plan, nil)
	if !errors.Is(err, f.cut) {
		t.Fatal(err)
	}
	assertXrayPreparedOriginalRollback(t, f, result)
}

func TestXrayPreparedInventoryOriginalActivateDispatchBeforeNative(t *testing.T) {
	f := newXrayPreparedManagerFixture(t, func(f *xrayPreparedManagerFixture, ctx context.Context, r *XraySelectedTCPExecutionResource) {
		e := f.x.material.execution
		originalRead, originalGuard := f.checks.read, r.scope.guard
		defer func() { f.checks.read, r.scope.guard = originalRead, originalGuard }()
		readReached, fullGuards := false, 0
		r.scope.guard = func(ctx context.Context) error {
			e.mu.Lock()
			started := e.started
			e.mu.Unlock()
			if started {
				fullGuards++
			}
			return originalGuard(ctx)
		}
		f.checks.read = func(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
			e.mu.Lock()
			started := e.started
			e.mu.Unlock()
			if started {
				readReached = true
				if ctx.Value(xraySelectedTCPPreparedInventoryScopeKey{}) != nil {
					t.Fatal("original Activate adopted a prepared collector grant")
				}
				return BackendInventorySnapshot{}, f.cut // Before any native call.
			}
			return originalRead(ctx, identity)
		}
		// Invoke the unchanged original publisher with the SAME actual issued
		// Manager resource/context. It must consume e.started and reach legacy
		// inventory, whose first complete read refuses before native/version.
		err := e.activate(ctx)
		e.mu.Lock()
		started := e.started
		e.mu.Unlock()
		if !errors.Is(err, f.cut) || !started || !readReached || fullGuards != 3 {
			t.Fatalf("original Activate did not dispatch its inventory: cut=%t started=%t read=%t full_guards=%d", errors.Is(err, f.cut), started, readReached, fullGuards)
		}
		if r.versionUsed || r.startUsed || r.versionChild != nil || r.child != nil || r.selectorUsed {
			t.Fatal("activation inventory refusal reached a native/version/effect issuer")
		}
	})
	_, err := f.x.manager.Apply(f.ctx, f.plan, nil)
	if !errors.Is(err, f.cut) {
		t.Fatal(err)
	}
}

func TestXrayPreparedInventoryDriftAndPublicationRefuse(t *testing.T) {
	for _, which := range []string{"opening-guard", "closing-guard", "provisional-image", "final-image", "final-process", "closing-process", "closing-common", "final-common", "cancel"} {
		t.Run(which, func(t *testing.T) {
			f := newXrayPreparedManagerFixture(t, func(f *xrayPreparedManagerFixture, ctx context.Context, r *XraySelectedTCPExecutionResource) {
				originalRead, originalGuard := f.checks.read, r.scope.guard
				reads, guards := 0, 0
				commonPath := filepath.Join(r.rootPath, policyAdditionFile)
				publish := func() {
					if strings.HasSuffix(which, "process") {
						r.observationMu.Lock()
						r.child = &xraySelectedTCPProcess{}
						r.observationMu.Unlock()
					} else if err := os.WriteFile(commonPath, []byte("unowned original-consumer publication"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				defer func() {
					f.checks.read, r.scope.guard = originalRead, originalGuard
					r.observationMu.Lock()
					r.child = nil
					r.observationMu.Unlock()
					_ = os.Remove(commonPath)
				}()
				c, cancel := context.WithCancel(ctx)
				defer cancel()
				r.scope.guard = func(ctx context.Context) error {
					guards++
					if guards == 1 && which == "opening-guard" || guards == 2 && which == "closing-guard" {
						return f.cut
					}
					if guards == 2 && (which == "closing-process" || which == "closing-common") {
						publish()
					}
					return originalGuard(ctx)
				}
				f.checks.read = func(ctx context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					image, err := originalRead(ctx, id)
					if reads == 2 && which == "provisional-image" || reads == 3 && which == "final-image" {
						image.Rows = append(image.Rows, BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "FOREIGN", "-j", "RETURN"}})
					}
					if reads == 3 && strings.HasPrefix(which, "final-") && which != "final-image" {
						publish()
					}
					if reads == 1 && which == "cancel" {
						cancel()
					}
					return image, err
				}
				if err := f.checks.InventoryCheck(context.WithValue(c, xrayPreparedInventoryEntryKey{}, true), f.checks.network, f.plan.LAN); err == nil {
					t.Fatal("prepared read accepted drift or rowless publication", which)
				}
			})
			result, err := f.x.manager.Apply(f.ctx, f.plan, nil)
			if !errors.Is(err, f.cut) {
				t.Fatal(err)
			}
			assertXrayPreparedOriginalRollback(t, f, result)
		})
	}
}

func TestXrayPreparedInventoryOriginalContextAndLifecycle(t *testing.T) {
	f := newXrayPreparedManagerFixture(t, func(f *xrayPreparedManagerFixture, ctx context.Context, r *XraySelectedTCPExecutionResource) {
		bound, read, err := f.checks.openXraySelectedTCPPreparedInventoryScope(ctx)
		if err != nil || read == nil {
			t.Fatal("actual issued prepared owner did not open its own collector", err)
		}
		defer read.close()
		copyRead := &xraySelectedTCPPreparedInventoryScope{origin: read.origin, checks: read.checks, execution: read.execution, resource: read.resource, owner: read.owner,
			identity: read.identity, provider: read.provider, inventory: read.inventory, original: read.original, bound: read.bound, cleanup: read.cleanup, record: read.record}
		copyRead.self = copyRead
		copyRead.open.Store(true)
		copyRead.bound = context.WithValue(read.original, xraySelectedTCPPreparedInventoryScopeKey{}, copyRead)
		if copyRead.current(copyRead.bound) == nil {
			t.Fatal("copied prepared owner renewed the original bound read")
		}
		if _, _, err := f.checks.openXraySelectedTCPPreparedInventoryScope(bound); err == nil {
			t.Fatal("nested read replaced its original session")
		}
		for _, field := range []string{"version", "start", "selector", "child", "record"} {
			r.observationMu.Lock()
			switch field {
			case "version":
				r.versionUsed = true
			case "start":
				r.startUsed = true
			case "selector":
				r.selectorUsed = true
			case "child":
				r.child = &xraySelectedTCPProcess{}
			case "record":
				r.scope.mu.Lock()
				index, _ := r.matching()
				r.scope.execution.Resources[index].Phase = "process-pending"
				r.scope.mu.Unlock()
			}
			r.observationMu.Unlock()
			if read.currentFinal(bound) == nil {
				t.Fatal("prepared session adopted a later lifecycle", field)
			}
			r.observationMu.Lock()
			r.versionUsed, r.startUsed, r.selectorUsed, r.child = false, false, false, nil
			r.scope.mu.Lock()
			r.scope.execution.Resources[0].Phase = "planned"
			r.scope.mu.Unlock()
			r.observationMu.Unlock()
		}
		read.close()
		if read.currentFinal(bound) == nil {
			t.Fatal("closed read remained usable")
		}
	})
	result, err := f.x.manager.Apply(f.ctx, f.plan, nil)
	if !errors.Is(err, f.cut) {
		t.Fatal(err)
	}
	assertXrayPreparedOriginalRollback(t, f, result)
}
