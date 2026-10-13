package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type xrayInventoryBudgetKey struct{}
type xrayInventoryBudget struct{ physical time.Duration }

func TestXrayInventoryScopeOriginalManagerKeepsExpensiveGuardsOutsideBudget(t *testing.T) {
	audited := false
	audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
		if audited {
			return
		}
		audited = true
		originalGuard, originalIdentity, originalRead := pre.owner.scope.guard, checks.identity.withCurrent, checks.read
		defer func() {
			pre.owner.scope.guard, checks.identity.withCurrent, checks.read = originalGuard, originalIdentity, originalRead
		}()
		// Model the actual reviewed Provider's finite aggregate with a logical
		// clock. Three six-unit physical guards exceed its sixteen-unit budget;
		// the four old nested stock/consumer guards therefore reproduce 449
		// without a slow or scheduler-dependent sixteen-second sleep.
		inside, outside, reads := 0, 0, 0
		checks.identity.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
			return originalIdentity(c, func(held context.Context, id netidentity.Identity) error {
				budget := &xrayInventoryBudget{}
				return use(context.WithValue(held, xrayInventoryBudgetKey{}, budget), id)
			})
		}
		pre.owner.scope.guard = func(c context.Context) error {
			if budget, ok := c.Value(xrayInventoryBudgetKey{}).(*xrayInventoryBudget); ok {
				inside++
				budget.physical += 6 * time.Millisecond
				if budget.physical > 16*time.Millisecond {
					return context.DeadlineExceeded
				}
			} else {
				outside++
			}
			return originalGuard(c)
		}
		var retained context.Context
		checks.read = func(c context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
			reads++
			retained = c
			return originalRead(c, id)
		}
		if err := checks.InventoryCheck(ctx, checks.network, pre.execution.plan.LAN); err != nil {
			t.Fatalf("original collector exceeded its nested physical budget: %v", err)
		}
		if inside != 0 || outside != 2 || reads != 3 {
			t.Fatalf("physical inside=%d outside=%d complete captures=%d", inside, outside, reads)
		}
		if _, err := checks.xraySelectedTCPStockExecution(retained); err == nil {
			t.Fatal("closed original capture session supplied a stock allowance")
		}
	}
	x, p, ctx, cut, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
	result, err := x.manager.Apply(ctx, p, nil)
	if !audited || !errors.Is(err, cut) || result.State != "rolled-back" || len(result.Resources) != 0 || x.model.starts != 0 || x.model.stops != 0 {
		t.Fatal("original Manager did not preserve cold ordinary rollback without native resources")
	}
}

func TestXrayInventoryScopeFullOriginalGuardRefusesBothBookends(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(map[int]string{1: "opening", 2: "closing"}[failAt], func(t *testing.T) {
			audited := false
			audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
				if audited {
					return
				}
				audited = true
				originalGuard, originalRead := pre.owner.scope.guard, checks.read
				defer func() { pre.owner.scope.guard, checks.read = originalGuard, originalRead }()
				calls, reads := 0, 0
				pre.owner.scope.guard = func(c context.Context) error {
					calls++
					if calls == failAt {
						return ErrReviewChanged
					}
					return originalGuard(c)
				}
				checks.read = func(c context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					return originalRead(c, id)
				}
				err := checks.InventoryCheck(ctx, checks.network, pre.execution.plan.LAN)
				if !errors.Is(err, ErrReviewChanged) || !errors.Is(err, ErrXrayOperationOwner) || calls != failAt || reads != 2*(failAt-1) {
					t.Fatalf("original bookend calls=%d captures=%d error=%v", calls, reads, err)
				}
				if pre.owner.revoked == nil {
					t.Fatal("forward source/control/physical loss did not revoke the same original owner")
				}
			}
			x, p, ctx, _, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
			result, _ := x.manager.Apply(ctx, p, nil)
			if !audited || len(result.Resources) != 0 || x.model.starts != 0 || x.model.stops != 0 {
				t.Fatal("changed original owner reached native resource issuance")
			}
		})
	}
}

func TestXrayInventoryScopeBothCompleteImageComparisonsRefuseDrift(t *testing.T) {
	for _, changedAt := range []int{2, 3} {
		t.Run(map[int]string{2: "held-capture", 3: "after-closing-owner"}[changedAt], func(t *testing.T) {
			audited := false
			audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
				if audited {
					return
				}
				audited = true
				originalRead := checks.read
				defer func() { checks.read = originalRead }()
				reads := 0
				checks.read = func(c context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
					image, err := originalRead(c, id)
					reads++
					if reads == changedAt {
						image.NFTGeneration++
					}
					return image, err
				}
				err := checks.InventoryCheck(ctx, checks.network, pre.execution.plan.LAN)
				if !errors.Is(err, ErrBackendInventoryUnknown) || reads != changedAt {
					t.Fatalf("complete image drift captures=%d error=%v", reads, err)
				}
			}
			x, p, ctx, cut, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
			result, err := x.manager.Apply(ctx, p, nil)
			if !audited || !errors.Is(err, cut) || result.State != "rolled-back" {
				t.Fatal("image refusal lost the original ordinary rollback")
			}
		})
	}
}

func TestXrayInventoryScopeCopiedCanceledAndPublishedContextsCannotSupplyRead(t *testing.T) {
	audited := false
	audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
		if audited {
			return
		}
		audited = true
		bound, read, err := checks.openXraySelectedTCPInventoryScope(ctx)
		if err != nil || read == nil || read.current(bound) != nil {
			t.Fatal("original cold collector could not open its own read")
		}
		defer read.close()
		if checks.InventoryCheck(bound, checks.network, pre.execution.plan.LAN) == nil {
			t.Fatal("nested collector reused its original one-call read session")
		}
		copy := &xraySelectedTCPInventoryScope{checks: checks, pre: pre, identity: read.identity, provider: read.provider, inventory: read.inventory, original: ctx, bound: read.bound, cleanup: read.cleanup}
		copy.self = copy
		copy.open.Store(true)
		for _, changed := range []context.Context{
			context.WithValue(bound, xraySelectedTCPInventoryScopeKey{}, copy),
			context.WithValue(bound, xrayOperationOwnerKey{}, (*xrayOperationOwner)(nil)),
			context.WithValue(bound, xraySelectedTCPPreResourceKey{}, &xraySelectedTCPPreResource{}),
			context.WithValue(bound, xrayOperationMaterialKey{}, (*XrayOperationMaterial)(nil)),
		} {
			if _, err := checks.xraySelectedTCPStockExecution(changed); err == nil {
				t.Fatal("copied or changed original read supplied stock authority")
			}
		}
		cancelled, cancel := context.WithCancel(bound)
		cancel()
		if read.current(cancelled) == nil {
			t.Fatal("cancelled original read remained usable")
		}
		originalProvider := checks.identity.provider
		checks.identity.provider = &netidentity.Provider{}
		read.inventory.reader.Provider = checks.identity.provider
		changedProvider := read.current(bound)
		checks.identity.provider, read.inventory.reader.Provider = originalProvider, originalProvider
		if changedProvider == nil {
			t.Fatal("replacement Provider pair replaced the original captured identity")
		}
		if read.checkClosing(bound) != nil || read.checkClosing(bound) == nil {
			t.Fatal("closing source bookend was not one-use")
		}
		pre.attempted.Store(true)
		if read.current(bound) == nil || checks.InventoryCheck(ctx, checks.network, pre.execution.plan.LAN) == nil {
			t.Fatal("first original publication attempt reverted to cold inventory")
		}
		read.close()
		if read.current(bound) == nil {
			t.Fatal("closed read was replayable")
		}
	}
	x, p, ctx, _, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
	result, _ := x.manager.Apply(ctx, p, nil)
	if !audited || len(result.Resources) != 0 || x.model.starts != 0 || x.model.stops != 0 {
		t.Fatal("invalid cold read reached native resource issuance")
	}
}

func TestXrayInventoryScopeCancellationDuringCaptureCannotFinishRead(t *testing.T) {
	audited := false
	audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
		if audited {
			return
		}
		audited = true
		originalRead := checks.read
		defer func() { checks.read = originalRead }()
		original, cancel := context.WithCancel(ctx)
		defer cancel()
		reads := 0
		checks.read = func(c context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
			image, err := originalRead(c, id)
			reads++
			if reads == 2 {
				cancel()
			}
			return image, err
		}
		err := checks.InventoryCheck(original, checks.network, pre.execution.plan.LAN)
		if !errors.Is(err, context.Canceled) || reads != 2 {
			t.Fatalf("cancelled capture reached final read: captures=%d error=%v", reads, err)
		}
	}
	x, p, ctx, cut, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
	result, err := x.manager.Apply(ctx, p, nil)
	if !audited || !errors.Is(err, cut) || result.State != "rolled-back" || len(result.Resources) != 0 || x.model.starts != 0 {
		t.Fatal("cancelled collector changed the original cold transaction authority")
	}
}

func TestXrayInventoryScopeClosingPublicationWithoutKernelRowsRefuses(t *testing.T) {
	for _, publication := range []string{"closing-guard", "final-capture"} {
		t.Run(publication, func(t *testing.T) {
			audited := false
			audit := func(checks *NetworkPolicyChecks, ctx context.Context, pre *xraySelectedTCPPreResource) {
				if audited {
					return
				}
				audited = true
				originalGuard, originalRead := pre.owner.scope.guard, checks.read
				view := checks.proxies["xray"]
				defer func() {
					pre.owner.scope.guard, checks.read = originalGuard, originalRead
					_ = os.Remove(view.forwardingPath())
				}()
				calls, reads := 0, 0
				publish := func() error {
					// An uncertain receipt publication in the actual original
					// registered producer has no rows in the frozen read fixture.
					if err := os.MkdirAll(view.StateRoot, 0700); err != nil {
						return err
					}
					return os.WriteFile(view.forwardingPath(), []byte("{}"), 0600)
				}
				pre.owner.scope.guard = func(c context.Context) error {
					calls++
					if calls == 2 && publication == "closing-guard" {
						if err := publish(); err != nil {
							return err
						}
					}
					return originalGuard(c)
				}
				checks.read = func(c context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					if reads == 3 && publication == "final-capture" {
						if err := publish(); err != nil {
							return BackendInventorySnapshot{}, err
						}
					}
					return originalRead(c, id)
				}
				err := checks.InventoryCheck(ctx, checks.network, pre.execution.plan.LAN)
				if !errors.Is(err, ErrNetworkPolicyConsumers) || calls != 2 || reads != map[string]int{"closing-guard": 2, "final-capture": 3}[publication] {
					t.Fatalf("closing producer publication escaped final absence: guards=%d captures=%d error=%v", calls, reads, err)
				}
			}
			x, p, ctx, cut, _ := newXrayPreResourceManagerFixture(t, false, LANPolicyXraySelectedTCPMode, audit)
			result, err := x.manager.Apply(ctx, p, nil)
			if !audited || !errors.Is(err, cut) || result.State != "rolled-back" || len(result.Resources) != 0 || x.model.starts != 0 {
				t.Fatal("consumer publication refusal lost the original cold rollback")
			}
		})
	}
}
