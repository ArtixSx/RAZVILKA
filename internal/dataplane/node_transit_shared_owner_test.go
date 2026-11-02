package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNodeTransitSharedOwnerKeepsAppliedPresenceAndDeleteBoundaries(t *testing.T) {
	for _, operation := range []string{"applied-presence", "before-delete"} {
		for _, shared := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/default", true: "/original-shared"}[shared], func(t *testing.T) {
				base, runner, _ := nodeTransitFixture(t)
				var events []string
				check := func(context.Context, NodeTransitSpec) error { events = append(events, "guard"); return nil }
				runtime := nodeTransitRuntime{runner: runner, ip: "ip", preflight: check, guard: check, beforeDelete: check, register: base.runtime.register}
				if shared {
					runtime.preflight, runtime.guard, runtime.beforeDelete = nil, nil, nil
					runtime.sharedOwner = newNodeTransitSharedOwner(base.spec, base.root, check)
				}
				lease, err := newNodeTransitLeaseWithOptions(base.spec, base.root, runtime, base.options)
				if err != nil {
					t.Fatal(err)
				}
				runner.rules[4] = []string{runner.line()}
				runner.beforeRead = func(_ context.Context, family int) error {
					events = append(events, map[int]string{4: "read4", 6: "read6"}[family])
					return nil
				}
				want := []string{"guard", "read4", "read6", "guard", "guard"}
				if operation == "before-delete" {
					err = lease.effectRuntime().BeforeDelete(context.Background(), 0)
					want = []string{"guard", "guard"}
				} else {
					err = lease.verifyAppliedPresence(context.Background())
				}
				if shared {
					want = want[:len(want)-1]
				}
				if err != nil || !reflect.DeepEqual(events, want) || runner.adds != 0 || runner.deletes != 0 {
					t.Fatal("changed original guarded read/delete comparison", err, events, want)
				}
			})
		}
	}
}

func TestNodeTransitSharedOwnerAppliedClosingAndCopyRefuse(t *testing.T) {
	for _, scenario := range []string{"closing-failure", "copied-owner", "copied-lease", "foreign-presence"} {
		t.Run(scenario, func(t *testing.T) {
			base, runner, _ := nodeTransitFixture(t)
			calls := 0
			failure := errors.New("original closing comparison failed")
			check := func(context.Context, NodeTransitSpec) error {
				calls++
				if scenario == "closing-failure" && calls == 2 {
					return failure
				}
				return nil
			}
			owner := newNodeTransitSharedOwner(base.spec, base.root, check)
			lease, err := newNodeTransitLeaseWithOptions(base.spec, base.root, nodeTransitRuntime{runner: runner, ip: "ip", sharedOwner: owner, register: base.runtime.register}, base.options)
			if err != nil {
				t.Fatal(err)
			}
			runner.rules[4] = []string{runner.line()}
			switch scenario {
			case "copied-owner":
				lease.runtime.sharedOwner = &nodeTransitSharedOwner{self: owner, spec: owner.spec, root: owner.root, check: owner.check}
			case "copied-lease":
				lease = &nodeTransitLease{spec: lease.spec, root: lease.root, plan: lease.plan, digest: lease.digest, runtime: lease.runtime, options: lease.options}
			case "foreign-presence":
				runner.rules[6] = []string{runner.line()}
			}
			err = lease.verifyAppliedPresence(context.Background())
			if err == nil || runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("changed original gained authority", err)
			}
			if scenario == "closing-failure" && !errors.Is(err, failure) {
				t.Fatal("lost closing failure", err)
			}
			if scenario == "copied-owner" || scenario == "copied-lease" {
				if calls != 0 || lease.effectRuntime().BeforeDelete(context.Background(), 0) == nil {
					t.Fatal("copy invoked original guard or gained delete admission", calls)
				}
			}
		})
	}
}

func TestNodeTransitSharedOwnerEffectDiagnosticsRetainCause(t *testing.T) {
	base, runner, _ := nodeTransitFixture(t)
	failure := errors.New("private original failure text")
	owner := newNodeTransitSharedOwner(base.spec, base.root, func(context.Context, NodeTransitSpec) error { return failure })
	lease, err := newNodeTransitLeaseWithOptions(base.spec, base.root, nodeTransitRuntime{runner: runner, ip: "ip", sharedOwner: owner, register: base.runtime.register}, base.options)
	if err != nil {
		t.Fatal(err)
	}
	guardErr := lease.effectRuntime().Guard(context.Background(), 0)
	_, presenceErr := lease.effectRuntime().ExactPresence(context.Background(), 0)
	for phase, err := range map[string]error{"effect-guard": guardErr, "effect-presence": presenceErr} {
		if !errors.Is(err, failure) || err.Error() != "node transit phase="+phase || strings.Contains(err.Error(), failure.Error()) {
			t.Fatal("changed error identity or leaked private diagnostic", phase, err)
		}
	}
}

// These are explicitly modeled inventory/command tests. Native routing is
// checked separately; no count or callback result mints resource authority.
func TestNodeTransitSharedOwnerKeepsFullGuardAroundBothFamilyReads(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "independent-default", true: "explicit-same-owner"}[shared], func(t *testing.T) {
			base, runner, _ := nodeTransitFixture(t)
			var events []string
			guard := func(context.Context, NodeTransitSpec) error { events = append(events, "guard"); return nil }
			runner.beforeRead = func(_ context.Context, family int) error {
				if family == 4 {
					events = append(events, "read4")
				} else {
					events = append(events, "read6")
				}
				return nil
			}
			runtime := nodeTransitRuntime{runner: runner, ip: "ip", preflight: guard, guard: guard, beforeDelete: guard, register: base.runtime.register}
			if shared {
				runtime.preflight, runtime.guard, runtime.beforeDelete = nil, nil, nil
				runtime.sharedOwner = newNodeTransitSharedOwner(base.spec, base.root, guard)
			}
			lease, err := newNodeTransitLeaseWithOptions(base.spec, base.root, runtime, base.options)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.effectRuntime().Preflight(context.Background()); err != nil {
				t.Fatal(err)
			}
			want := []string{"guard", "guard", "read4", "read6", "guard", "guard"}
			if shared {
				want = []string{"guard", "read4", "read6", "guard"}
			}
			if !reflect.DeepEqual(events, want) || runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("changed full IO guard/effect boundary", events, want)
			}
		})
	}
}

func TestNodeTransitSharedOwnerClosingGuardAndReadFailuresRemainErrors(t *testing.T) {
	for _, scenario := range []string{"closing-owner", "read", "canceled", "foreign-presence"} {
		t.Run(scenario, func(t *testing.T) {
			base, runner, _ := nodeTransitFixture(t)
			failure := errors.New("actual modeled owner/read failure")
			calls := 0
			check := func(ctx context.Context, _ NodeTransitSpec) error {
				calls++
				if scenario == "closing-owner" && calls == 2 {
					return failure
				}
				return ctx.Err()
			}
			if scenario == "read" {
				runner.readErrors[6] = failure
			}
			if scenario == "foreign-presence" {
				runner.rules[4] = []string{runner.line()}
			}
			owner := newNodeTransitSharedOwner(base.spec, base.root, check)
			lease, err := newNodeTransitLeaseWithOptions(base.spec, base.root, nodeTransitRuntime{runner: runner, ip: "ip", sharedOwner: owner, register: base.runtime.register}, base.options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			err = lease.effectRuntime().Preflight(ctx)
			if err == nil || runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("refusal became effect/permission", err)
			}
			if scenario == "closing-owner" && !errors.Is(err, failure) {
				t.Fatal("underlying callback/read error lost", err)
			}
			// The existing readPolicyRules reader intentionally sanitizes the
			// raw tool error. Retain its refusal, not a new raw-cause contract.
			if scenario == "read" && !errors.Is(err, ErrNodeTransitUnavailable) {
				t.Fatal("read refusal lost", err)
			}
			if scenario == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
		})
	}
}

func TestNodeTransitSharedOwnerIsOriginalOneUseAndCannotMixCallbacks(t *testing.T) {
	base, runner, _ := nodeTransitFixture(t)
	check := func(context.Context, NodeTransitSpec) error { return nil }
	owner := newNodeTransitSharedOwner(base.spec, base.root, check)
	runtime := nodeTransitRuntime{runner: runner, ip: "ip", sharedOwner: owner, register: base.runtime.register}
	lease, err := newNodeTransitLeaseWithOptions(base.spec, base.root, runtime, base.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newNodeTransitLeaseWithOptions(base.spec, base.root, runtime, base.options); err == nil {
		t.Fatal("shared owner adopted another lease")
	}
	copy := &nodeTransitSharedOwner{self: owner, spec: owner.spec, root: owner.root, check: check}
	runtime.sharedOwner = copy
	if _, err := newNodeTransitLeaseWithOptions(base.spec, base.root, runtime, base.options); err == nil {
		t.Fatal("copied owner admitted")
	}
	runtime.sharedOwner = newNodeTransitSharedOwner(base.spec, base.root, check)
	runtime.preflight = check
	if _, err := newNodeTransitLeaseWithOptions(base.spec, base.root, runtime, base.options); err == nil {
		t.Fatal("independent callback silently replaced")
	}
	foreign := &nodeTransitLease{spec: lease.spec, root: lease.root, runtime: lease.runtime, options: lease.options}
	if err := foreign.effectRuntime().Preflight(context.Background()); err == nil {
		t.Fatal("copied lease borrowed original owner")
	}
	lease.root += "-different"
	if err := lease.effectRuntime().Preflight(context.Background()); err == nil {
		t.Fatal("changed frozen owner root admitted")
	}
}
