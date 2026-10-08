package dataplane

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual Manager/registrar/protected roots/control/configureActive; the native
// process/capture ACK and tool collector below are explicit models. No native
// effect, actual App source or ACTIVE permission is claimed by this fixture.
func nfqwsActiveCommandFixture(t *testing.T) (*nfqws2ActiveExecution, context.Context) {
	t.Helper()
	e, ctx := nfqwsUnlaunchedFixture(t)
	r := e.resource
	ctx = context.WithValue(ctx, nfqwsExecutionActiveReadbackKey{}, nfqwsExecutionActiveReadback(func(context.Context, *NFQWSScopedPlan, string, nfqwsExecutionActiveReadbackMode, NFQWSActiveObservation) error {
		return nil
	}))
	if err := r.configureActive(ctx, e.material.command); err != nil {
		t.Fatal(err)
	}
	e.inventory.review = strings.Repeat("d", 64)
	e.inventory.reader.IPTables = "/retained/iptables-legacy"
	e.inventory.reader.IP6Tables = "/retained/ip6tables-legacy"
	e.inventory.reader.CheckTools = func(context.Context, backendInventoryScope) error {
		t.Fatal("Start leaf reentered tool checks")
		return nil
	}
	e.inventory.reader.Runner = nfqws2RunFunc(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("Start leaf invoked a tool runner")
		return nil, nil
	})
	e.binding = &NFQWSScopedBinding{Tools: PolicyEffectTools{IPTables: e.inventory.reader.IPTables, IP6Tables: e.inventory.reader.IP6Tables},
		ApplyGuard: func(context.Context, *NFQWSScopedPlan, PolicyEffect) error {
			t.Fatal("Start leaf reentered full ApplyGuard")
			return nil
		},
		CleanupGuard: func(context.Context, *NFQWSScopedPlan, PolicyEffect) error {
			t.Fatal("Start leaf reentered full CleanupGuard")
			return nil
		}}
	o := &nfqws2ActiveOwner{adapter: e.material.adapter, command: e.material.command.clone(), admission: nfqws2ActiveProcessAdmission{Binding: r.binding}, state: "prepared"}
	p := &NFQWSPreparedHandle{owner: o}
	o.prepared = p
	e.prepared, e.launchInvoked = p, true
	e.material.adapter.activeProcess = o
	r.preparedOwner = p
	r.transferGuards = &nfqwsExecutionTransferGuards{control: e.material.control, originalCleanup: e.cleanup}
	r.startACK, r.preparedUsed = true, true
	r.scope.execution.Resources[0].Phase = "capture-ready" // Explicit native ACK model.
	return e, context.WithValue(ctx, nfqws2ActiveExecutionKey{}, e)
}

func nfqwsActiveCommandPolicyFixture(t *testing.T) (*nfqws2ActiveExecution, context.Context, *policyEffectFixture) {
	t.Helper()
	e, ctx := nfqwsActiveCommandFixture(t)
	f := newPolicyEffectFixture(t)
	plan, err := e.resource.plan.Effects()
	if err != nil {
		t.Fatal(err)
	}
	f.plan, f.root = plan, e.resource.root
	f.options.boot = func() (string, error) { return e.resource.plan.resources.BootID, nil }
	f.runtime.Tools = e.binding.Tools
	return e, ctx, f
}

// The real COMMON per-RPC issuer/writer, Gate and durable Stop are exercised.
// begin and kernel ACKs remain explicit models, never a native Start fixture.
func TestNFQWSActiveCommandStartConsumesActualCOMMONInvocationAndStopCleanup(t *testing.T) {
	e, ctx, f := nfqwsActiveCommandPolicyFixture(t)
	var escaped context.Context
	var escapedName string
	var escapedArgs []string
	starts := 0
	f.runtime.Runner = nfqws2RunFunc(func(c context.Context, name string, args ...string) ([]byte, error) {
		escaped, escapedName, escapedArgs = c, name, append([]string(nil), args...)
		var out []byte
		err := WithNFQWSScopedCommandStart(c, name, args, e.inventory.review, func() error {
			starts++
			var err error
			out, err = f.Run(c, name, args...) // Explicit kernel/Start model.
			return err
		})
		if err == nil && WithNFQWSScopedCommandStart(c, name, args, e.inventory.review, func() error { t.Fatal("repeated actual invocation began"); return nil }) == nil {
			t.Fatal("actual COMMON invocation could be consumed twice")
		}
		return out, err
	})
	if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
		t.Fatal("original COMMON Add/control admission refused", err)
	}
	if starts != len(f.plan.Effects) {
		t.Fatal("actual per-command invocation missing", starts)
	}
	if err := WithNFQWSScopedCommandStart(escaped, escapedName, escapedArgs, e.inventory.review, func() error { t.Fatal("escaped invocation began"); return nil }); err == nil {
		t.Fatal("escaped completed COMMON invocation revived")
	}
	done := make(chan struct{})
	close(done)
	e.prepared.owner.done = done
	e.prepared.owner.result = func() (nfqws2ActiveProcessLease, error) {
		t.Fatal("Start leaf reentered inactive result reader")
		return nfqws2ActiveProcessLease{}, nil
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, e.material.command.ControlRoot, strings.Repeat("7", 32), 0); err != nil {
		t.Fatal(err)
	}
	if err := e.material.control.WithStart(ctx, func() error { t.Fatal("durable Stop admitted a forward syscall"); return nil }); err == nil {
		t.Fatal("ready-only forward admission weakened")
	}
	if err := removePolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
		t.Fatal("original COMMON Delete/control cleanup admission refused", err)
	}
	if starts != 2*len(f.plan.Effects) {
		t.Fatal("actual reverse Delete invocations missing", starts)
	}
	status, err := inspectPolicyEffects(ctx, f.plan, f.root, f.options)
	if err != nil || !status.Removed || status.Unknown {
		t.Fatal("real COMMON did not close modeled effects", status, err)
	}
}

func TestNFQWSActiveCommandStartRefusesWithoutActualInvocationAndOnLeafFailure(t *testing.T) {
	for _, outcome := range []string{"raw-context", "wrong-alias", "wrong-argv", "wrong-digest", "begin-failure", "closing-owner-drift"} {
		t.Run(outcome, func(t *testing.T) {
			e, ctx, f := nfqwsActiveCommandPolicyFixture(t)
			starts := 0
			leafFailure := errors.New("modeled actual Start failure")
			f.runtime.Runner = nfqws2RunFunc(func(c context.Context, name string, args ...string) ([]byte, error) {
				digest := e.inventory.review
				switch outcome {
				case "raw-context":
					c = ctx // Original NFQ owner alone is not a COMMON invocation.
				case "wrong-alias":
					name = "/foreign/iptables-legacy"
				case "wrong-argv":
					args = append(append([]string(nil), args...), "--queue-bypass")
				case "wrong-digest":
					digest = strings.Repeat("e", 64)
				}
				return nil, WithNFQWSScopedCommandStart(c, name, args, digest, func() error {
					starts++
					if outcome == "begin-failure" {
						return leafFailure
					}
					if outcome == "closing-owner-drift" {
						nfqws2ActiveAdapterMu.Lock()
						e.material.adapter.activeExecution = nil
						nfqws2ActiveAdapterMu.Unlock()
					}
					return nil
				})
			})
			err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options)
			if err == nil || len(f.calls) != 0 || outcome == "begin-failure" && (!errors.Is(err, leafFailure) || starts != 1) || outcome == "closing-owner-drift" && starts != 1 || outcome != "begin-failure" && outcome != "closing-owner-drift" && starts != 0 {
				t.Fatal("invalid command gained a COMMON ACK", starts, err)
			}
			status, err := inspectPolicyEffects(ctx, f.plan, f.root, f.options)
			if err != nil || !status.Unknown || status.Complete {
				t.Fatal("refused/uncertain Start cleared the original COMMON intent", status, err)
			}
		})
	}
}

func TestNFQWSActiveCommandPureOwnerMatchesOnlyOriginalCompilerCommands(t *testing.T) {
	e, ctx := nfqwsActiveCommandFixture(t)
	plan, err := e.resource.plan.Effects()
	if err != nil {
		t.Fatal(err)
	}
	for i, effect := range plan.Effects {
		name := e.binding.Tools.command(effect.Tool)
		owner, err := nfqws2ReviewActiveCommandOwner(ctx, name, effect.Add, e.inventory.review)
		if err != nil || owner.execution != e || owner.resource != e.resource || owner.index != i || owner.cleanup {
			t.Fatal("original compiler Add refused", i, err)
		}
		if _, err := nfqws2ReviewActiveCommandOwner(ctx, name, effect.Delete, e.inventory.review); err == nil {
			t.Fatal("running original process authorized a Delete")
		}
	}
	done := make(chan struct{})
	close(done)
	e.prepared.owner.done = done
	e.prepared.owner.result = func() (nfqws2ActiveProcessLease, error) {
		t.Fatal("pure Start leaf reread sole Wait result")
		return nfqws2ActiveProcessLease{}, nil
	}
	for i, effect := range plan.Effects {
		owner, err := nfqws2ReviewActiveCommandOwner(ctx, e.binding.Tools.command(effect.Tool), effect.Delete, e.inventory.review)
		if err != nil || owner.index != i || !owner.cleanup {
			t.Fatal("local original joined-owner Delete comparison refused", i, err)
		}
	}
}

func TestNFQWSActiveCommandPureOwnerRefusesCopiesDriftAndBroadCommands(t *testing.T) {
	for _, name := range []string{"raw-context", "copy-execution", "copy-material", "copy-resource", "copy-prepared", "foreign-association", "wrong-phase", "wrong-digest", "wrong-alias", "extra-argv", "read-argv", "stopped-forward", "resource-root-replaced"} {
		t.Run(name, func(t *testing.T) {
			e, ctx := nfqwsActiveCommandFixture(t)
			p, err := e.resource.plan.Effects()
			if err != nil {
				t.Fatal(err)
			}
			command, args, digest := e.binding.Tools.command(p.Effects[0].Tool), append([]string(nil), p.Effects[0].Add...), e.inventory.review
			switch name {
			case "raw-context":
				ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, nil)
			case "copy-execution":
				ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, &nfqws2ActiveExecution{self: e.self, material: e.material})
			case "copy-material":
				e.material = &NFQWSActiveMaterial{self: e.material.self}
			case "copy-resource":
				copied := *e.resource
				e.resource = &copied
			case "copy-prepared":
				e.prepared = &NFQWSPreparedHandle{owner: e.prepared.owner}
			case "foreign-association":
				e.material.adapter.activeExecution = &nfqws2ActiveExecution{}
			case "wrong-phase":
				e.resource.scope.execution.Resources[0].Phase = "process-pending"
			case "wrong-digest":
				digest = strings.Repeat("e", 64)
			case "wrong-alias":
				command = "/foreign/iptables-legacy"
			case "extra-argv":
				args = append(args, "--queue-bypass")
			case "read-argv":
				args = []string{"-t", "mangle", "-S"}
			case "stopped-forward":
				e.prepared.owner.stopRequested = true
			case "resource-root-replaced":
				if err := os.Rename(e.resource.root, e.resource.root+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(e.resource.root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := nfqws2ReviewActiveCommandOwner(ctx, command, args, digest); err == nil {
				t.Fatal("copied/drifted command owner admitted", name)
			}
		})
	}
}
