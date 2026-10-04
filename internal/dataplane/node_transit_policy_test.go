package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNodeTransitReservationsFollowCompleteSharedRegistry(t *testing.T) {
	owners, transit := PolicyOwnershipSpecs(), NodeTransitOwnershipSpecs()
	end := 0
	for _, owner := range owners {
		if owner.SharedPriorityEnd > end {
			end = owner.SharedPriorityEnd
		}
	}
	if len(transit) != len(owners) {
		t.Fatal("transit reservation inventory omitted an adapter")
	}
	for i, slot := range transit {
		if slot.Engine != owners[i].Adapter || slot.Interface != owners[i].Interface || slot.Table != owners[i].Table || slot.Priority != end+i+1 || slot.Table == 219 || slot.Priority == 18050 {
			t.Fatal("transit allocator reused canary/foreign coordinates", slot)
		}
		for _, owner := range owners {
			if slot.Priority >= owner.SharedPriorityBase && slot.Priority <= owner.SharedPriorityEnd || slot.Priority >= owner.PriorityBase && slot.Priority <= owner.PriorityEnd || slot.Priority == owner.EndpointPriority {
				t.Fatal("transit allocator overlaps existing ownership", slot, owner)
			}
		}
	}
	transit[0].Priority = 1
	if NodeTransitOwnershipSpecs()[0].Priority != end+1 {
		t.Fatal("caller mutated the central inventory")
	}
}

func TestNodeTransitCompilerBindsFullFrozenSpecAndOnlyExactRule(t *testing.T) {
	spec := nodeTransitFixtureSpec()
	plan, err := CompileNodeTransit(spec)
	if err != nil || len(plan.Effects) != 1 || plan.Generation != mustNodeTransitDigest(t, spec) {
		t.Fatal(plan, err)
	}
	add := []string{"-4", "rule", "add", "priority", strconv.Itoa(spec.Priority), "from", "172.31.22.1/32", "to", "1.1.1.1/32", "oif", "rz-xray", "lookup", "204"}
	remove := append([]string(nil), add...)
	remove[2] = "del"
	if !reflect.DeepEqual(plan.Effects[0], PolicyEffect{Tool: PolicyEffectIP, Add: add, Delete: remove}) {
		t.Fatal("compiler widened exact source/oif/destination tuple", plan)
	}
	for _, mutate := range []func(*NodeTransitSpec){
		func(s *NodeTransitSpec) { s.BootID = "00000000-0000-0000-0000-000000000002" },
		func(s *NodeTransitSpec) { s.PlanID = "dp-fedcba9876543210" },
		func(s *NodeTransitSpec) { s.PlanDigest = strings.Repeat("d", 64) },
		func(s *NodeTransitSpec) { s.NetworkProfile = "wan-ffffffffffff" },
		func(s *NodeTransitSpec) { s.RuntimeID = strings.Repeat("e", 64) },
		func(s *NodeTransitSpec) { s.PolicyGeneration = strings.Repeat("f", 32) },
		func(s *NodeTransitSpec) { s.IfIndex++ },
		func(s *NodeTransitSpec) { s.Source = netip.MustParseAddr("172.31.22.2") },
		func(s *NodeTransitSpec) { s.Destination = netip.MustParseAddr("1.0.0.1") },
	} {
		changed := spec
		mutate(&changed)
		other, err := CompileNodeTransit(changed)
		if err != nil || other.Generation == plan.Generation {
			t.Fatal("generation did not bind full immutable spec", changed, err)
		}
	}
	plan.Effects[0].Add[4] = "1"
	fresh, err := CompileNodeTransit(spec)
	if err != nil || !reflect.DeepEqual(fresh.Effects[0].Add, add) {
		t.Fatal("compiler returned shared mutable commands", err)
	}
}

func TestNodeTransitCompilerRefusesInvalidIdentityAndOwnership(t *testing.T) {
	for _, kind := range []string{"schema", "engine", "boot", "plan-id", "plan-digest", "network", "runtime", "generation", "interface", "ifindex", "source6", "source-mapped", "source-loopback", "destination6", "destination-mapped", "destination-private", "table", "priority"} {
		t.Run(kind, func(t *testing.T) {
			spec := nodeTransitFixtureSpec()
			switch kind {
			case "schema":
				spec.Schema++
			case "engine":
				spec.Engine = "xray:node"
			case "boot":
				spec.BootID = "unknown"
			case "plan-id":
				spec.PlanID = "current"
			case "plan-digest":
				spec.PlanDigest = strings.Repeat("A", 64)
			case "network":
				spec.NetworkProfile = "network-unknown"
			case "runtime":
				spec.RuntimeID = strings.Repeat("b", 63)
			case "generation":
				spec.PolicyGeneration = strings.Repeat("c", 64)
			case "interface":
				spec.Interface = "eth0"
			case "ifindex":
				spec.IfIndex = 0
			case "source6":
				spec.Source = netip.MustParseAddr("fd00::1")
			case "source-mapped":
				spec.Source = netip.MustParseAddr("::ffff:172.31.22.1")
			case "source-loopback":
				spec.Source = netip.MustParseAddr("127.0.0.1")
			case "destination6":
				spec.Destination = netip.MustParseAddr("2606:4700::1111")
			case "destination-mapped":
				spec.Destination = netip.MustParseAddr("::ffff:1.1.1.1")
			case "destination-private":
				spec.Destination = netip.MustParseAddr("192.168.1.1")
			case "table":
				spec.Table = 219
			case "priority":
				spec.Priority = 18050
			}
			if plan, err := CompileNodeTransit(spec); !errors.Is(err, ErrNodeTransitUnavailable) || len(plan.Effects) != 0 {
				t.Fatal("invalid resource identity compiled", plan, err)
			}
		})
	}
}

func TestNodeTransitOIFGrammarUsesFullTupleAndNumericTables(t *testing.T) {
	spec := nodeTransitFixtureSpec()
	line := (&nodeTransitTestRunner{spec: spec}).line()
	if !nodeTransitRuleMatches(spec, 4, line) || !nodeTransitRuleMatches(spec, 4, strings.Replace(line, spec.Source.String(), spec.Source.String()+"/32", 1)) {
		t.Fatal("exact numeric host source/oif tuple refused")
	}
	for _, changed := range []string{
		strings.Replace(line, "lookup 204", "lookup main", 1), strings.Replace(line, "lookup 204", "lookup 0204", 1),
		strings.Replace(line, "from 172.31.22.1", "from all", 1), strings.Replace(line, "from 172.31.22.1", "from 172.31.22.0/30", 1),
		strings.Replace(line, "to 1.1.1.1", "to 1.0.0.1", 1), strings.Replace(line, "oif rz-xray", "iif rz-xray", 1),
		strings.Replace(line, "oif rz-xray", "oif eth0", 1), line + " proto 3", line + " not", "0" + line,
	} {
		if nodeTransitRuleMatches(spec, 4, changed) || nodeTransitRuleMatches(spec, 6, changed) {
			t.Fatal("foreign/unknown grammar became the typed lease", changed)
		}
	}
}

func TestNodeTransitRouteRequiresACKExactSourceOIFAndNumericTable(t *testing.T) {
	for _, kind := range []string{"exact", "missing-ACK", "foreign-device", "table-alias", "foreign-source", "gateway", "duplicate-device", "unknown", "missing-table"} {
		t.Run(kind, func(t *testing.T) {
			l, runner, _ := nodeTransitFixture(t)
			if kind != "missing-ACK" {
				if err := l.Apply(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "foreign-device":
				runner.route = strings.Replace(runner.route, "dev rz-xray", "dev eth0", 1)
			case "table-alias":
				runner.route = strings.Replace(runner.route, "table 204", "table main", 1)
			case "foreign-source":
				runner.route = strings.Replace(runner.route, "from 172.31.22.1", "from 172.31.22.2", 1)
			case "gateway":
				runner.route += " via 192.0.2.1"
			case "duplicate-device":
				runner.route += " dev rz-xray"
			case "unknown":
				runner.route += " nexthop dev eth0"
			case "missing-table":
				runner.route = strings.Replace(runner.route, " table 204", "", 1)
			}
			if err := l.VerifyRoute(context.Background()); (err == nil) != (kind == "exact") {
				t.Fatal("unowned FIB route acquired transit proof", kind, err)
			}
		})
	}
}

func TestNodeTransitRuntimeRequiresEveryTrustedCallbackAndCancellation(t *testing.T) {
	l, runner, authority := nodeTransitFixture(t)
	for _, kind := range []string{"runner", "ip", "preflight", "guard", "before-delete", "register"} {
		runtime := l.runtime
		switch kind {
		case "runner":
			runtime.runner = nil
		case "ip":
			runtime.ip = ""
		case "preflight":
			runtime.preflight = nil
		case "guard":
			runtime.guard = nil
		case "before-delete":
			runtime.beforeDelete = nil
		case "register":
			runtime.register = nil
		}
		if _, err := newNodeTransitLeaseWithOptions(l.spec, l.root, runtime, l.options); err == nil {
			t.Fatal("missing local authority was admitted", kind)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Apply(ctx); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 || authority.registrations != 0 {
		t.Fatal("canceled operation began registration/effects", err)
	}
	authority.guardErr = ErrReviewChanged
	if err := l.Apply(context.WithoutCancel(ctx)); !errors.Is(err, ErrReviewChanged) || len(runner.calls) != 0 || authority.registrations != 0 {
		t.Fatal("detached context renewed revoked review", err)
	}
}

func TestNodeTransitCanceledNumericReadCannotBeginEffect(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(strconv.Itoa(family), func(t *testing.T) {
			l, runner, _ := nodeTransitFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner.beforeRead = func(readCtx context.Context, gotFamily int) error {
				if gotFamily == family {
					cancel()
					return readCtx.Err()
				}
				return nil
			}
			if err := l.Apply(ctx); !errors.Is(err, context.Canceled) || runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("canceled numeric read lost cancellation or began an effect", err, runner)
			}
		})
	}
}
