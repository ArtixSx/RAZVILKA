package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type lanPolicyReceiptModel struct {
	plan       *LANPolicyRuntimePlan
	effects    []LANPolicyEffect
	present    map[int]int
	calls      []int
	lostAdd    int
	foreignRef bool
}

func (m *lanPolicyReceiptModel) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	for i, e := range m.effects {
		if e.Tool != tool {
			continue
		}
		add, remove := reflect.DeepEqual(e.Add, args), reflect.DeepEqual(e.Delete, args)
		if !add && !remove {
			continue
		}
		m.calls = append(m.calls, i)
		if add {
			m.present[i]++
			if i == m.lostAdd {
				return nil, errors.New("lost model RPC acknowledgement")
			}
		} else {
			m.present[i]--
		}
		return nil, nil
	}
	if tool == "ip" {
		if len(args) != 4 || args[1] != "-N" || args[2] != "rule" || args[3] != "show" {
			return nil, errors.New("unexpected IP model command")
		}
		output := "0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n"
		for i, e := range m.effects {
			if e.Tool != tool || e.Add[0] != args[0] {
				continue
			}
			for _, rule := range lanPolicyRules(m.plan) {
				if reflect.DeepEqual(e.Add, rule.args("add")) {
					for n := 0; n < m.present[i]; n++ {
						output += rule.line() + "\n"
					}
				}
			}
		}
		return []byte(output), nil
	}
	if len(args) != 3 || args[0] != "-t" || args[2] != "-S" {
		return nil, errors.New("unexpected firewall model command")
	}
	if args[1] != "mangle" {
		return nil, nil
	}
	output := ""
	for i, e := range m.effects {
		if e.Tool != tool {
			continue
		}
		line := e.Add[2:]
		if line[0] == "-I" {
			line = append([]string{"-A", line[1]}, line[3:]...)
		}
		for n := 0; n < m.present[i]; n++ {
			output += strings.Join(line, " ") + "\n"
		}
	}
	if m.foreignRef {
		for _, chain := range lanPolicyChains(m.plan) {
			if chain.family == 4 && tool == "iptables" {
				output += "-A FOREIGN -j " + chain.name + "\n"
			}
		}
	}
	return []byte(output), nil
}

func lanReceiptBindingFixture(t *testing.T) (*LANPolicyReceiptBinding, *lanPolicyReceiptModel, string) {
	t.Helper()
	p := lanRuntimeFixture(t)
	effects, _ := p.Effects()
	m := &lanPolicyReceiptModel{plan: p, effects: effects, present: map[int]int{}, lostAdd: -1}
	r := &LANPolicyRuntime{Runner: m, IP: "ip", IPTables: "iptables", IP6Tables: "ip6tables", ScopeCheck: func(context.Context, *LANPolicyRuntimePlan) error { return nil }}
	guard := func(_ context.Context, got *LANPolicyRuntimePlan, _ LANPolicyEffect) error {
		if !reflect.DeepEqual(got, p) {
			return ErrReviewChanged
		}
		return nil
	}
	b := &LANPolicyReceiptBinding{Runtime: r, ApplyGuard: guard, CleanupGuard: guard, RetireCheck: func(context.Context, *LANPolicyRuntimePlan) error { return nil }, options: policyAdditionOptions{boot: func() (string, error) { return "lan-binding-model-boot", nil }}}
	return b, m, privateScopedXrayFixtureDir(t)
}

func TestLANPolicyReceiptBindingApplyPromoteAndStopCleanup(t *testing.T) {
	b, model, root := lanReceiptBindingFixture(t)
	if err := b.Apply(context.Background(), model.plan, root); err != nil {
		t.Fatal(err)
	}
	status, err := b.Inspect(context.Background(), model.plan, root)
	if err != nil || !status.Complete || status.Added != len(model.effects) {
		t.Fatal(status, err)
	}
	destination := privateScopedXrayFixtureDir(t)
	if err := b.Promote(context.Background(), model.plan, root, destination); err != nil {
		t.Fatal(err)
	}
	before := len(model.calls)
	if err := b.Remove(context.Background(), model.plan, root); !errors.Is(err, ErrPolicyAdditionUnknown) || len(model.calls) != before {
		t.Fatal("promoted source retained deletion authority", err)
	}
	// Stop/expired review must prevent a new Apply, while exact retained
	// cleanup uses the distinct cleanup admission and never live ScopeCheck.
	b.Runtime.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error { return ErrReviewChanged }
	b.ApplyGuard = func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error { return ErrReviewChanged }
	if err := b.Remove(context.Background(), model.plan, destination); err != nil {
		t.Fatal("cleanup borrowed expired Apply authority", err)
	}
	status, err = b.Inspect(context.Background(), model.plan, destination)
	if err != nil || !status.Removed || status.Unknown {
		t.Fatal(status, err)
	}
	for i, count := range model.present {
		if count != 0 {
			t.Fatal("effect remained after known cleanup", i, count)
		}
	}
	if err := b.Apply(context.Background(), model.plan, privateScopedXrayFixtureDir(t)); !errors.Is(err, ErrReviewChanged) {
		t.Fatal("Stop admitted new effects", err)
	}
}

func TestLANPolicyReceiptBindingUnknownConsumerAndLostACKRetainGate(t *testing.T) {
	for _, lostACK := range []bool{false, true} {
		t.Run(map[bool]string{false: "consumer", true: "lost-ack"}[lostACK], func(t *testing.T) {
			b, model, root := lanReceiptBindingFixture(t)
			if lostACK {
				model.lostAdd = len(model.effects) - 1 // unknown published attachment
			}
			err := b.Apply(context.Background(), model.plan, root)
			if lostACK && err == nil || !lostACK && err != nil {
				t.Fatal(err)
			}
			before := len(model.calls)
			if !lostACK {
				b.RetireCheck = func(context.Context, *LANPolicyRuntimePlan) error { return ErrPolicyAdditionUnknown }
			}
			if err := b.Remove(context.Background(), model.plan, root); err == nil || len(model.calls) != before {
				t.Fatal("unknown consumer/attachment removed prerequisites", err, model.calls)
			}
			for i, e := range model.effects {
				if strings.Contains(strings.Join(e.Add, " "), "--set-xmark 0x8000000/0x28000000") && model.present[i] != 1 {
					t.Fatal("negative guard lost", i)
				}
			}
		})
	}
}

func TestLANPolicyReceiptBindingForeignRefusalAndDetachedEffects(t *testing.T) {
	b, model, root := lanReceiptBindingFixture(t)
	mixed, err := LANPolicyEffectsPlan(model.plan)
	if err != nil {
		t.Fatal(err)
	}
	mixed.Effects[0].Add[0] = "changed"
	if model.effects[0].Add[0] == "changed" || ValidateLANPolicyRuntime(model.plan) != nil {
		t.Fatal("binding exposed mutable expected plan")
	}
	b.ApplyGuard = func(_ context.Context, copy *LANPolicyRuntimePlan, effect LANPolicyEffect) error {
		copy.Ingress[0].Sources[0] = "edited"
		effect.Add[0] = "edited"
		return nil
	}
	if err := b.Apply(context.Background(), model.plan, root); err != nil {
		t.Fatal(err)
	}
	model.foreignRef = true
	before := len(model.calls)
	if err := b.Remove(context.Background(), model.plan, root); err == nil || len(model.calls) != before {
		t.Fatal("foreign reference adopted by exact inspector", err)
	}
}
