package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func lanPolicySuspensionFixture(t *testing.T, prior *LANPolicyRuntimePlan) *LANPolicySuspensionPlan {
	t.Helper()
	p, err := FreezeLANPolicySuspensionPlan(strings.Repeat("b", 64), prior, prior,
		[]LANPolicyCaptureClass{
			{Owner: "dns", Generation: prior.Generation, Family: 4, SegmentID: "home", Interface: "br0", Hook: "nat-prerouting", Sources: []string{"192.168.1.0/24"}, Protocol: "udp", DestinationMode: "all", DestinationPorts: []uint16{53}},
			{Owner: "proxy", Generation: prior.Generation, Family: 6, SegmentID: "home", Interface: "br0", Hook: "mangle-prerouting", Sources: []string{"fd00:1::/64"}, Protocol: "tcp", DestinationMode: "prefix", Destinations: []string{"2001:4860::/32"}, DestinationPorts: []uint16{443}},
		}, []LANPolicyProtectedFlow{{Generation: prior.Generation, FlowID: "baseline-flow", GrantDigest: strings.Repeat("c", 64), SegmentID: "home", Interface: "br0", MAC: "02:00:00:00:00:02", Source: netip.MustParseAddrPort("192.168.1.42:23456"), Destination: netip.MustParseAddrPort("8.8.8.8:53"), Protocol: "udp"}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type lanPolicySuspensionModel struct {
	prior   *lanPolicyReceiptModel
	plan    *LANPolicySuspensionPlan
	effects []PolicyEffect
	present map[int]int
	calls   []int
	lostAdd int
	foreign bool
	late    bool
}

func (m *lanPolicySuspensionModel) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	for i, e := range m.effects {
		if string(e.Tool) != tool {
			continue
		}
		add, remove := slices.Equal(args, e.Add), slices.Equal(args, e.Delete)
		if !add && !remove {
			continue
		}
		m.calls = append(m.calls, i)
		if add {
			m.present[i]++
			if i == m.lostAdd {
				return nil, errors.New("lost suspension ACK")
			}
		} else {
			m.present[i]--
		}
		return nil, nil
	}
	old, err := m.prior.Run(ctx, tool, args...)
	if err != nil || tool == "ip" || len(args) != 3 || args[1] != "mangle" {
		return old, err
	}
	var head, body []string
	for i, e := range m.effects {
		if string(e.Tool) != tool {
			continue
		}
		line := e.Add[2:]
		for n := 0; n < m.present[i]; n++ {
			if line[0] == "-I" {
				head = append([]string{strings.Join(append([]string{"-A", line[1]}, line[3:]...), " ")}, head...)
			} else {
				body = append(body, strings.Join(line, " "))
			}
		}
	}
	if m.foreign {
		for _, c := range lanPolicySuspensionChains(m.plan) {
			if c.family == 4 && tool == "iptables" {
				body = append(body, "-A OUTPUT -j "+c.name)
				break
			}
		}
	}
	if m.late {
		head = append([]string{"-A PREROUTING -j FOREIGN"}, head...)
	}
	return []byte(strings.Join(body, "\n") + "\n" + strings.Join(head, "\n") + "\n" + string(old)), nil
}

func lanSuspensionBindingFixture(t *testing.T) (*LANPolicySuspensionBinding, *lanPolicySuspensionModel, string, string, *LANPolicyReceiptBinding) {
	t.Helper()
	gate, old, priorRoot := lanReceiptBindingFixture(t)
	if err := gate.Apply(context.Background(), old.plan, priorRoot); err != nil {
		t.Fatal(err)
	}
	plan := lanPolicySuspensionFixture(t, old.plan)
	mixed, err := plan.Effects()
	if err != nil {
		t.Fatal(err)
	}
	model := &lanPolicySuspensionModel{prior: old, plan: plan, effects: mixed.Effects, present: map[int]int{}, lostAdd: -1}
	runtime := *gate.Runtime
	runtime.Runner = model
	guard := func(_ context.Context, got *LANPolicySuspensionPlan, _ PolicyEffect) error {
		if !reflect.DeepEqual(got, plan) {
			return ErrReviewChanged
		}
		return nil
	}
	proof := func(context.Context, *LANPolicySuspensionPlan) error { return nil }
	b := &LANPolicySuspensionBinding{Runtime: &runtime, FenceGuard: guard, CleanupGuard: guard, CaptureCheck: proof, ReleaseCheck: proof, options: gate.options}
	return b, model, priorRoot, privateScopedXrayFixtureDir(t), gate
}

func TestLANPolicySuspensionFrozenBoundaryAndHooks(t *testing.T) {
	prior := lanRuntimeFixture(t)
	p := lanPolicySuspensionFixture(t, prior)
	copy := CloneLANPolicySuspensionPlan(p)
	copy.Captures[0].Sources[0] = "changed"
	if ValidateLANPolicySuspensionPlan(copy) == nil || ValidateLANPolicySuspensionPlan(p) != nil {
		t.Fatal("mutable frozen capture")
	}
	current, err := CompileLANPolicyRuntime(strings.Repeat("d", 64), []LANPolicyIngress{{SegmentID: "home", Interface: "br0", Sources: []string{"192.168.1.0/24", "fd00:1::/64"}, ExcludedSources: []string{"192.168.1.40/32"}, ExcludedMACs: []string{"02:00:00:00:00:03"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FreezeLANPolicySuspensionPlan(p.Generation, prior, current, p.Captures, p.Baseline); !errors.Is(err, ErrLANPolicyTransitionRequired) {
		t.Fatal("raw RETURN could re-admit changed exclusion", err)
	}
	for _, mutate := range []func(*LANPolicySuspensionPlan){
		func(p *LANPolicySuspensionPlan) { p.Captures[0].Hook = "raw-prerouting" },
		func(p *LANPolicySuspensionPlan) { p.Captures[0].Interface = "wan0" },
		func(p *LANPolicySuspensionPlan) { p.Captures[0].Sources = []string{"192.168.2.0/24"} },
		func(p *LANPolicySuspensionPlan) { p.Captures[0].DestinationMode = "" },
		func(p *LANPolicySuspensionPlan) { p.Baseline[0].FlowID = "" },
	} {
		bad := CloneLANPolicySuspensionPlan(p)
		mutate(bad)
		if _, err := FreezeLANPolicySuspensionPlan(bad.Generation, bad.PriorLAN, bad.CurrentLAN, bad.Captures, bad.Baseline); err == nil {
			t.Fatal("unproved descriptor accepted", bad)
		}
	}
	plan, err := p.Effects()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range plan.Effects {
		text := strings.Join(e.Add, " ")
		if strings.Contains(text, "MARK") || strings.Contains(text, "OUTPUT") || strings.Contains(text, "ACCEPT") {
			t.Fatal("fence broadened baseline/mark ownership", text)
		}
		if e.Add[2] == "-I" {
			if len(e.Needs) != len(p.Captures) {
				t.Fatal("publication lacks both-family body prerequisites", e)
			}
		}
	}
}

func TestLANPolicySuspensionActualReceiptFenceRetainAndRelease(t *testing.T) {
	b, m, priorRoot, root, gate := lanSuspensionBindingFixture(t)
	priorCalls, priorPresent := len(m.prior.calls), map[int]int{}
	for i, n := range m.prior.present {
		priorPresent[i] = n
	}
	if err := b.Fence(context.Background(), m.plan, priorRoot, root); err != nil {
		t.Fatal(err)
	}
	status, err := b.Inspect(context.Background(), m.plan, root)
	if err != nil || !status.Complete {
		t.Fatal(status, err)
	}
	if len(m.prior.calls) != priorCalls || !reflect.DeepEqual(m.prior.present, priorPresent) {
		t.Fatal("fence rewrote retained/unknown consumer grants")
	}
	b.ReleaseCheck = func(context.Context, *LANPolicySuspensionPlan) error { return ErrPolicyAdditionUnknown }
	before := len(m.calls)
	if err := b.Remove(context.Background(), m.plan, priorRoot, root); !errors.Is(err, ErrPolicyAdditionUnknown) || len(m.calls) != before {
		t.Fatal("unknown flow removed barrier", err)
	}
	b.ReleaseCheck = func(context.Context, *LANPolicySuspensionPlan) error { return nil }
	b.FenceGuard = func(context.Context, *LANPolicySuspensionPlan, PolicyEffect) error { return ErrReviewChanged }
	if err := b.Remove(context.Background(), m.plan, priorRoot, root); err != nil {
		t.Fatal("cleanup required expired Apply", err)
	}
	if !reflect.DeepEqual(m.prior.present, priorPresent) {
		t.Fatal("suspension cleanup stripped prior LAN boundary")
	}
	if err := gate.Remove(context.Background(), m.prior.plan, priorRoot); err != nil {
		t.Fatal(err)
	}
}

func TestLANPolicySuspensionLostACKForeignAndCoverageRetain(t *testing.T) {
	for _, failure := range []string{"lost ACK", "foreign reference", "late barrier", "unproved raw coverage", "missing negative"} {
		t.Run(failure, func(t *testing.T) {
			b, m, priorRoot, root, _ := lanSuspensionBindingFixture(t)
			if failure == "lost ACK" {
				m.lostAdd = len(m.effects) - 1
			}
			if failure == "unproved raw coverage" {
				b.CaptureCheck = func(context.Context, *LANPolicySuspensionPlan) error { return ErrLANPolicyRuntime }
			}
			if failure == "missing negative" {
				for i, e := range m.prior.effects {
					if strings.Contains(strings.Join(e.Add, " "), "--mac-source") {
						m.prior.present[i] = 0
						break
					}
				}
			}
			err := b.Fence(context.Background(), m.plan, priorRoot, root)
			if failure == "lost ACK" || failure == "unproved raw coverage" || failure == "missing negative" {
				if err == nil {
					t.Fatal("unsafe fence accepted")
				}
				before := len(m.calls)
				if remove := b.Remove(context.Background(), m.plan, priorRoot, root); remove == nil || len(m.calls) != before {
					t.Fatal("unknown fence got cleanup authority", remove)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			m.foreign = failure == "foreign reference"
			m.late = failure == "late barrier"
			before := len(m.calls)
			if err := b.Remove(context.Background(), m.plan, priorRoot, root); err == nil || len(m.calls) != before {
				t.Fatal("foreign/late barrier adopted", err)
			}
		})
	}
}

func TestLANPolicySuspensionPromotionAndDetachedGuards(t *testing.T) {
	b, m, priorRoot, root, _ := lanSuspensionBindingFixture(t)
	b.FenceGuard = func(_ context.Context, p *LANPolicySuspensionPlan, e PolicyEffect) error {
		p.Captures[0].Sources[0] = "changed"
		e.Add[0] = "changed"
		return nil
	}
	if err := b.Fence(context.Background(), m.plan, priorRoot, root); err != nil {
		t.Fatal(err)
	}
	dest := privateScopedXrayFixtureDir(t)
	if err := b.Promote(context.Background(), m.plan, priorRoot, root, dest); err != nil {
		t.Fatal(err)
	}
	before := len(m.calls)
	if err := b.Remove(context.Background(), m.plan, priorRoot, root); !errors.Is(err, ErrPolicyAdditionUnknown) || len(m.calls) != before {
		t.Fatal("source kept deletion grant", err)
	}
	if err := b.Remove(context.Background(), m.plan, priorRoot, dest); err != nil {
		t.Fatal(err)
	}
	if ValidateLANPolicySuspensionPlan(m.plan) != nil {
		t.Fatal("callback edited trusted plan")
	}
}
