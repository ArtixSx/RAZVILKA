package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type cleanupRouteRunner struct {
	default4, default6    string
	foreign               string
	mutations             []string
	keepDefault, failRead bool
}

func (r *cleanupRouteRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	v6 := strings.HasPrefix(command, "-6 ")
	command = strings.TrimPrefix(command, "-6 ")
	if command == "route show table 203" {
		if r.failRead {
			return nil, errors.New("read failed")
		}
		line := r.default4
		if v6 {
			line = r.default6
		}
		return []byte(line + "\n" + r.foreign + "\n"), nil
	}
	if command == "rule show" {
		return []byte("0: from all lookup local\n32766: from all lookup main\n"), nil
	}
	r.mutations = append(r.mutations, strings.Join(args, " "))
	if strings.HasPrefix(command, "route del default dev rz-sing table 203") && !r.keepDefault {
		if v6 {
			r.default6 = ""
		} else {
			r.default4 = ""
		}
	}
	if strings.Contains(command, "flush") {
		r.foreign = ""
	}
	return nil, nil
}

func TestPolicyCleanupPreservesEndpointAndForeignRoutes(t *testing.T) {
	runner := &cleanupRouteRunner{default4: "default dev rz-sing scope link", default6: "default dev rz-sing metric 1024 pref medium", foreign: "203.0.113.7 via 192.168.1.1 dev eth0"}
	state := PolicyState{Interface: "rz-sing", Table: 203}
	if err := removeKernelPolicy(context.Background(), runner, "ip", state, nil); err != nil {
		t.Fatal(err)
	}
	if runner.default4 != "" || runner.default6 != "" || runner.foreign == "" {
		t.Fatalf("cleanup state: %+v", runner)
	}
	if len(runner.mutations) != 2 {
		t.Fatalf("unexpected mutations: %v", runner.mutations)
	}
	for _, command := range runner.mutations {
		if strings.Contains(command, "flush") {
			t.Fatal("whole table flushed")
		}
	}
}

func TestPolicyCleanupRejectsAmbiguousDefaultBeforeDeletingSelectors(t *testing.T) {
	for _, line := range []string{"default via 192.168.1.1 dev rz-sing", "default dev rz-sing metric 12", "default dev rz-sing proto static", "default dev rz-sing\ndefault dev rz-sing", "default dev rz-sing onlink"} {
		t.Run(line, func(t *testing.T) {
			runner := &cleanupRouteRunner{default4: line}
			if err := removeKernelPolicy(context.Background(), runner, "ip", PolicyState{Interface: "rz-sing", Table: 203}, []kernelPolicyRule{{family: 4, priority: 65, table: 203, source: "all", destination: "203.0.113.7/32"}}); err == nil {
				t.Fatal("foreign default accepted")
			}
			if len(runner.mutations) != 0 {
				t.Fatalf("mutated before ownership proof: %v", runner.mutations)
			}
		})
	}
}

func TestPolicyCleanupRequiresRouteRemovalReadback(t *testing.T) {
	runner := &cleanupRouteRunner{default4: "default dev rz-sing", keepDefault: true}
	if err := removeKernelPolicy(context.Background(), runner, "ip", PolicyState{Interface: "rz-sing", Table: 203}, nil); err == nil {
		t.Fatal("reported clean despite remaining route")
	}
	runner = &cleanupRouteRunner{failRead: true}
	if err := removeKernelPolicy(context.Background(), runner, "ip", PolicyState{Interface: "rz-sing", Table: 203}, nil); err == nil || len(runner.mutations) != 0 {
		t.Fatal("unreadable table mutated")
	}
}

func TestPolicyApplyRefusesExistingDefaultsBeforeAnyMutation(t *testing.T) {
	for _, route := range []string{"default via 192.0.2.1 dev foreign", "default dev rz-sing proto boot metric 0", "default dev rz-sing proto static", "blackhole default", "default dev foreign\ndefault dev rz-sing", "unexpected diagnostic"} {
		for _, family := range []string{"4/203", "6/203"} {
			t.Run(family+"/"+route, func(t *testing.T) {
				r := &recordedPolicyFakeRunner{kernel: policyKernelFake{defaults: map[string]string{family: route}}}
				if err := applyRecordedPolicy(context.Background(), r, "ip", testEarlyPolicy()); err == nil {
					t.Fatal("existing default accepted")
				}
				for _, call := range r.calls {
					if strings.Contains(call, " add ") || strings.Contains(call, " del ") || strings.Contains(call, " replace ") {
						t.Fatalf("mutated occupied table: %s", call)
					}
				}
				if r.kernel.defaults[family] != route {
					t.Fatal("foreign default changed")
				}
				if !strings.Contains(strings.Join(r.calls, "\n"), "ip route show table 203") || !strings.Contains(strings.Join(r.calls, "\n"), "ip -6 route show table 203") {
					t.Fatal("both families were not inspected")
				}
			})
		}
	}
}

func TestPolicyApplyReadAndIPv6AddFailuresRemainHonest(t *testing.T) {
	r := &recordedPolicyFakeRunner{failRead: 6}
	if err := applyRecordedPolicy(context.Background(), r, "ip", testEarlyPolicy()); err == nil {
		t.Fatal("unreadable IPv6 reported successful")
	}
	for _, call := range r.calls {
		if strings.Contains(call, " add ") || strings.Contains(call, " del ") {
			t.Fatal("read failure changed tables", call)
		}
	}
	r = &recordedPolicyFakeRunner{failAdd: 6}
	if err := applyRecordedPolicy(context.Background(), r, "ip", testEarlyPolicy()); err == nil {
		t.Fatal("IPv6 add failure reported successful")
	}
	if len(r.kernel.defaults) != 0 || len(r.kernel.entries) != 0 {
		t.Fatalf("partial state leaked: %+v", r.kernel)
	}
	for _, call := range r.calls {
		if strings.Contains(call, "-6 route del") {
			t.Fatal("failed IPv6 add granted deletion authority", call)
		}
	}
}

func TestPolicyApplyConcurrentOccupantSurvivesFailedAdd(t *testing.T) {
	r := &recordedPolicyFakeRunner{}
	const foreign = "default dev rz-sing proto boot metric 1024\n"
	r.beforeAdd = func(family int) {
		if family == 6 {
			r.kernel.defaults["6/203"] = foreign
		}
	}
	if err := applyRecordedPolicy(context.Background(), r, "ip", testEarlyPolicy()); err == nil {
		t.Fatal("concurrent occupant accepted")
	}
	if r.kernel.defaults["6/203"] != foreign || r.kernel.defaults["4/203"] != "" || len(r.kernel.entries) != 0 {
		t.Fatalf("cleanup adopted foreign tuple: %+v", r.kernel)
	}
	for _, call := range r.calls {
		if strings.Contains(call, "-6 route del") || strings.Contains(call, "replace") {
			t.Fatal("foreign concurrent tuple was touched", call)
		}
	}
}

func TestPolicyApplySelectorFailureRemovesOnlySuccessfulAdditions(t *testing.T) {
	r := &recordedPolicyFakeRunner{failRule: 2}
	if err := applyRecordedPolicy(context.Background(), r, "ip", testEarlyPolicy()); err == nil {
		t.Fatal("selector failure reported successful")
	}
	if len(r.kernel.defaults) != 0 || len(r.kernel.entries) != 0 {
		t.Fatalf("partial created tuples leaked: %+v", r.kernel)
	}
	deletes := 0
	for _, call := range r.calls {
		if strings.Contains(call, "rule del ") {
			deletes++
		}
		if strings.Contains(call, "flush") || strings.Contains(call, "replace") {
			t.Fatal("broad mutation used", call)
		}
	}
	if deletes != 1 {
		t.Fatalf("cleanup deleted a selector whose add failed: %v", r.calls)
	}
}
