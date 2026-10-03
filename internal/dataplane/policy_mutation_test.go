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
