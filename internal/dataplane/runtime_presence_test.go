package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestRuntimePresenceNeverAcceptsJournalWithDeadOwnedProxy(t *testing.T) {
	m, plan := committedNodeHealthFixture(t)
	a, err := NewProxyTunnelAdapter("sing-box", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	processes := &proxyFakeProcesses{running: map[string]bool{}}
	a.Processes = processes
	state := PolicyState{Interface: a.Interface, Table: a.Table, PriorityBase: a.Priority, Prefixes: []string{"8.8.8.8/32"}}
	data, _ := json.Marshal(state)
	for _, file := range []string{a.policyPath(), a.engineConfigPath(), a.sidecarConfigPath()} {
		_ = os.MkdirAll(filepath.Dir(file), 0700)
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	before, _, _ := m.Committed()
	if err := m.ObserveCommittedRuntime(context.Background(), plan); err == nil {
		t.Fatal("dead owned process displayed running")
	}
	after, _, _ := m.Committed()
	if len(processes.startSpecs) != 0 || len(processes.running) != 0 || !reflect.DeepEqual(before, after) {
		t.Fatal("observation repaired or rewrote state")
	}
}

func TestCommittedNodeHealthMixedPlanChecksOnlyOwnedNodeAdapter(t *testing.T) {
	m, plan := committedNodeHealthFixture(t)
	plan.Adapters = []string{"nfqws2", "sing-box"}
	plan.Routes = append(plan.Routes, Route{ServiceID: "youtube", Selected: "nfqws2", Resolved: "nfqws2"})
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	node, other := &fakeAdapter{id: "sing-box"}, &fakeAdapter{id: "nfqws2", failAt: "health"}
	_ = m.Register(node)
	_ = m.Register(other)
	if err := m.CheckCommittedNodeHealth(context.Background(), plan); err != nil {
		t.Fatal("valid mixed plan rejected", err)
	}
	if !reflect.DeepEqual(node.calls, []string{"health"}) || len(other.calls) != 0 {
		t.Fatal("node health claimed or modified another adapter")
	}
	node.failAt = "health"
	if err := m.CheckCommittedNodeHealth(context.Background(), plan); err == nil || errors.Is(err, ErrReviewChanged) {
		t.Fatal("owned node health failure not checked", err)
	}
}
