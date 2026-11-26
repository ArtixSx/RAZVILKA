package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

type runtimePresenceDelayedRunner struct {
	NFQWS2Runner
	delay time.Duration
	done  bool
}

func (r *runtimePresenceDelayedRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !r.done {
		r.done = true
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			// OS command wrappers may replace the context error with exit status.
			return nil, errors.New("command killed")
		case <-timer.C:
		}
	}
	return r.NFQWS2Runner.Run(ctx, name, args...)
}

func TestRuntimePresenceScopedProxyAllowsCompleteReadOnlyInspection(t *testing.T) {
	f := newForwardingRepairFixture(t)
	f.a.Runner = &runtimePresenceDelayedRunner{NFQWS2Runner: f.a.Runner, delay: 2100 * time.Millisecond}
	if err := f.m.ObserveCommittedRuntime(context.Background(), f.plan); err != nil {
		t.Fatalf("working scoped runtime lost its presence proof at the old two-second limit: %v", err)
	}
	f.unchangedPrivateRuntime(t)
	requireOnlyFirewallReads(t, f.firewall)
}

func TestRuntimePresencePreservesCallerDeadlineAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "canceled"}[canceled], func(t *testing.T) {
			f := newForwardingRepairFixture(t)
			f.a.Runner = &runtimePresenceDelayedRunner{NFQWS2Runner: f.a.Runner, delay: time.Second}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			want := context.DeadlineExceeded
			if canceled {
				timer := time.AfterFunc(10*time.Millisecond, cancel)
				defer timer.Stop()
				want = context.Canceled
			}
			if err := f.m.ObserveCommittedRuntime(ctx, f.plan); !errors.Is(err, want) {
				t.Fatalf("command wrapper hid caller termination: got %v, want %v", err, want)
			}
			f.unchangedPrivateRuntime(t)
			requireOnlyFirewallReads(t, f.firewall)
		})
	}
}

func TestRuntimePresenceStillRequiresEveryOwnedScopedRule(t *testing.T) {
	f := newForwardingRepairFixture(t)
	eraseForwardingTable(f.firewall, "iptables", "filter", f.state.Forwarding.Chain)
	if err := f.m.ObserveCommittedRuntime(context.Background(), f.plan); err == nil {
		t.Fatal("running processes and a journal hid missing scoped firewall rules")
	}
	f.unchangedPrivateRuntime(t)
	requireOnlyFirewallReads(t, f.firewall)
}

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
