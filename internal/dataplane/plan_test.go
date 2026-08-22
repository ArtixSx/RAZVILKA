package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildDirectPlanIsReadyNoop(t *testing.T) {
	plan, err := BuildAt(Input{Revision: 3, SafeMode: true, Routes: []Route{{ServiceID: "example", ServiceName: "Example", Selected: "direct", Resolved: "direct"}}}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || !plan.Noop || len(plan.Blockers) != 0 {
		t.Fatalf("unexpected direct plan: %+v", plan)
	}
}

func TestBuildBlocksEngineDraftWithoutMatchingServiceRoute(t *testing.T) {
	plan, err := BuildAt(Input{
		Revision:           7,
		Routes:             []Route{{ServiceID: "youtube", ServiceName: "YouTube", Resolved: "direct"}},
		EngineConfigDrafts: []string{"warp-wg/main"},
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ready || plan.Noop || len(plan.Blockers) != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if got := plan.Blockers[0]; got.Code != "ENGINE_DRAFT_UNUSED" || got.Adapter != "warp-wg" {
		t.Fatalf("unexpected blocker: %+v", got)
	}
	if len(plan.EngineDrafts) != 1 || plan.EngineDrafts[0] != "warp-wg/main" {
		t.Fatalf("engine drafts not exposed: %+v", plan.EngineDrafts)
	}
}

type fakeAdapter struct {
	id          string
	calls       []string
	failAt      string
	rollback    bool
	recovered   bool
	refreshed   bool
	deactivated bool
}

type blockingAdapter struct {
	started chan struct{}
	release chan struct{}
}

func (a *blockingAdapter) ID() string { return "nfqws2" }
func (a *blockingAdapter) Snapshot(context.Context, Plan, string) error {
	close(a.started)
	<-a.release
	return nil
}
func (a *blockingAdapter) Stage(context.Context, Plan, string) error    { return nil }
func (a *blockingAdapter) Validate(context.Context, Plan, string) error { return nil }
func (a *blockingAdapter) Activate(context.Context, Plan, string) error { return nil }
func (a *blockingAdapter) Health(context.Context, Plan, string) error   { return nil }
func (a *blockingAdapter) Commit(context.Context, Plan, string) error   { return nil }
func (a *blockingAdapter) Rollback(context.Context, Plan, string) error { return nil }

func (a *fakeAdapter) ID() string { return a.id }
func (a *fakeAdapter) call(phase string) error {
	a.calls = append(a.calls, phase)
	if a.failAt == phase {
		return errors.New("forced " + phase + " failure")
	}
	if phase == "rollback" {
		a.rollback = true
	}
	return nil
}
func (a *fakeAdapter) Snapshot(context.Context, Plan, string) error { return a.call("snapshot") }
func (a *fakeAdapter) Stage(context.Context, Plan, string) error    { return a.call("stage") }
func (a *fakeAdapter) Validate(context.Context, Plan, string) error { return a.call("validate") }
func (a *fakeAdapter) Activate(context.Context, Plan, string) error { return a.call("activate") }
func (a *fakeAdapter) Health(context.Context, Plan, string) error   { return a.call("health") }
func (a *fakeAdapter) Commit(context.Context, Plan, string) error   { return a.call("commit-adapter") }
func (a *fakeAdapter) Rollback(context.Context, Plan, string) error { return a.call("rollback") }
func (a *fakeAdapter) Reconcile(context.Context, Plan) error {
	a.recovered = true
	return a.call("reconcile")
}
func (a *fakeAdapter) RefreshPolicy(context.Context, Plan) (bool, error) {
	a.refreshed = true
	return true, nil
}
func (a *fakeAdapter) Deactivate(context.Context) error {
	a.deactivated = true
	return a.call("deactivate")
}

func TestManagerApplyCommitsOnlyAfterHealth(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &fakeAdapter{id: "nfqws2"}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0).UTC())
	if err != nil || !plan.Ready {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	committed := false
	execution, err := manager.Apply(context.Background(), plan, func() (func() error, error) {
		committed = true
		return func() error { committed = false; return nil }, nil
	})
	if err != nil || !committed || execution.State != "committed" {
		t.Fatalf("execution=%+v committed=%v err=%v", execution, committed, err)
	}
	want := []string{"snapshot", "stage", "validate", "activate", "health", "commit-adapter"}
	if strings.Join(adapter.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls=%v want=%v", adapter.calls, want)
	}
}

func TestRuntimeStatusDoesNotWaitForLongApply(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &blockingAdapter{started: make(chan struct{}), release: make(chan struct{})}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0).UTC())
	if err != nil || !plan.Ready {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	done := make(chan error, 1)
	go func() {
		_, applyErr := manager.Apply(context.Background(), plan, nil)
		done <- applyErr
	}()
	select {
	case <-adapter.started:
	case <-time.After(time.Second):
		t.Fatal("apply did not reach blocking snapshot")
	}
	statusDone := make(chan RuntimeStatus, 1)
	go func() {
		status, statusErr := manager.Status()
		if statusErr != nil {
			statusDone <- RuntimeStatus{}
			return
		}
		statusDone <- status
	}()
	select {
	case status := <-statusDone:
		if status.Execution == nil || status.Execution.State != "applying" {
			t.Fatalf("unexpected live status: %+v", status)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runtime status waited for the apply operation lock")
	}
	close(adapter.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestManagerApplyRollsBackBeforeCommitOnHealthFailure(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &fakeAdapter{id: "nfqws2", failAt: "health"}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0).UTC())
	if err != nil || !plan.Ready {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	committed := false
	execution, err := manager.Apply(context.Background(), plan, func() (func() error, error) {
		committed = true
		return func() error { committed = false; return nil }, nil
	})
	if err == nil || committed || !adapter.rollback || execution.State != "rolled-back" {
		t.Fatalf("execution=%+v committed=%v rollback=%v err=%v", execution, committed, adapter.rollback, err)
	}
}

func TestBuildNFQWS2PlanExplainsEveryGate(t *testing.T) {
	input := Input{
		Revision: 7,
		SafeMode: true,
		Routes:   []Route{{ServiceID: "youtube", ServiceName: "YouTube", Selected: "auto", Resolved: "nfqws2", Domains: []string{"youtube.com"}}},
		Engines:  []Engine{{ID: "nfqws2", Installed: true, Configured: true, Running: true, Version: "2.0"}},
		Host:     HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"},
	}
	plan, err := BuildAt(input, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ready || plan.Noop || len(plan.Actions) < 6 {
		t.Fatalf("unexpected nfqws2 plan: %+v", plan)
	}
	want := map[string]bool{"SAFE_MODE": false, "ADAPTER_ACTIVATION_PENDING": false}
	for _, blocker := range plan.Blockers {
		if _, ok := want[blocker.Code]; ok {
			want[blocker.Code] = true
		}
	}
	for code, found := range want {
		if !found {
			t.Fatalf("missing blocker %s in %+v", code, plan.Blockers)
		}
	}
	if plan.Actions[0].Phase != "snapshot" || plan.Actions[len(plan.Actions)-1].Phase != "commit" {
		t.Fatalf("transaction ordering not explicit: %+v", plan.Actions)
	}
}

func TestDigestIsIndependentOfInputOrdering(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	a := Input{Revision: 1, Routes: []Route{{ServiceID: "b", Resolved: "direct"}, {ServiceID: "a", Resolved: "direct", Domains: []string{"z.example", "a.example"}}}}
	b := Input{Revision: 1, Routes: []Route{{ServiceID: "a", Resolved: "direct", Domains: []string{"a.example", "z.example"}}, {ServiceID: "b", Resolved: "direct"}}}
	left, err := BuildAt(a, now)
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildAt(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if left.Digest != right.Digest || left.PlanID != right.PlanID {
		t.Fatalf("non-deterministic plan digest: %s != %s", left.Digest, right.Digest)
	}
}

func TestBuildBlocksStandaloneNFQWS2WhileZ2KOwnsNFQueue(t *testing.T) {
	plan, err := BuildAt(Input{
		Revision: 1,
		Routes:   []Route{{ServiceID: "discord", ServiceName: "Discord", Resolved: "nfqws2"}},
		Engines:  []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}},
		Host: HostState{
			IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true,
			NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled",
			Z2KInstalled: true, Z2KRunning: true, Z2KVersion: "r-77.5",
		},
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, blocker := range plan.Blockers {
		if blocker.Code == "EXTERNAL_NFQUEUE_OWNER" && blocker.Adapter == "nfqws2" {
			return
		}
	}
	t.Fatalf("z2k ownership blocker missing: %+v", plan.Blockers)
}

func TestManagerRecordsLatestPlanAtomically(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	plan, err := BuildAt(Input{Revision: 1}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Record(plan); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := manager.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || loaded.Digest != plan.Digest || loaded.PlanID != plan.PlanID {
		t.Fatalf("unexpected journal: exists=%v loaded=%+v", exists, loaded)
	}
}

func TestManagerRecoversOnlyCommittedPlan(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &fakeAdapter{id: "nfqws2"}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	plan.State = "committed"
	if err := manager.Record(plan); err != nil {
		t.Fatal(err)
	}
	recovery, err := manager.Recover(context.Background())
	if err != nil || recovery.State != "recovered" || !adapter.recovered {
		t.Fatalf("recovery=%+v recovered=%v err=%v", recovery, adapter.recovered, err)
	}
	adapter.recovered = false
	plan.State = "reviewed"
	if err := manager.Record(plan); err != nil {
		t.Fatal(err)
	}
	recovery, err = manager.Recover(context.Background())
	if err != nil || recovery.State != "skipped" || adapter.recovered {
		t.Fatalf("unsafe recovery=%+v recovered=%v err=%v", recovery, adapter.recovered, err)
	}
}

func TestManagerRefreshesOnlyCommittedPolicy(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &fakeAdapter{id: "nfqws2"}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	plan.State = "committed"
	if err := manager.Record(plan); err != nil {
		t.Fatal(err)
	}
	changed, err := manager.RefreshCommitted(context.Background())
	if err != nil || !changed["nfqws2"] || !adapter.refreshed {
		t.Fatalf("changed=%v refreshed=%v err=%v", changed, adapter.refreshed, err)
	}
}

func TestManagerDeactivatesRegisteredOwnedRuntime(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &fakeAdapter{id: "nfqws2"}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	report, err := manager.Deactivate(context.Background())
	if err != nil || report.State != "deactivated" || !adapter.deactivated || len(report.Steps) != 1 || report.Steps[0].State != "deactivated" {
		t.Fatalf("report=%+v adapter=%+v err=%v", report, adapter, err)
	}
}
