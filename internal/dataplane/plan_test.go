package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestBuildDirectPlanIsReadyNoop(t *testing.T) {
	plan, err := BuildAt(Input{Revision: 3, SafeMode: true, Routes: []Route{{ServiceID: "example", ServiceName: "Example", Selected: "direct", Resolved: "direct"}}}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || !plan.Noop || len(plan.Blockers) != 0 {
		t.Fatalf("unexpected direct plan: %+v", plan)
	}
	if plan.RequiredEvidence != evidence.Service || plan.ObservedEvidence != evidence.None {
		t.Fatalf("desired direct route promoted evidence: required=%s observed=%s", plan.RequiredEvidence, plan.ObservedEvidence)
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

type cancellationAdapter struct {
	stageStarted      chan struct{}
	rollbackUnblocked bool
}

func (a *cancellationAdapter) ID() string                                   { return "nfqws2" }
func (a *cancellationAdapter) Snapshot(context.Context, Plan, string) error { return nil }
func (a *cancellationAdapter) Stage(ctx context.Context, _ Plan, _ string) error {
	close(a.stageStarted)
	<-ctx.Done()
	return ctx.Err()
}
func (a *cancellationAdapter) Validate(context.Context, Plan, string) error { return nil }
func (a *cancellationAdapter) Activate(context.Context, Plan, string) error { return nil }
func (a *cancellationAdapter) Health(context.Context, Plan, string) error   { return nil }
func (a *cancellationAdapter) Commit(context.Context, Plan, string) error   { return nil }
func (a *cancellationAdapter) Rollback(ctx context.Context, _ Plan, _ string) error {
	a.rollbackUnblocked = ctx.Err() == nil
	return ctx.Err()
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
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2", ProbeURL: "https://www.youtube.com/generate_204"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0).UTC())
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
	committedPlan, exists, latestErr := manager.Latest()
	if latestErr != nil || !exists {
		t.Fatalf("latest plan missing: exists=%v err=%v", exists, latestErr)
	}
	if committedPlan.ObservedEvidence != evidence.Service || committedPlan.RequiredEvidence != evidence.Service {
		t.Fatalf("successful health was not recorded as service evidence: %+v", committedPlan)
	}
}

func TestManagerDoesNotPromoteUnprobedDirectRoute(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &fakeAdapter{id: "nfqws2"}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAt(Input{
		Revision: 2,
		Routes: []Route{
			{ServiceID: "youtube", Resolved: "nfqws2", ProbeURL: "https://www.youtube.com/generate_204"},
			{ServiceID: "github", Resolved: "direct"},
		},
		Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}},
		Host:    HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"},
	}, time.Unix(100, 0).UTC())
	if err != nil || !plan.Ready {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if _, err := manager.Apply(context.Background(), plan, nil); err != nil {
		t.Fatal(err)
	}
	committed, exists, err := manager.Latest()
	if err != nil || !exists {
		t.Fatalf("latest plan missing: exists=%v err=%v", exists, err)
	}
	if committed.ObservedEvidence != evidence.None {
		t.Fatalf("DIRECT route was promoted by another adapter health: %s", committed.ObservedEvidence)
	}
	proofs := map[string]RouteEvidence{}
	for _, proof := range committed.RouteEvidence {
		proofs[proof.ServiceID] = proof
	}
	if proofs["youtube"].Observed != evidence.Service || proofs["github"].Observed != evidence.None {
		t.Fatalf("unexpected per-route evidence: %+v", proofs)
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

func TestConflictingOperationWaitIsContextAware(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &blockingAdapter{started: make(chan struct{}), release: make(chan struct{})}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan := readyNFQWS2Plan(t)
	firstDone := make(chan error, 1)
	go func() {
		_, err := manager.Apply(context.Background(), plan, nil)
		firstDone <- err
	}()
	<-adapter.started
	waitCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	execution, err := manager.Apply(waitCtx, plan, nil)
	if !errors.Is(err, context.DeadlineExceeded) || execution.State != "cancelled" {
		t.Fatalf("second apply did not cancel while waiting: execution=%+v err=%v", execution, err)
	}
	close(adapter.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestRollbackUsesIndependentBoundedContext(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &cancellationAdapter{stageStarted: make(chan struct{})}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	plan := readyNFQWS2Plan(t)
	done := make(chan struct {
		execution Execution
		err       error
	}, 1)
	go func() {
		execution, err := manager.Apply(ctx, plan, nil)
		done <- struct {
			execution Execution
			err       error
		}{execution, err}
	}()
	<-adapter.stageStarted
	cancel()
	result := <-done
	if !errors.Is(result.err, context.Canceled) || result.execution.State != "rolled-back" || !adapter.rollbackUnblocked {
		t.Fatalf("cancelled apply did not get a fresh rollback context: execution=%+v rollback=%v err=%v", result.execution, adapter.rollbackUnblocked, result.err)
	}
}

func readyNFQWS2Plan(t *testing.T) Plan {
	t.Helper()
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0).UTC())
	if err != nil || !plan.Ready {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	return plan
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

func TestBuildBlocksSelectedAdapterResourceConflict(t *testing.T) {
	plan, err := BuildAt(Input{
		Revision:          1,
		Routes:            []Route{{ServiceID: "telegram", ServiceName: "Telegram", Resolved: "sing-box"}},
		Engines:           []Engine{{ID: "sing-box", Installed: true, Configured: true, Activatable: true}},
		Host:              HostState{IPCommand: true, TUN: true, SingBox: true},
		ResourceConflicts: []ResourceConflict{{Kind: "port", Value: "1080", Engines: []string{"sing-box", "usque"}}},
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, blocker := range plan.Blockers {
		if blocker.Code == "PORT_CONFLICT" && blocker.Adapter == "sing-box" && strings.Contains(blocker.Message, "1080") {
			return
		}
	}
	t.Fatalf("resource conflict blocker missing: %+v", plan.Blockers)
}

func TestBuildNamesPolicyOwnershipConflicts(t *testing.T) {
	plan, err := BuildAt(Input{
		Revision:          1,
		Routes:            []Route{{ServiceID: "video", ServiceName: "Video", Resolved: "sing-box"}},
		Engines:           []Engine{{ID: "sing-box", Installed: true, Configured: true, Activatable: true}},
		Host:              HostState{IPCommand: true, TUN: true},
		ResourceConflicts: []ResourceConflict{{Kind: "priority", Value: "22000", Engines: []string{"sing-box"}, SystemUse: "lookup 999"}, {Kind: "table", Value: "203", Engines: []string{"sing-box"}, SystemUse: "default dev foreign0"}},
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, blocker := range plan.Blockers {
		codes[blocker.Code] = true
	}
	if !codes["POLICY_PRIORITY_CONFLICT"] || !codes["POLICY_TABLE_CONFLICT"] {
		t.Fatalf("policy conflicts were not named: %+v", plan.Blockers)
	}
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

func TestManagerReviewedDraftDoesNotReplaceCommittedRecoveryPlan(t *testing.T) {
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
	latest, latestExists, latestErr := manager.Latest()
	committed, committedExists, committedErr := manager.Committed()
	if latestErr != nil || committedErr != nil || !latestExists || !committedExists || latest.State != "reviewed" || committed.State != "committed" {
		t.Fatalf("journals were not separated: latest=%+v committed=%+v errors=%v/%v", latest, committed, latestErr, committedErr)
	}
	recovery, err = manager.Recover(context.Background())
	if err != nil || recovery.State != "recovered" || !adapter.recovered {
		t.Fatalf("committed recovery was hidden by reviewed draft: recovery=%+v recovered=%v err=%v", recovery, adapter.recovered, err)
	}
}

func TestManagerEntersRecoverySafeModeAndGuardsRepeatedBootFailure(t *testing.T) {
	manager := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &fakeAdapter{id: "nfqws2", failAt: "reconcile"}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "telegram", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	plan.State = "committed"
	if err := manager.Record(plan); err != nil {
		t.Fatal(err)
	}
	first, err := manager.Recover(context.Background())
	if err == nil || first.State != "degraded" || first.FailureCount != 1 || !adapter.deactivated {
		t.Fatalf("first recovery=%+v deactivated=%v err=%v", first, adapter.deactivated, err)
	}
	adapter.recovered, adapter.deactivated = false, false
	second, err := manager.Recover(context.Background())
	if err == nil || second.State != "safe-mode" || !second.Guarded || second.FailureCount < 2 || adapter.recovered || !adapter.deactivated {
		t.Fatalf("second recovery=%+v recovered=%v deactivated=%v err=%v", second, adapter.recovered, adapter.deactivated, err)
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
