package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

func coldXrayRollbackRetryFixture(t *testing.T) (*Manager, *inactiveFixture, *rollbackVerifierFake, Plan, Execution, string) {
	t.Helper()
	f, oldRoot, candidate := unstagedColdXrayFixture(t)
	m := New(filepath.Dir(f.a.StateRoot))
	nfq := &rollbackVerifierFake{networkExecutionAdapter: &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "nfqws2"}}, verify: func(context.Context) (bool, error) { return true, nil }}
	if err := m.Register(nfq); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(f.a); err != nil {
		t.Fatal(err)
	}
	previous := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-1111111111111111", Digest: strings.Repeat("1", 64), State: "committed", Ready: true, Revision: 5, Adapters: []string{"nfqws2"}, Routes: []Route{{ServiceID: "youtube", Selected: "nfqws2", Resolved: "nfqws2"}}}
	if err := m.Record(previous); err != nil {
		t.Fatal(err)
	}
	candidate.SchemaVersion, candidate.PlanID, candidate.Digest, candidate.State = SchemaVersion, "dp-2222222222222222", strings.Repeat("2", 64), "rollback-failed"
	candidate.Ready, candidate.Revision, candidate.Adapters = true, 6, []string{"nfqws2", "xray"}
	candidate.Routes = append(previous.Routes, candidate.Routes...)
	if err := m.Record(candidate); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(m.StateRoot, "transactions", candidate.PlanID)
	if err := m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	xrayRoot := filepath.Join(root, "xray")
	raw, err := os.ReadFile(filepath.Join(oldRoot, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	inactiveWrite(t, filepath.Join(xrayRoot, "snapshot.json"), raw)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	execution := Execution{PlanID: candidate.PlanID, Digest: candidate.Digest, State: "rollback-failed", StartedAt: now, FinishedAt: now, Error: "stage refused; rollback failed: exit status 255"}
	for _, row := range [][3]string{{"nfqws2", "snapshot", "passed"}, {"xray", "snapshot", "passed"}, {"nfqws2", "stage", "passed"}, {"xray", "stage", "failed"}, {"xray", "rollback", "failed"}, {"nfqws2", "rollback", "passed"}, {"nfqws2", "verify-rollback", "passed"}, {"xray", "verify-rollback", "passed"}} {
		execution.Steps = append(execution.Steps, ExecutionStep{Adapter: row[0], Phase: row[1], State: row[2], StartedAt: now, FinishedAt: now})
	}
	if err := m.writeExecution(root, execution); err != nil {
		t.Fatal(err)
	}
	return m, f, nfq, candidate, execution, xrayRoot
}

func TestRetryUnstagedColdXrayExactJournalPlanSurvivesDispatchCopy(t *testing.T) {
	for _, priorRetry := range []bool{false, true} {
		t.Run(map[bool]string{false: "original-eight-steps", true: "persisted-twelve-steps"}[priorRetry], func(t *testing.T) {
			m, f, nfq, plan, original, root := coldXrayRollbackRetryFixture(t)
			// The captured failed journal has a service descriptor without probes.
			// Dispatch's defensive service copy turns this nil slice into empty.
			plan.Routes[0].ProbeService = &catalog.Service{ID: "youtube", Domains: []string{}, Strategy: []string{}}
			if err := m.Record(plan); err != nil {
				t.Fatal(err)
			}
			plan, _, _ = m.latestLocked()
			_, copied, err := f.a.dispatchXrayPlan(plan, root, true)
			if err != nil || reflect.DeepEqual(plan, copied) || plan.Routes[0].ProbeService.Probes != nil || copied.Routes[0].ProbeService.Probes == nil {
				t.Fatal("fixture did not preserve the original dispatch shape mismatch", err)
			}
			if priorRetry {
				now := time.Now().UTC().Format(time.RFC3339Nano)
				for _, row := range [][3]string{{"xray", "retry-rollback", "failed"}, {"nfqws2", "retry-rollback", "passed"}, {"nfqws2", "retry-verify-rollback", "passed"}, {"xray", "retry-verify-rollback", "failed"}} {
					original.Steps = append(original.Steps, ExecutionStep{Adapter: row[0], Phase: row[1], State: row[2], StartedAt: now, FinishedAt: now})
				}
				original.FinishedAt = now
				if err := m.writeExecution(filepath.Dir(root), original); err != nil {
					t.Fatal(err)
				}
			}
			before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
			processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
			f.a.Processes = processes
			result, err := m.retryFailedRollback(context.Background(), plan.PlanID, plan.Digest, func(Plan) error { return nil }, &f.proof)
			if err != nil || result.State != "rolled-back" || !result.RollbackVerified || !nfq.rollback || len(result.Steps) != len(original.Steps)+4 || !reflect.DeepEqual(result.Steps[:len(original.Steps)], original.Steps) {
				t.Fatal("exact original plan could not close its failed transaction", result, err)
			}
			if m.checkExecutionRecovery() != nil || len(processes.start) != 0 || len(processes.stop) != 0 || !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
				t.Fatal("no-effect retry changed Xray files/processes or retained the fence")
			}
		})
	}
}

func TestRetryUnstagedColdXrayWrapperRejectsOriginalPlanDrift(t *testing.T) {
	for _, mode := range []string{"probe-shape", "route", "root"} {
		t.Run(mode, func(t *testing.T) {
			m, f, _, plan, _, root := coldXrayRollbackRetryFixture(t)
			plan.Routes[0].ProbeService = &catalog.Service{ID: "youtube"}
			if err := m.Record(plan); err != nil {
				t.Fatal(err)
			}
			reviewed, ok := m.reviewUnstagedColdXrayRollback(context.Background(), plan.PlanID, plan.Digest, &f.proof)
			if !ok {
				t.Fatal("fixture not admitted")
			}
			wrapper := reviewed.prepared[1].(*unstagedColdXrayRollback)
			reads := len(f.runner.seen)
			switch mode {
			case "probe-shape":
				reviewed.plan.Routes[0].ProbeService.Probes = []catalog.Probe{}
			case "route":
				reviewed.plan.Routes[0].Resolved = "foreign"
			case "root":
				root += "-other"
			}
			if err := wrapper.Rollback(context.Background(), reviewed.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
				t.Fatal("changed original plan reached no-op helper", err)
			}
			if len(f.runner.seen) != reads || m.checkExecutionRecovery() == nil {
				t.Fatal("refusal observed a different plan or lost the fence")
			}
		})
	}
}

func TestRetryUnstagedColdXrayClosesOnlyOriginalFailedTransaction(t *testing.T) {
	m, f, nfq, plan, original, root := coldXrayRollbackRetryFixture(t)
	before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
	processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
	f.a.Processes = processes
	previous, _, err := m.Committed()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CloseFailedRollback(context.Background(), plan.PlanID, plan.Digest, func(Plan) error { return nil }); err == nil || nfq.rollback {
		t.Fatal("cold retry admission leaked into deactivation recovery")
	}
	guards := 0
	result, err := m.retryFailedRollback(context.Background(), plan.PlanID, plan.Digest, func(p Plan) error {
		guards++
		if !reflect.DeepEqual(p, previous) {
			t.Fatal("different applied intent")
		}
		return nil
	}, &f.proof)
	if err != nil || result.State != "rolled-back" || !result.RollbackVerified || !nfq.rollback || guards != 2 || len(result.Steps) != len(original.Steps)+4 || !strings.Contains(result.Error, "exit status 255") {
		t.Fatal("original failure was not reviewed and closed", result, err)
	}
	if !reflect.DeepEqual(result.Steps[:len(original.Steps)], original.Steps) || m.checkExecutionRecovery() != nil {
		t.Fatal("original evidence changed or fence did not settle")
	}
	afterPrevious, _, err := m.Committed()
	if err != nil || !reflect.DeepEqual(afterPrevious, previous) {
		t.Fatal("committed intent changed", err)
	}
	if len(processes.start) != 0 || len(processes.stop) != 0 || !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
		t.Fatal("cold Xray recovery touched runtime or snapshot")
	}
}

func TestRetryUnstagedColdXrayRejectsAmbiguityBeforeAnyParticipant(t *testing.T) {
	for _, mode := range []string{"malformed", "mismatched-journal", "stage-passed", "issued-activate", "wrong-previous", "resources", "partial-staged", "receipt", "boot-drift", "foreign-process", "foreign-config", "kernel-error", "active-snapshot", "source-path", "hidden-payload", "guard"} {
		t.Run(mode, func(t *testing.T) {
			m, f, nfq, plan, execution, root := coldXrayRollbackRetryFixture(t)
			processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
			f.a.Processes = processes
			guard := func(Plan) error { return nil }
			switch mode {
			case "malformed":
				inactiveWrite(t, filepath.Join(root, "snapshot.json"), []byte(`{"engine_id":"xray"}`))
			case "mismatched-journal":
				execution.Error += " changed"
				raw, _ := json.Marshal(execution)
				inactiveWrite(t, filepath.Join(filepath.Dir(root), "execution.json"), raw)
			case "stage-passed":
				execution.Steps[3].State = "passed"
			case "issued-activate":
				execution.Steps[3].Phase = "activate"
			case "wrong-previous":
				previous, _, _ := m.Committed()
				previous.Adapters = []string{"nfqws2", "xray"}
				if err := m.Record(previous); err != nil {
					t.Fatal(err)
				}
				if err := m.Record(plan); err != nil {
					t.Fatal(err)
				}
			case "resources":
				execution.ResourcePlanID = plan.PlanID
			case "partial-staged":
				inactiveWrite(t, filepath.Join(root, "engine.staged.json"), []byte(`{}`))
			case "receipt":
				inactiveWrite(t, proxyPolicyReceiptPath(root), []byte(`{}`))
			case "boot-drift":
				f.a.bootIdentity = func() (string, error) { return "other-boot", nil }
			case "foreign-process":
				f.writeProcess(t, 456, "S", "0", "xray\x00run\x00")
			case "foreign-config":
				inactiveWrite(t, f.a.engineConfigPath(), []byte(`{}`))
			case "kernel-error":
				f.runner.err = errors.New("kernel inventory unavailable")
			case "active-snapshot":
				snapshot, err := readProxySnapshot(root)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.EngineWasRunning = true
				raw, _ := json.Marshal(snapshot)
				inactiveWrite(t, filepath.Join(root, "snapshot.json"), raw)
			case "source-path", "hidden-payload":
				snapshot, err := readProxySnapshot(root)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "source-path" {
					snapshot.ConfigPath += ".other"
				} else {
					snapshot.Config = []byte("unrecognized payload")
				}
				raw, _ := json.Marshal(snapshot)
				inactiveWrite(t, filepath.Join(root, "snapshot.json"), raw)
			case "guard":
				guard = func(Plan) error { return errors.New("settings drift") }
			}
			if mode == "stage-passed" || mode == "issued-activate" || mode == "resources" {
				if err := m.writeExecution(filepath.Dir(root), execution); err != nil {
					t.Fatal(err)
				}
			}
			before := proxyRollbackRetryFiles(t, m.StateRoot)
			if result, err := m.retryFailedRollback(context.Background(), plan.PlanID, plan.Digest, guard, &f.proof); err == nil || result.State == "rolled-back" {
				t.Fatal("ambiguous history closed", result, err)
			}
			if nfq.rollback || len(processes.start) != 0 || len(processes.stop) != 0 || !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, m.StateRoot)) || m.checkExecutionRecovery() == nil {
				t.Fatal("refusal changed a participant, journal or fence")
			}
		})
	}
}

func TestRetryUnstagedColdXrayLateStageCannotFallThroughToCleanup(t *testing.T) {
	m, f, _, plan, _, root := coldXrayRollbackRetryFixture(t)
	processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
	f.a.Processes = processes
	guard := func(Plan) error {
		inactiveWrite(t, filepath.Join(root, "engine.staged.json"), []byte("foreign late candidate"))
		return nil
	}
	result, err := m.retryFailedRollback(context.Background(), plan.PlanID, plan.Digest, guard, &f.proof)
	if err == nil || result.State != "rollback-failed" || m.checkExecutionRecovery() == nil || len(processes.start) != 0 || len(processes.stop) != 0 {
		t.Fatal("late stage was adopted or cleaned", result, err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "engine.staged.json"))
	if err != nil || string(raw) != "foreign late candidate" {
		t.Fatal("foreign artifact changed", err)
	}
}

func TestRetryUnstagedColdXrayRejectsJournalDriftDuringAbsence(t *testing.T) {
	m, f, nfq, plan, execution, _ := coldXrayRollbackRetryFixture(t)
	var changed map[string]string
	f.runner.hook = func() {
		execution.Error += " changed while observing"
		raw, err := json.Marshal(execution)
		if err != nil {
			t.Fatal(err)
		}
		inactiveWrite(t, filepath.Join(m.StateRoot, "latest-execution.json"), raw)
		changed = proxyRollbackRetryFiles(t, m.StateRoot)
	}
	if result, err := m.retryFailedRollback(context.Background(), plan.PlanID, plan.Digest, func(Plan) error { return nil }, &f.proof); err == nil || result.State == "rolled-back" {
		t.Fatal("observation outlived reviewed journals", result, err)
	}
	if changed == nil || nfq.rollback || !reflect.DeepEqual(changed, proxyRollbackRetryFiles(t, m.StateRoot)) || m.checkExecutionRecovery() == nil {
		t.Fatal("changed journal was overwritten or its fence lost")
	}
}
