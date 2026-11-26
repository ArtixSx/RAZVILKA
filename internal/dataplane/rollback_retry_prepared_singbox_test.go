package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func preparedSingboxRetryFixture(t *testing.T) (*Manager, *inactiveFixture, *rollbackVerifierFake, Plan, Execution, string) {
	t.Helper()
	f, oldRoot, _ := coldPreparedRollbackFixture(t)
	m := New(filepath.Dir(f.a.StateRoot))
	nfq := &rollbackVerifierFake{networkExecutionAdapter: &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "nfqws2"}}, verify: func(context.Context) (bool, error) { return true, nil }}
	if err := m.Register(nfq); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(f.a); err != nil {
		t.Fatal(err)
	}
	previous := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-1111111111111111", Digest: strings.Repeat("1", 64), State: "committed", Ready: true, Revision: 5, NetworkProfileID: executionNetwork, Adapters: []string{"nfqws2"}}
	if err := m.Record(previous); err != nil {
		t.Fatal(err)
	}
	plan := previous
	plan.PlanID = "dp-2222222222222222"
	plan.Digest = strings.Repeat("2", 64)
	plan.State = "rollback-failed"
	plan.Revision = 6
	plan.Adapters = []string{"nfqws2", "sing-box"}
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(m.StateRoot, "transactions", plan.PlanID)
	if err := m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	candidateRoot := filepath.Join(root, "sing-box")
	for _, name := range []string{"snapshot.json", "policy.staged.json", "policy-additions.json"} {
		raw, err := os.ReadFile(filepath.Join(oldRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		inactiveWrite(t, filepath.Join(candidateRoot, name), raw)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "rollback-failed", StartedAt: now, FinishedAt: now}
	for _, row := range [][3]string{{"nfqws2", "snapshot", "passed"}, {"sing-box", "snapshot", "passed"}, {"nfqws2", "stage", "passed"}, {"sing-box", "stage", "passed"}, {"nfqws2", "validate", "passed"}, {"sing-box", "validate", "passed"}, {"sing-box", "canary", "passed"}, {"nfqws2", "activate", "failed"}, {"sing-box", "rollback", "passed"}, {"nfqws2", "rollback", "passed"}, {"nfqws2", "verify-rollback", "passed"}, {"sing-box", "verify-rollback", "failed"}} {
		execution.Steps = append(execution.Steps, ExecutionStep{Adapter: row[0], Phase: row[1], State: row[2], StartedAt: now, FinishedAt: now})
	}
	if err := m.writeExecution(root, execution); err != nil {
		t.Fatal(err)
	}
	return m, f, nfq, plan, execution, candidateRoot
}

func TestRetryPreparedColdSingboxMixedAdditionUsesReadOnlyParticipant(t *testing.T) {
	m, f, nfq, plan, original, root := preparedSingboxRetryFixture(t)
	before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, ok := m.reviewFailedRollback(plan.PlanID, plan.Digest); ok {
		t.Fatal("general mixed recovery broadened")
	}
	if _, err := m.CloseFailedRollback(ctx, plan.PlanID, plan.Digest, func(Plan) error { return nil }); err == nil || nfq.rollback {
		t.Fatal("mixed Close unexpectedly acquired authority", err)
	}
	result, err := m.retryFailedRollback(ctx, plan.PlanID, plan.Digest, func(Plan) error { return nil }, &f.proof)
	if err != nil || result.State != "rolled-back" || !result.RollbackVerified || !nfq.rollback || len(result.Steps) != len(original.Steps)+4 {
		t.Fatal("safe mixed retry refused", result, err)
	}
	if m.checkExecutionRecovery() != nil || !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
		t.Fatal("retry changed cold participant or stayed fenced")
	}
}

func TestRetryPreparedColdSingboxRejectsUncertainHistoryBeforeNFQMutation(t *testing.T) {
	for _, mode := range []string{"activate-singbox", "canary-failed", "journal-mismatch", "receipt-unknown", "ledger", "prior-live", "foreign-process", "snapshot-drift", "settings-guard", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			m, f, nfq, p, e, root := preparedSingboxRetryFixture(t)
			guard := func(Plan) error { return nil }
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			switch mode {
			case "activate-singbox":
				e.Steps[7].Adapter = "sing-box"
				_ = m.writeExecution(filepath.Dir(root), e)
			case "canary-failed":
				e.Steps[6].State = "failed"
				_ = m.writeExecution(filepath.Dir(root), e)
			case "journal-mismatch":
				e.Error = "changed"
				raw, _ := json.Marshal(e)
				inactiveWrite(t, filepath.Join(filepath.Dir(root), "execution.json"), raw)
			case "receipt-unknown":
				state := mustScopedPolicy(t, f.a, root)
				r, _ := f.a.readCandidatePolicyReceipt(root, state)
				r.Phase = "unknown"
				_ = writeProxyPolicyReceipt(root, r)
			case "ledger":
				inactiveWrite(t, filepath.Join(root, policyAdditionFile), []byte("{}"))
			case "prior-live":
				s, _ := readProxySnapshot(root)
				s.EngineWasRunning = true
				raw, _ := json.Marshal(s)
				inactiveWrite(t, filepath.Join(root, "snapshot.json"), raw)
			case "foreign-process":
				f.writeProcess(t, 456, "S", "0", "sing-box\x00run\x00")
			case "snapshot-drift":
				f.runner.hook = func() {
					s, _ := readProxySnapshot(root)
					s.Config = []byte("changed")
					raw, _ := json.Marshal(s)
					inactiveWrite(t, filepath.Join(root, "snapshot.json"), raw)
				}
			case "settings-guard":
				guard = func(Plan) error { return ErrReviewChanged }
			case "cancel":
				cancel()
			}
			if _, err := m.retryFailedRollback(ctx, p.PlanID, p.Digest, guard, &f.proof); err == nil || nfq.rollback {
				t.Fatal("uncertain history reached NFQ mutation", mode, err)
			}
		})
	}
}
