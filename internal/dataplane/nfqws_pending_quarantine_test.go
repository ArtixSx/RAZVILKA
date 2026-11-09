package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// This exercises actual original roots and retained publication FDs. The
// transaction classifier/native inventory remains the separate native case;
// this private fixture does not claim to issue a production quarantine.
func nfqQuarantineRecordsFixture(t *testing.T) (*NFQWSPendingQuarantine, context.Context) {
	t.Helper()
	f, s, _ := preResourcePendingScope(t)
	s.execution.State = "rollback-failed"
	records, err := newNFQWSProbeRecords(s)
	if err != nil {
		t.Fatal(err)
	}
	plan := cloneExecutionResourcePlan(f.e.plan)
	plan.State, plan.Ready = "rollback-failed", false
	q := &NFQWSPendingQuarantine{manager: s.manager, scope: s, execution: f.e, plan: plan, records: records}
	q.self = q
	t.Cleanup(func() { _ = q.Close() })
	if err := q.publishPlan(plan); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(s.execution, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.publishExecution(data); err != nil {
		t.Fatal(err)
	}
	return q, f.ctx
}

func TestNFQWSQuarantineActualThreeWriterFDsSurviveScopeClose(t *testing.T) {
	q, ctx := nfqQuarantineRecordsFixture(t)
	q.claimed = true // Explicit classification model; native fixture proves issuer.
	q.scope.nfqQuarantine = q
	q.scope.execution.State, q.scope.execution.RollbackVerified = "rolled-back", true
	plan := cloneExecutionResourcePlan(q.plan)
	plan.State = "rolled-back"
	if err := q.publishPlan(plan); err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(q.scope.execution, "", "  ")
	if err := q.publishExecution(data); err != nil {
		t.Fatal(err)
	}
	if err := q.sealJoined(ctx, *q.scope.execution, plan); err != nil {
		t.Fatal(err)
	}
	if err := q.scope.close(); err != nil {
		t.Fatal(err)
	}
	if err := q.Joined(ctx); err != nil {
		t.Fatal("original publication lost before source close", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	if err := q.Joined(ctx); err == nil {
		t.Fatal("closed witness revived")
	}
	if err := q.Close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
}

func TestNFQWSQuarantineNoNamedAdoptionAndStickyPublicationFailure(t *testing.T) {
	for _, target := range []string{"latest-plan.json", "latest-execution.json", "execution.json", "state-root", "transaction-root"} {
		t.Run(target, func(t *testing.T) {
			q, ctx := nfqQuarantineRecordsFixture(t)
			var path string
			if target == "state-root" || target == "transaction-root" {
				path = q.scope.managerRoot
				if target == "transaction-root" {
					path = q.scope.root
				}
				old := path + "-original"
				if err := os.Rename(path, old); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = os.Remove(path); _ = os.Rename(old, path) }()
			} else {
				path = filepath.Join(q.scope.managerRoot, target)
				if target == "execution.json" {
					path = filepath.Join(q.scope.root, target)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				old := path + "-original"
				if err := os.Rename(path, old); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = os.Remove(path); _ = os.Rename(old, path) }()
			}
			if err := q.recordsCurrentLocked(ctx); err == nil {
				t.Fatal("same bytes/replaced root adopted")
			}
			if err := q.publishPlan(q.plan); err == nil || q.revoked == nil {
				t.Fatal("publication uncertainty not sticky", err)
			}
			q.claimed = true
			if err := q.Joined(ctx); err == nil {
				t.Fatal("revoked witness granted completion")
			}
		})
	}
}

func TestNFQWSQuarantineTerminalProofRefusesCancelCopyAndIncompletePair(t *testing.T) {
	for _, cut := range []string{"cancel", "copy", "unverified", "nonterminal", "stale-plan", "journal-mismatch"} {
		t.Run(cut, func(t *testing.T) {
			q, ctx := nfqQuarantineRecordsFixture(t)
			q.claimed = true
			plan := cloneExecutionResourcePlan(q.plan)
			plan.State = "rolled-back"
			q.scope.execution.State, q.scope.execution.RollbackVerified = "rolled-back", true
			if err := q.publishPlan(plan); err != nil {
				t.Fatal(err)
			}
			data, _ := json.MarshalIndent(q.scope.execution, "", "  ")
			if err := q.publishExecution(data); err != nil {
				t.Fatal(err)
			}
			switch cut {
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "copy":
				q = &NFQWSPendingQuarantine{self: q, scope: q.scope, execution: q.execution, records: q.records, claimed: true}
			case "unverified":
				q.scope.execution.RollbackVerified = false
			case "nonterminal":
				q.scope.execution.State = "rollback-failed"
			case "stale-plan":
				plan.Revision++
			case "journal-mismatch":
				q.scope.execution.Error = "late modification"
			case "revoked":
				q.Revoke()
			}
			if err := q.sealJoined(ctx, *q.scope.execution, plan); err == nil {
				t.Fatal("invalid terminal proof accepted")
			}
			if q.joined {
				t.Fatal("failed seal published terminal state")
			}
		})
	}
}

func TestNFQWSQuarantineExactParticipantsAndIssuerRefusal(t *testing.T) {
	f, s, _ := preResourcePendingScope(t)
	e := f.e
	prepared := []Adapter{e.gate, e.material.adapter}
	if !originalNFQQuarantineParticipants(f.ctx, prepared, e.gate, s) {
		t.Fatal("exact pair refused")
	}
	for _, adapters := range [][]Adapter{{e.gate, e.gate}, {e.material.adapter, e.material.adapter}, {e.gate, e.material.adapter, NewNFQWS2Adapter()}, {e.gate, NewNFQWS2Adapter()}} {
		if originalNFQQuarantineParticipants(f.ctx, adapters, e.gate, s) {
			t.Fatal("foreign participants granted classification")
		}
	}
	if _, err := newNFQWSPendingQuarantine(f.ctx, e.material.manager, s, e.plan); !errors.Is(err, ErrNFQWSScopedOwner) {
		t.Fatal("pre-resource state minted pending witness", err)
	}
	if _, err := e.material.manager.ReviewPendingNFQWSQuarantine(f.ctx); err == nil {
		t.Fatal("non-pending Manager issued witness")
	}
}

func TestNFQWSQuarantineRevokedAdmissionStillFinishesOriginalCleanup(t *testing.T) {
	q, ctx := nfqQuarantineRecordsFixture(t)
	q.claimed = true
	q.Revoke() // A failed prior Stop has already permanently fenced the App.
	plan := cloneExecutionResourcePlan(q.plan)
	plan.State = "rolled-back"
	q.scope.execution.State, q.scope.execution.RollbackVerified = "rolled-back", true
	if err := q.publishPlan(plan); err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(q.scope.execution, "", "  ")
	if err := q.publishExecution(data); err != nil {
		t.Fatal(err)
	}
	if err := q.sealJoined(ctx, *q.scope.execution, plan); err != nil {
		t.Fatal("revocation stranded original terminal cleanup", err)
	}
	if err := q.Joined(ctx); err == nil {
		t.Fatal("revoked admission recovered")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := q.VerifyJoinedCleanup(canceled); err == nil {
		t.Fatal("canceled cleanup accepted")
	}
	if err := q.VerifyJoinedCleanup(ctx); err != nil {
		t.Fatal("fresh original cleanup stranded", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	if err := q.Joined(ctx); err == nil {
		t.Fatal("closed revoked witness revived")
	}
}
