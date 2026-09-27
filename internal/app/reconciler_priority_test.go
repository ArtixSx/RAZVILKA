package app

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestReconcilerMaintenanceAgingSurvivesJournal(t *testing.T) {
	now := time.Now()
	tasks := []reconcilerTask{{kind: "node-recovery"}, {kind: "node-fallback"}, {kind: "legacy-routes"}, {kind: "feeds"}, {kind: "service-checks"}}
	operations := []automationOperation{}
	for _, task := range tasks {
		operations = append(operations, automationOperation{Kind: task.kind, NextRun: now})
	}
	if got := orderedReconcilerTasks(tasks, operations, now); !reflect.DeepEqual(got, tasks) {
		t.Fatalf("fresh work did not retain recovery priority: %+v", got)
	}
	operations[4].NextRun = now.Add(-9 * time.Minute)
	raw, err := json.Marshal(operations)
	if err != nil {
		t.Fatal(err)
	}
	var restored []automationOperation
	if err = json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if got := orderedReconcilerTasks(tasks, restored, now); got[0].kind != "service-checks" || got[1].kind != "node-recovery" {
		t.Fatalf("old maintenance starved after restore: %+v", got)
	}
	// A future retry is not aged merely because it is a lower priority kind.
	operations[4].NextRun = now.Add(time.Minute)
	if got := orderedReconcilerTasks(tasks, operations, now); got[0].kind != "node-recovery" {
		t.Fatalf("future task displaced recovery: %+v", got)
	}
}

func TestReconcilerWakeRetainsWaitingAge(t *testing.T) {
	a, _, _, _, _ := nodeAutofallbackFixture(t, 1)
	now := time.Now()
	initReconcilerFixture(t, a, now)
	waiting := now.Add(-10 * time.Minute)
	for i := range a.reconciler.doc.Operations {
		if a.reconciler.doc.Operations[i].Kind == "feeds" {
			a.reconciler.doc.Operations[i].NextRun = waiting
		}
	}
	a.wakeReconciler()
	a.wakeReconciler()
	for _, op := range a.reconciler.doc.Operations {
		if op.Kind == "feeds" && !op.NextRun.Equal(waiting) {
			t.Fatal("repeated wake made waiting maintenance young again")
		}
	}
}

func TestReconcilerLongTaskYieldsAfterCleanupAndPersistsUnstartedWork(t *testing.T) {
	a, _, _, _, _ := nodeAutofallbackFixture(t, 1)
	now := time.Now()
	initReconcilerFixture(t, a, now)
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		time.Sleep(reconcilerDispatchQuantum + 20*time.Millisecond)
		return autofallbackResult(r, false), nil
	})
	a.reconcileRound(context.Background(), now)
	data, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	var doc reconcilerDocument
	if err = json.Unmarshal(data, &doc); err != nil || validateReconcilerDocument(doc) != nil {
		t.Fatal("long task did not leave a valid durable schedule", err)
	}
	found := 0
	for _, op := range doc.Operations {
		switch op.Kind {
		case "node-fallback":
			if op.State != "completed" || !op.NextRun.After(now.Add(time.Minute+reconcilerDispatchQuantum)) {
				t.Fatalf("completed long job was immediately due again: %+v", op)
			}
			found++
		case "service-checks":
			if op.ID != 0 || !op.NextRun.Equal(now) {
				t.Fatalf("another task ran before a new dispatch boundary: %+v", op)
			}
			found++
		}
	}
	if found != 2 {
		t.Fatal("first dispatch failed to persist waiting work")
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("dispatch yielded before cleanup joined", err)
	} else {
		release()
	}
	// The next pass consumes the already persisted due intent; no replay of the
	// slow fallback is needed before the scheduled check can run.
	a.reconcileRound(context.Background(), time.Now())
	for _, op := range a.reconciler.doc.Operations {
		if op.Kind == "service-checks" && (op.ID == 0 || op.State != "completed") {
			t.Fatalf("next pass lost waiting work: %+v", op)
		}
	}
}
