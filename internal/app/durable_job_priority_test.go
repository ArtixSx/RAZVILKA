package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestDurablePriorityStopThenManualThenShortWithAging(t *testing.T) {
	now := time.Now().UTC()
	job := func(id uint64, kind string, count int) durableServiceJob {
		return durableServiceJob{ID: id, State: "queued", CreatedAt: now, Request: serviceControlJobRequest{Kind: kind, NodeIDs: make([]string, count)}}
	}
	jobs := []durableServiceJob{job(1, "node-check", 8), job(2, "node-check", 1), job(3, "resume", 0), job(4, "stop", 0)}
	for _, want := range []int{3, 2, 1, 0} {
		got := selectDurableServiceJob(jobs, now, false)
		if got != want {
			t.Fatalf("priority got=%d want=%d", got, want)
		}
		jobs[got].State = "completed"
	}
	jobs[0].State = "interrupted"
	jobs[0].CreatedAt = now.Add(-7 * time.Minute)
	jobs[1].State = "queued"
	jobs[2].State = "queued"
	raw, err := json.Marshal(jobs)
	if err != nil {
		t.Fatal(err)
	}
	var restored []durableServiceJob
	if err = json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if got := selectDurableServiceJob(restored, now, false); got != 0 {
		t.Fatalf("restart/short requests starved old batch: %d", got)
	}
	restored[3].State = "queued"
	if got := selectDurableServiceJob(restored, now, false); got != 3 {
		t.Fatal("aging overtook Stop")
	}
	if got := selectDurableServiceJob(restored, now, true); got != 3 {
		t.Fatal("recovery blocked Stop")
	}
	restored[3].NotBefore = now.Add(time.Hour)
	if got := selectDurableServiceJob(restored, now, true); got != 2 {
		t.Fatalf("aging bypassed recovery or not-before: %d", got)
	}
}

func TestDurableSingleCheckOvertakesBatchWithoutLosingAcceptedBatch(t *testing.T) {
	a, q := durableNodeFixture(t, 3)
	batch := enqueueNodeFixture(t, a, q)
	q.NodeIDs = q.NodeIDs[1:2]
	q.IdempotencyKey = "single-check-priority"
	single := enqueueNodeFixture(t, a, q)
	if !a.runDurableServiceJob(context.Background(), time.Now()) {
		t.Fatal("no job ran")
	}
	if job := durableJobAt(t, a, single); job.State != "completed" || job.Cursor != 1 {
		t.Fatal("single check waited behind full batch", job)
	}
	if job := durableJobAt(t, a, batch); job.State != "queued" || job.Cursor != 0 {
		t.Fatal("priority canceled or consumed batch", job)
	}
	if !a.runDurableServiceJob(context.Background(), time.Now()) {
		t.Fatal("batch was lost")
	}
	if job := durableJobAt(t, a, batch); job.State != "queued" || job.Cursor != 1 {
		t.Fatal("batch did not resume from its durable cursor", job)
	}
}
