package providerfeed

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func waitJob(t *testing.T, m *Manager, id string) Job {
	t.Helper()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		job, err := m.Job(id)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status != "queued" && job.Status != "running" {
			return job
		}
		select {
		case <-deadline:
			t.Fatal("bounded job failed to join")
		case <-ticker.C:
		}
	}
}
func TestSubscriptionJobsOwnAdmissionSerializeWorkAndCancelWithoutRoutes(t *testing.T) {
	m, nodes, _ := persistentManager(t)
	first := saveFeed(t, m, false)
	second, err := m.Save(context.Background(), "", SaveRequest{Request: Request{URL: "https://another.example.org/private-token"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var admissions, active, maxActive, fetches atomic.Int32
	entered := make(chan struct{}, 1)
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		fetches.Add(1)
		if admissions.Load() != 1 {
			t.Error("worker lost operation admission")
		}
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := maxActive.Load()
			if n <= old || maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	m.Start(ctx, func(context.Context) (func(), error) { admissions.Add(1); return func() { admissions.Add(-1) }, nil })
	job1, err := m.QueueSync(first.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	job2, err := m.QueueSync(second.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := m.QueueSync(first.SourceID)
	if again.ID != job1.ID {
		t.Fatal("duplicate source job queued")
	}
	if _, err := m.CancelJob(job2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CancelJob(job1.ID); err != nil {
		t.Fatal(err)
	}
	if got := waitJob(t, m, job1.ID); got.Status != "canceled" {
		t.Fatalf("running cancel status=%s", got.Status)
	}
	if got := waitJob(t, m, job2.ID); got.Status != "canceled" {
		t.Fatal("queued cancel not retained")
	}
	stop()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Wait(wait); err != nil {
		t.Fatal(err)
	}
	if admissions.Load() != 0 || active.Load() != 0 || maxActive.Load() != 1 || fetches.Load() != 1 {
		t.Fatal("work leaked, overlapped, or canceled queue reached network")
	}
	snapshot, err := nodes.Snapshot(context.Background(), testTime)
	if err != nil || len(snapshot.Nodes) != 0 {
		t.Fatal("failed/canceled job changed candidates")
	}
}

func TestSubscriptionJobSuccessPublishesResultAndBackoffSurvivesRestart(t *testing.T) {
	m, _, _ := persistentManager(t)
	saved := saveFeed(t, m, true)
	setResponse(m, 200, goodURI, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx, nil)
	job, err := m.QueueSync(saved.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	result := waitJob(t, m, job.ID)
	if result.Status != "completed" || result.Result == nil || result.Result.Imported != 1 {
		t.Fatal("job lost successful import result")
	}
	view, err := m.Saved(saved.SourceID)
	if err != nil || view.NextRefreshAt.Before(testTime.Add(6*time.Hour)) {
		t.Fatal("successful refresh was scheduled too soon")
	}
	setResponse(m, 503, "private failure body", nil)
	job, err = m.QueueSync(saved.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	result = waitJob(t, m, job.ID)
	if result.Status != "failed" || result.ErrorCode != "FEED_FETCH" {
		t.Fatal("job exposes wrong failure")
	}
	view, _ = m.Saved(saved.SourceID)
	if view.NextRefreshAt.Before(testTime.Add(MinRefreshMinutes*time.Minute)) || !view.LastKnownGood {
		t.Fatal("failure lost retained candidates or backoff")
	}
	cancel()
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := m.Wait(wait); err != nil {
		t.Fatal(err)
	}
}
