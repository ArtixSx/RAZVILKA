package providerfeed

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedFeedSchedulingUsesSameBoundedCancelableWorker(t *testing.T) {
	m, _, _ := persistentManager(t)
	feed := saveFeed(t, m, true)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	entered := make(chan struct{}, 1)
	var fetches atomic.Int32
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		fetches.Add(1)
		entered <- struct{}{}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	m.StartManaged(ctx, nil)
	m.ScheduleDue(testTime.Add(24 * time.Hour))
	m.ScheduleDue(testTime.Add(24 * time.Hour))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("managed due event did not start worker")
	}
	job, err := m.QueueSync(feed.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 1 {
		t.Fatal("duplicate due event started another download")
	}
	if _, err = m.CancelJob(job.ID); err != nil {
		t.Fatal(err)
	}
	if got := waitJob(t, m, job.ID); got.Status != "canceled" {
		t.Fatal("managed job not canceled")
	}
	stop()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = m.Wait(wait); err != nil {
		t.Fatal(err)
	}
}
