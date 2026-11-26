package providerfeed

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"net/http"
	"testing"
	"time"
)

func TestRetryAfterSurvivesRestartAndCannotBeForced(t *testing.T) {
	m, nodes, path := persistentManager(t)
	s := saveFeed(t, m, true)
	setResponse(m, 200, goodURI, nil)
	if _, e := m.SyncSaved(context.Background(), s.SourceID); e != nil {
		t.Fatal(e)
	}
	setResponse(m, 429, "private body", http.Header{"Retry-After": []string{"3600"}})
	if _, e := m.SyncSaved(context.Background(), s.SourceID); !errors.Is(e, ErrRateLimited) {
		t.Fatal(e)
	}
	m.Close()
	m2, e := Open(nodes, path)
	if e != nil {
		t.Fatal(e)
	}
	defer m2.Close()
	m2.now = func() time.Time { return testTime.Add(time.Minute) }
	calls := 0
	m2.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(200, goodURI, nil), nil })}
	if _, e := m2.SyncSaved(context.Background(), s.SourceID); !errors.Is(e, ErrDeferred) || calls != 0 {
		t.Fatal(e, calls)
	}
	v, _ := m2.Saved(s.SourceID)
	if v.NextRefreshAt.Before(testTime.Add(time.Hour)) || !v.LastKnownGood {
		t.Fatal(v)
	}
	// Editing a subscription interval must not override a server's embargo.
	_, e = m2.Save(context.Background(), s.SourceID, SaveRequest{Request: Request{URL: "https://feed.example.org/private-path-token?secret=query-token", Limit: 128}, Enabled: true, Revision: v.Revision, RefreshIntervalMinutes: 15})
	if e != nil {
		t.Fatal(e)
	}
	v, _ = m2.Saved(s.SourceID)
	if v.NextRefreshAt.Before(testTime.Add(time.Hour)) {
		t.Fatal(v)
	}
}
func TestPendingAttemptWrittenBeforeFetch(t *testing.T) {
	m, _, path := persistentManager(t)
	s := saveFeed(t, m, true)
	m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		image, e := m.storage.target.Read(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		doc, e := decodeDocument(image)
		if e != nil {
			t.Fatal(e)
		}
		if len(doc.States) != 1 || doc.States[0].State.Status != "fetching" || doc.States[0].State.LastAttemptAt.IsZero() || doc.States[0].State.NextRefreshAt.Before(testTime.Add(15*time.Minute)) {
			t.Fatal("no crash reservation", path)
		}
		return response(200, goodURI, nil), nil
	})}
	if _, e := m.SyncSaved(context.Background(), s.SourceID); e != nil {
		t.Fatal(e)
	}
}
func TestDemandRefillAllowlistAndDedup(t *testing.T) {
	m, _, _ := persistentManager(t)
	s := saveFeed(t, m, true)
	// Worker is deliberately not running network for this scheduling test.
	m.jobs = jobState{started: true, entries: map[string]*jobEntry{}, wake: make(chan struct{}, 1)}
	if d, e := m.RequestRefill(context.Background(), []string{"unknown"}); e != nil || d.State != "no-enabled-source" {
		t.Fatal(d, e)
	}
	d, e := m.RequestRefill(context.Background(), []string{s.SourceID, s.SourceID})
	if e != nil || d.State != "queued" {
		t.Fatal(d, e)
	}
	m.RequestRefill(context.Background(), []string{s.SourceID})
	if len(m.jobs.entries) != 1 {
		t.Fatal("duplicate")
	}
}
func TestWorkerWaitsForAdmissionRatherThanFailingSource(t *testing.T) {
	m, _, _ := persistentManager(t)
	s := saveFeed(t, m, true)
	setResponse(m, 200, goodURI, nil)
	count := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.StartManaged(ctx, func(context.Context) (func(), error) {
		count++
		if count < 3 {
			return nil, operationgate.ErrBusy
		}
		return func() {}, nil
	})
	j, e := m.QueueSync(s.SourceID)
	if e != nil {
		t.Fatal(e)
	}
	done := waitJob(t, m, j.ID)
	if done.Status != "completed" || count < 3 {
		t.Fatal(done, count)
	}
	cancel()
	wait, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	if e := m.Wait(wait); e != nil {
		t.Fatal(e)
	}
}
func TestRetryAfterBounds(t *testing.T) {
	for _, s := range []string{"-1", "garbage", "0", "3600", "9223372036854775807"} {
		until := retryAfter(s, testTime)
		if !until.IsZero() && (!until.After(testTime) || until.After(testTime.Add(MaxRefreshMinutes*time.Minute))) {
			t.Fatal(s, until)
		}
	}
}
