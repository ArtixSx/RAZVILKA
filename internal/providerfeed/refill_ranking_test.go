package providerfeed

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func rankedRefillFixture(t *testing.T) (*Manager, []string, string) {
	t.Helper()
	m, _, path := persistentManager(t)
	var ids []string
	for _, label := range []string{"a", "b", "c"} {
		v, err := m.Save(context.Background(), "", SaveRequest{Request: Request{URL: "https://feed.example.org/" + label, Limit: 32}, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, v.SourceID)
		c := m.states[v.SourceID]
		c.state.LastAttemptAt = testTime.Add(-20 * time.Minute)
		c.state.NextRefreshAt = testTime.Add(time.Hour)
		m.states[v.SourceID] = c
	}
	if err := m.persistLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.jobs = jobState{started: true, entries: map[string]*jobEntry{}, wake: make(chan struct{}, 1)}
	return m, ids, path
}

func TestRankedRefillUsefulSourceDoesNotBypassConsentCooldownOrAging(t *testing.T) {
	for _, scenario := range []string{"useful", "retry-after", "minimum-pause", "failure", "aging", "untried", "disabled", "not-allowed"} {
		t.Run(scenario, func(t *testing.T) {
			m, ids, _ := rankedRefillFixture(t)
			useful := map[string]int{ids[0]: 10, ids[1]: 1, ids[2]: 0}
			allowed := ids
			want := ids[0]
			first, second := m.states[ids[0]], m.states[ids[1]]
			switch scenario {
			case "retry-after":
				first.state.RetryAfterAt = testTime.Add(time.Hour)
				want = ids[1]
			case "minimum-pause":
				first.state.LastAttemptAt = testTime.Add(-time.Minute)
				want = ids[1]
			case "failure":
				m.storage.doc.Sources[m.sourceIndexLocked(ids[0])].Failures = 1
				first.state.NextRefreshAt = testTime.Add(-time.Minute)
				want = ids[1]
			case "aging":
				second.state.LastAttemptAt = testTime.Add(-time.Hour)
				want = ids[1]
			case "untried":
				second.state.LastAttemptAt = time.Time{}
				want = ids[1]
			case "disabled":
				m.storage.doc.Sources[m.sourceIndexLocked(ids[0])].Enabled = false
				want = ids[1]
			case "not-allowed":
				allowed = ids[1:]
				want = ids[1]
			}
			m.states[ids[0]], m.states[ids[1]] = first, second
			decision, err := m.RequestRefillRanked(context.Background(), allowed, useful)
			if err != nil || decision.State != "queued" || decision.SourceID != want || len(m.jobs.queue) != 1 {
				t.Fatal(decision, err)
			}
			// Repeated polling joins this job instead of filling the queue.
			decision, err = m.RequestRefillRanked(context.Background(), allowed, useful)
			if err != nil || decision.SourceID != want || len(m.jobs.queue) != 1 {
				t.Fatal(decision, err)
			}
		})
	}
}

func TestRankedRefillWaitingAndAttemptAgeSurviveRestart(t *testing.T) {
	m, ids, path := rankedRefillFixture(t)
	for _, id := range ids {
		c := m.states[id]
		c.state.RetryAfterAt = testTime.Add(time.Hour)
		m.states[id] = c
	}
	c := m.states[ids[1]]
	c.state.RetryAfterAt = testTime.Add(30 * time.Minute)
	m.states[ids[1]] = c
	if err := m.persistLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	d, err := m.RequestRefillRanked(context.Background(), ids, map[string]int{ids[0]: 512})
	if err != nil || d.State != "waiting" || d.SourceID != ids[1] || len(m.jobs.entries) != 0 {
		t.Fatal(d, err)
	}
	nodes := m.nodes
	m.Close()
	next, err := Open(nodes, path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.now = func() time.Time { return testTime }
	next.jobs = jobState{started: true, entries: map[string]*jobEntry{}, wake: make(chan struct{}, 1)}
	d2, err := next.RequestRefillRanked(context.Background(), ids, map[string]int{ids[0]: 512})
	if err != nil || !reflect.DeepEqual(d, d2) {
		t.Fatal(d2, err)
	}
	next.now = func() time.Time { return testTime.Add(time.Hour) }
	d2, err = next.RequestRefillRanked(context.Background(), ids, map[string]int{ids[0]: 512})
	if err != nil || d2.State != "queued" {
		t.Fatal(d2, err)
	}
}

func TestRefillAbortedWriteCannotLeaveInMemoryDemand(t *testing.T) {
	m, ids, _ := rankedRefillFixture(t)
	before := m.states[ids[0]]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancellation after admission but before the real file CAS.
	m.now = func() time.Time { cancel(); return testTime }
	_, err := m.RequestRefillRanked(ctx, ids, map[string]int{ids[0]: 1})
	if !errors.Is(err, ErrStore) || m.fenced || len(m.jobs.entries) != 0 || !reflect.DeepEqual(before, m.states[ids[0]]) {
		t.Fatal("aborted write changed scheduling", err)
	}
}
