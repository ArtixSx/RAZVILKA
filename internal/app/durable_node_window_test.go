package app

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

// windowNodeChecker models a checker with parallel slots and transport
// screening. Dead nodes fail screening; every other node passes its check.
type windowNodeChecker struct {
	mu                  sync.Mutex
	capacity            int
	dead                map[string]bool
	checked, screened   []string
	inflight, maxFlight int
}

func (c *windowNodeChecker) Check(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	c.mu.Lock()
	c.inflight++
	c.maxFlight = max(c.maxFlight, c.inflight)
	c.checked = append(c.checked, r.NodeID)
	c.mu.Unlock()
	time.Sleep(20 * time.Millisecond) // overlap parallel checks
	c.mu.Lock()
	c.inflight--
	c.mu.Unlock()
	return autofallbackResult(r, true), nil
}
func (*windowNodeChecker) Recover(context.Context) error { return nil }
func (c *windowNodeChecker) Capacity() int               { return c.capacity }
func (c *windowNodeChecker) ScreenTransport(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, bool, error) {
	c.mu.Lock()
	c.screened = append(c.screened, r.NodeID)
	dead := c.dead[r.NodeID]
	c.mu.Unlock()
	result := autofallbackResult(r, false)
	result.Stage, result.TestLevel = "transport", "transport"
	if !dead {
		result.Stages = []dataplane.NodeCheckStage{{ID: "transport", Status: "passed", Duration: 12}}
		return result, false, nil
	}
	result.Verdict, result.ErrorCode = evidence.VerdictError, "node-transport-failed"
	result.Stages = []dataplane.NodeCheckStage{{ID: "transport", Status: "failed", Duration: 3000}}
	return result, true, nil
}

// One durable step screens a window, records the dead nodes as their full
// check would, checks up to capacity of the rest at once and advances the
// cursor past exactly the nodes it completed; the next step finishes.
func TestDurableNodeCheckWindowScreensAndChecksInParallel(t *testing.T) {
	a, request := durableNodeFixture(t, 8)
	ids := request.NodeIDs
	checker := &windowNodeChecker{capacity: 3, dead: map[string]bool{ids[1]: true, ids[4]: true, ids[6]: true}}
	a.NodeChecker = checker
	id := enqueueNodeFixture(t, a, request)
	a.runDurableServiceJob(context.Background(), time.Now())
	j := durableJobAt(t, a, id)
	if j.State != "queued" || j.Cursor != 5 {
		t.Fatalf("first window cursor %d state %s, want 5 queued", j.Cursor, j.State)
	}
	p := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if p.Completed != 5 || p.Passed != 3 || len(p.Results) != 5 {
		t.Fatalf("first window results: completed=%d passed=%d failed=%d inconclusive=%d results=%d", p.Completed, p.Passed, p.Failed, p.Inconclusive, len(p.Results))
	}
	for _, item := range p.Results {
		if checker.dead[item.NodeID] && (item.Available || item.ErrorCode != "node-transport-failed") {
			t.Fatalf("dead node %s not recorded as its transport failure: %+v", item.NodeID, item)
		}
	}
	if checker.maxFlight > checker.capacity {
		t.Fatalf("%d checks ran at once, capacity %d", checker.maxFlight, checker.capacity)
	}
	for _, node := range checker.checked {
		if checker.dead[node] {
			t.Fatal("a screened dead node still got a full check", node)
		}
	}
	pings := a.nodeCheckCurrentView()["pings"].([]nodeCheckItem)
	if len(pings) != 5 {
		t.Fatalf("screening did not fill pings of the completed window: %d", len(pings))
	}
	a.runDurableServiceJob(context.Background(), time.Now().Add(2*time.Second))
	j = durableJobAt(t, a, id)
	p = a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.State != "completed" || j.Cursor != 8 || p.Completed != 8 || p.Passed != 5 {
		t.Fatalf("second window: cursor %d state %s completed %d passed %d", j.Cursor, j.State, p.Completed, p.Passed)
	}
	if len(checker.checked) != 5 {
		t.Fatalf("full checks %v, want the five live nodes once each", checker.checked)
	}
}
