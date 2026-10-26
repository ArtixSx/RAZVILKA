package app

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// nodeCheckQuota models the dispatcher: one non-blocking quota shared by
// the checks and screens of every engine view, refused as busy beyond it.
type nodeCheckQuota struct {
	gate                      chan struct{}
	mu                        sync.Mutex
	busy, inflight, maxFlight int
}

func (q *nodeCheckQuota) enter() bool {
	select {
	case q.gate <- struct{}{}:
	default:
		q.mu.Lock()
		q.busy++
		q.mu.Unlock()
		return false
	}
	q.mu.Lock()
	q.inflight++
	q.maxFlight = max(q.maxFlight, q.inflight)
	q.mu.Unlock()
	time.Sleep(10 * time.Millisecond) // overlap work started together
	return true
}

func (q *nodeCheckQuota) leave() {
	q.mu.Lock()
	q.inflight--
	q.mu.Unlock()
	<-q.gate
}

func (q *nodeCheckQuota) counts() (busy, maxFlight int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.busy, q.maxFlight
}

// quotaNodeChecker is one engine view of a nodeCheckQuota. Dead nodes fail
// screening; refused nodes are rejected before the quota, as production
// Sing-box rejects XHTTP material; every other node passes its check.
type quotaNodeChecker struct {
	engine                     string
	quota                      *nodeCheckQuota
	dead, refuse               map[string]bool
	mu                         sync.Mutex
	checked, screened, refused []string
	probes                     atomic.Int64
}

func (c *quotaNodeChecker) EngineID() string            { return c.engine }
func (*quotaNodeChecker) Recover(context.Context) error { return nil }
func (c *quotaNodeChecker) Capacity() int               { return cap(c.quota.gate) }

func (c *quotaNodeChecker) admit(r dataplane.NodeCheckRequest) error {
	c.mu.Lock()
	refused := c.refuse[r.NodeID]
	if refused {
		c.refused = append(c.refused, r.NodeID)
	}
	c.mu.Unlock()
	if refused {
		return dataplane.ErrExactNodeUnsupported
	}
	if !c.quota.enter() {
		return dataplane.ErrExactNodeBusy
	}
	return nil
}

func (c *quotaNodeChecker) result(r dataplane.NodeCheckRequest) dataplane.NodeCheckResult {
	now := time.Now().UTC()
	result := dataplane.NodeCheckResult{ProbeID: fmt.Sprintf("probe-quota-%s-%d", c.engine, c.probes.Add(1)), NodeID: r.NodeID, ServiceID: r.Service.ID,
		NetworkProfile: r.NetworkProfile, RoutePathID: c.engine + ":" + r.NodeID, StartedAt: now.Add(-time.Second), FinishedAt: now,
		ExpiresAt: now.Add(30 * time.Minute), Stage: "service", TestLevel: "service", Verdict: evidence.VerdictPass, Available: true, DirectControl: "measured", Message: "Проверка завершена."}
	return modeledNodeServiceProof(result, c.engine)
}

func (c *quotaNodeChecker) Check(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	if err := c.admit(r); err != nil {
		return dataplane.NodeCheckResult{}, err
	}
	defer c.quota.leave()
	c.mu.Lock()
	c.checked = append(c.checked, r.NodeID)
	c.mu.Unlock()
	return c.result(r), nil
}

func (c *quotaNodeChecker) ScreenTransport(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, bool, error) {
	if err := c.admit(r); err != nil {
		return dataplane.NodeCheckResult{}, false, err
	}
	defer c.quota.leave()
	c.mu.Lock()
	c.screened = append(c.screened, r.NodeID)
	dead := c.dead[r.NodeID]
	c.mu.Unlock()
	result := c.result(r)
	result.Available, result.Stage, result.TestLevel = false, "transport", "transport"
	if !dead {
		result.Stages = []dataplane.NodeCheckStage{{ID: "transport", Status: "passed", Duration: 12}}
		return result, false, nil
	}
	result.Verdict, result.ErrorCode = evidence.VerdictError, "node-transport-failed"
	result.Stages = []dataplane.NodeCheckStage{{ID: "transport", Status: "failed", Duration: 3000}}
	return result, true, nil
}

func (c *quotaNodeChecker) calls() (checked, screened, refused []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Sorted(slices.Values(c.checked)), slices.Sorted(slices.Values(c.screened)), slices.Sorted(slices.Values(c.refused))
}

// useQuotaEngines installs both engine views on one quota, the Xray history
// admission and the given installed executors. Sing-box refuses XHTTP nodes.
func useQuotaEngines(t *testing.T, a *App, xhttp string, installed ...string) (*quotaNodeChecker, *quotaNodeChecker) {
	t.Helper()
	quota := &nodeCheckQuota{gate: make(chan struct{}, 2)}
	sing := &quotaNodeChecker{engine: "sing-box", quota: quota, refuse: map[string]bool{xhttp: true}}
	xray := &quotaNodeChecker{engine: "xray", quota: quota}
	a.NodeChecker = sing
	a.NodeCheckers = map[string]dataplane.NodeChecker{"sing-box": sing, "xray": xray}
	a.NodeHistoryWriteGuard = func(ctx context.Context, version int) error {
		if version != nodestore.XrayHistoryReadVersion {
			t.Error("wrong history admission version", version)
		}
		return ctx.Err()
	}
	a.nodeReviews.options = func() []routecatalog.Option {
		options := []routecatalog.Option{}
		for _, id := range installed {
			options = append(options, routecatalog.Option{ID: id, Installed: true})
		}
		return options
	}
	return sing, xray
}

// importXHTTPNode adds the canonical XHTTP fixture, which only Xray runs.
func importXHTTPNode(t *testing.T, a *App) string {
	t.Helper()
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, autonomyXHTTPURI, time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range snapshot.Nodes {
		if node.Transport == "xhttp" {
			return node.ID
		}
	}
	t.Fatal("canonical XHTTP fixture missing")
	return ""
}

func nodeHistory(t *testing.T, a *App, id string) []nodestore.CheckRecord {
	t.Helper()
	snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range snapshot.Nodes {
		if node.ID == id {
			return node.Health.History
		}
	}
	t.Fatal("node missing", id)
	return nil
}

// A service check of selected nodes never leads to Apply, so an XHTTP node
// is checked by Xray instead of being refused by the Sing-box default. When
// Xray cannot take it, Sing-box still reports its own refusal as before.
func TestCheckOnlyServiceJobChecksXHTTPWithXray(t *testing.T) {
	for _, xrayInstalled := range []bool{true, false} {
		t.Run(fmt.Sprint("xray-installed=", xrayInstalled), func(t *testing.T) {
			a, ids := newNodeJobTest(t, 1)
			xhttp := importXHTTPNode(t, a)
			installed := []string{"sing-box"}
			if xrayInstalled {
				installed = append(installed, "xray")
			}
			sing, xray := useQuotaEngines(t, a, xhttp, installed...)
			if w := postNodeJob(t, a, []string{ids[0], xhttp}, "service"); w.Code != 202 {
				t.Fatalf("start: %d %s", w.Code, w.Body.String())
			}
			job := joinNodeJob(t, a)
			rows := map[string]nodeCheckItem{}
			for _, item := range job.Results {
				rows[item.NodeID] = item
			}
			singChecked, _, singRefused := sing.calls()
			xrayChecked, _, _ := xray.calls()
			if len(rows) != 2 || !rows[ids[0]].Available || !slices.Equal(singChecked, []string{ids[0]}) {
				t.Fatalf("Sing-box node changed: rows=%+v sing=%v", rows, singChecked)
			}
			history := nodeHistory(t, a, xhttp)
			if !xrayInstalled {
				if rows[xhttp].Available || rows[xhttp].ErrorCode != "node-runtime-unsupported" || len(xrayChecked) != 0 || !slices.Equal(singRefused, []string{xhttp}) || len(history) != 0 {
					t.Fatalf("missing Xray did not keep the Sing-box refusal: %+v xray=%v refused=%v history=%v", rows[xhttp], xrayChecked, singRefused, history)
				}
				return
			}
			if !rows[xhttp].Available || rows[xhttp].Verdict != "PASS" || rows[xhttp].ErrorCode != "" || !slices.Equal(xrayChecked, []string{xhttp}) || len(singRefused) != 0 {
				t.Fatalf("XHTTP not checked by Xray: %+v xray=%v refused=%v", rows[xhttp], xrayChecked, singRefused)
			}
			if len(history) != 1 || history[0].RoutePathID != "xray:"+xhttp {
				t.Fatalf("XHTTP proof not bound to Xray: %+v", history)
			}
		})
	}
}

// A durable node check screens and checks an XHTTP node with Xray, next to
// Sing-box nodes on the same shared quota.
func TestDurableNodeCheckScreensAndChecksXHTTPWithXray(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	ids := request.NodeIDs
	xhttp := importXHTTPNode(t, a)
	request.NodeIDs = append(slices.Clone(ids), xhttp)
	sing, xray := useQuotaEngines(t, a, xhttp, "sing-box", "xray")
	sing.dead = map[string]bool{ids[1]: true}
	id := enqueueNodeFixture(t, a, request)
	a.runDurableServiceJob(context.Background(), time.Now())
	j := durableJobAt(t, a, id)
	view := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.State != "completed" || j.Cursor != 3 || view.Completed != 3 || view.Passed != 2 {
		t.Fatalf("cursor %d state %s completed %d passed %d", j.Cursor, j.State, view.Completed, view.Passed)
	}
	for _, item := range view.Results {
		if item.NodeID == xhttp && (!item.Available || item.ErrorCode != "") || item.NodeID == ids[1] && item.ErrorCode != "node-transport-failed" {
			t.Fatalf("wrong row: %+v", item)
		}
	}
	singChecked, singScreened, singRefused := sing.calls()
	xrayChecked, xrayScreened, _ := xray.calls()
	if !slices.Equal(xrayScreened, []string{xhttp}) || !slices.Equal(xrayChecked, []string{xhttp}) || len(singRefused) != 0 ||
		!slices.Equal(singScreened, slices.Sorted(slices.Values(ids))) || !slices.Equal(singChecked, []string{ids[0]}) {
		t.Fatalf("wrong executor: xray=%v/%v sing=%v/%v refused=%v", xrayScreened, xrayChecked, singScreened, singChecked, singRefused)
	}
	if history := nodeHistory(t, a, xhttp); len(history) != 1 || history[0].RoutePathID != "xray:"+xhttp {
		t.Fatalf("XHTTP proof not bound to Xray: %+v", history)
	}
}

// Paths that can lead to Apply keep the Sing-box binding; they never switch
// executors without the autopilot's consent gate.
func TestApplyCapableNodeChecksKeepSingBoxForXHTTP(t *testing.T) {
	a, _ := serviceControlFixture(t, 1)
	xhttp := importXHTTPNode(t, a)
	sing, xray := useQuotaEngines(t, a, xhttp, "sing-box", "xray")
	startControlFixture(t, a, "select", []string{xhttp})
	job := joinNodeJob(t, a)
	if len(job.ServiceResults) != 1 || job.ServiceResults[0].Available || job.ServiceResults[0].RecommendedNodeID != "" {
		t.Fatalf("selection recommended an unchecked executor: %+v", job.ServiceResults)
	}
	if _, _, err := a.checkAndRecordNode(context.Background(), xhttp, a.Catalog.Services[0], "", 0); err == nil {
		t.Fatal("Apply-capable check changed executor")
	}
	_, _, singRefused := sing.calls()
	xrayChecked, xrayScreened, _ := xray.calls()
	if len(xrayChecked) != 0 || len(xrayScreened) != 0 || !slices.Equal(singRefused, []string{xhttp, xhttp}) || len(nodeHistory(t, a, xhttp)) != 0 {
		t.Fatalf("Apply-capable path used Xray: xray=%v refused=%v", xrayChecked, singRefused)
	}
}

// Screens take the shared quota, so a step screens at most its capacity at
// once: no screen is refused as busy and every dead node in the window is
// decided once, by its screen.
func TestDurableNodeScreeningStaysWithinDispatcherQuota(t *testing.T) {
	a, request := durableNodeFixture(t, 10)
	ids := request.NodeIDs
	sing, _ := useQuotaEngines(t, a, "", "sing-box")
	sing.dead = map[string]bool{}
	for _, i := range []int{0, 1, 2, 3, 5, 6, 7} {
		sing.dead[ids[i]] = true
	}
	id := enqueueNodeFixture(t, a, request)
	a.runDurableServiceJob(context.Background(), time.Now())
	j := durableJobAt(t, a, id)
	view := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.State != "queued" || j.Cursor != 9 || view.Completed != 9 || view.Passed != 2 {
		t.Fatalf("first window: cursor %d state %s completed %d passed %d", j.Cursor, j.State, view.Completed, view.Passed)
	}
	for _, item := range view.Results {
		if sing.dead[item.NodeID] != (item.ErrorCode == "node-transport-failed") || item.ErrorCode == "node-check-busy" {
			t.Fatalf("wrong row: %+v", item)
		}
	}
	a.runDurableServiceJob(context.Background(), time.Now().Add(2*time.Second))
	j = durableJobAt(t, a, id)
	view = a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.State != "completed" || j.Cursor != 10 || view.Completed != 10 || view.Passed != 3 {
		t.Fatalf("second window: cursor %d state %s completed %d passed %d", j.Cursor, j.State, view.Completed, view.Passed)
	}
	busy, maxFlight := sing.quota.counts()
	checked, screened, _ := sing.calls()
	if busy != 0 || maxFlight > 2 || !slices.Equal(checked, slices.Sorted(slices.Values([]string{ids[4], ids[8], ids[9]}))) {
		t.Fatalf("busy=%d max=%d checked=%v", busy, maxFlight, checked)
	}
	for node := range sing.dead {
		times := 0
		for _, other := range screened {
			if other == node {
				times++
			}
		}
		if n := len(nodeHistory(t, a, node)); n != 1 || times != 1 {
			t.Fatalf("dead node %s screened %d times, recorded %d results", node, times, n)
		}
	}
}

// If another holder takes the whole quota anyway, a refused screen is not a
// decision: its node gets a full check whose refusal is an explicit row, and
// the cursor stops before nodes nobody checked.
func TestDurableNodeScreeningBusyStaysExplicit(t *testing.T) {
	a, request := durableNodeFixture(t, 6)
	ids := request.NodeIDs
	sing, _ := useQuotaEngines(t, a, "", "sing-box")
	id := enqueueNodeFixture(t, a, request)
	sing.quota.gate <- struct{}{}
	sing.quota.gate <- struct{}{}
	a.runDurableServiceJob(context.Background(), time.Now())
	<-sing.quota.gate
	<-sing.quota.gate
	j := durableJobAt(t, a, id)
	view := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.State != "queued" || j.Cursor != 2 || view.Completed != 2 || view.Passed != 0 || len(view.Results) != 2 {
		t.Fatalf("cursor %d state %s completed %d results %+v", j.Cursor, j.State, view.Completed, view.Results)
	}
	for i, item := range view.Results {
		if item.NodeID != ids[i] || item.Available || item.ErrorCode != "node-check-busy" {
			t.Fatalf("busy check not explicit: %+v", item)
		}
	}
	for _, node := range ids {
		if n := len(nodeHistory(t, a, node)); n != 0 {
			t.Fatalf("busy node %s recorded %d results", node, n)
		}
	}
}
