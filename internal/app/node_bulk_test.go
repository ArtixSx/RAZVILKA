package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func bulkTestWait(ctx context.Context, _ time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Millisecond):
		return nil
	}
}
func bulkTestResult(q dataplane.NodeCheckRequest) dataplane.NodeCheckResult {
	now := time.Now().UTC()
	return dataplane.NodeCheckResult{ProbeID: "node-check-0123456789abcdef01234567", NodeID: q.NodeID, ServiceID: q.Service.ID, NetworkProfile: q.NetworkProfile, RoutePathID: "sing-box:" + q.NodeID, FinishedAt: now, ExpiresAt: now.Add(time.Hour), Stage: "service", Verdict: evidence.VerdictPass, Available: true, TestLevel: "service", Message: "test"}
}
func postBulkTest(t *testing.T, a *App, q nodeCheckJobRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(q)
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/node-checks", strings.NewReader(string(raw))))
	return w
}
func allBulkRequest(t *testing.T, a *App) nodeCheckJobRequest {
	t.Helper()
	s, e := a.Nodes.Snapshot(context.Background(), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return nodeCheckJobRequest{Scope: allVLESSScope, Generation: s.Generation, Mode: "service", ServiceID: "telegram", Confirm: "CHECK_ALL_VLESS"}
}
func awaitBulk(t *testing.T, a *App) *nodeCheckJob {
	t.Helper()
	a.nodeChecks.mu.Lock()
	done := a.nodeChecks.done
	a.nodeChecks.mu.Unlock()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("bulk queue did not finish")
	}
	return a.nodeCheckSnapshot()["job"].(*nodeCheckJob)
}
func withBulkConfig(t *testing.T, a *App) {
	t.Helper()
	var e error
	a.Store, e = config.Load(filepath.Join(t.TempDir(), "config.json"))
	if e != nil {
		t.Fatal(e)
	}
}
func TestAllVLESSChecksEntireCatalogueSequentiallyAndBoundsMemory(t *testing.T) {
	a, _ := newNodeJobTest(t, 83)
	a.nodeChecks.bulkWait = bulkTestWait
	var active, peak, calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		n := active.Add(1)
		defer active.Add(-1)
		if n > peak.Load() {
			peak.Store(n)
		}
		c := calls.Add(1)
		r := bulkTestResult(q)
		if c == 2 {
			r.Available = false
			r.Verdict = evidence.VerdictBlocked
		} else if c == 3 {
			r.Available = false
			r.Verdict = evidence.VerdictInconclusive
		}
		return r, nil
	})
	if w := postBulkTest(t, a, allBulkRequest(t, a)); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	j := awaitBulk(t, a)
	if j.Completed != 83 || j.Total != 83 || j.Passed != 81 || j.Failed != 1 || j.Inconclusive != 1 || peak.Load() != 1 || j.State != "completed" || len(j.Results) != 64 {
		t.Fatalf("wrong aggregate: %+v peak=%d", j, peak.Load())
	}
	s, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	for _, n := range s.Nodes {
		if n.Health.CheckedAt.IsZero() {
			t.Fatal("a node beyond page/batch was not recorded")
		}
	}
	if s.Generation != 84 {
		t.Fatal("checks not recorded once per node", s.Generation)
	}
}
func TestAllVLESSScopeOnlyProtocolAndInitialEligibility(t *testing.T) {
	a, ids := newNodeJobTest(t, 4)
	a.nodeChecks.bulkWait = bulkTestWait
	_, e := a.Nodes.Import(context.Background(), nodestore.Source{ID: "extra", Kind: "manual"}, "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@edge.example:8388", time.Now(), time.Hour, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Nodes.SetDisabled(context.Background(), ids[0], true, time.Now()); e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		return bulkTestResult(q), nil
	})
	if w := postBulkTest(t, a, allBulkRequest(t, a)); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	j := awaitBulk(t, a)
	if j.Matched != 4 || j.Total != 3 || j.Completed != 3 || j.Skipped != 1 || calls.Load() != 3 {
		t.Fatalf("protocol scope: %+v", j)
	}
}
func TestAllVLESSStrictSelectorsKeepLegacyBatchLimit(t *testing.T) {
	a, _ := newNodeJobTest(t, 1)
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Error("invalid request ran")
		return dataplane.NodeCheckResult{}, nil
	})
	base := allBulkRequest(t, a)
	cases := []struct {
		name   string
		modify func(*nodeCheckJobRequest)
	}{
		{"missing consent", func(q *nodeCheckJobRequest) { q.Confirm = "" }}, {"no generation", func(q *nodeCheckJobRequest) { q.Generation = 0 }},
		{"other protocol", func(q *nodeCheckJobRequest) { q.Scope = "all-tuic" }}, {"mixed IDs", func(q *nodeCheckJobRequest) { q.NodeIDs = []string{"x"} }},
		{"mixed source", func(q *nodeCheckJobRequest) { q.FeedID = "one" }}, {"mixed limit", func(q *nodeCheckJobRequest) { q.Limit = 64 }},
		{"no service", func(q *nodeCheckJobRequest) { q.ServiceID = "" }}, {"ping", func(q *nodeCheckJobRequest) { q.Mode = "tcp" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := base
			c.modify(&q)
			if w := postBulkTest(t, a, q); w.Code != 400 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	q := base
	q.Generation++
	if w := postBulkTest(t, a, q); w.Code != 409 {
		t.Fatal("stale catalogue not rejected")
	}
	if validNodeCheckJobRequest(nodeCheckJobRequest{Mode: "service", NodeIDs: make([]string, 65)}) {
		t.Fatal("legacy limit raised")
	}
}
func TestAllVLESSReleasesGateBetweenItemsAndFreezesNewImports(t *testing.T) {
	a, _ := newNodeJobTest(t, 2)
	var calls atomic.Int32
	yielded, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	a.nodeChecks.bulkWait = func(ctx context.Context, d time.Duration) error {
		if calls.Load() == 1 {
			once.Do(func() { close(yielded) })
			select {
			case <-proceed:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return bulkTestWait(ctx, d)
	}
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		return bulkTestResult(q), nil
	})
	if w := postBulkTest(t, a, allBulkRequest(t, a)); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	select {
	case <-yielded:
	case <-time.After(3 * time.Second):
		t.Fatal("no node boundary")
	}
	release, e := a.Operations.Exclusive(context.Background())
	if e != nil {
		t.Fatal("queue held gate between nodes", e)
	}
	_, e = a.Nodes.Import(context.Background(), nodestore.Source{ID: "later", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174001@later.example:443?security=tls", time.Now(), time.Hour, false)
	release()
	if e != nil {
		t.Fatal(e)
	}
	close(proceed)
	j := awaitBulk(t, a)
	if j.Total != 2 || j.Completed != 2 || calls.Load() != 2 {
		t.Fatal("new node silently added", j.Total, calls.Load())
	}
}
func TestAllVLESSCancelAndDuplicateKeepCleanupAdmission(t *testing.T) {
	a, _ := newNodeJobTest(t, 3)
	a.nodeChecks.bulkWait = bulkTestWait
	entered, cleaning, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(cleaning)
		<-finish
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	q := allBulkRequest(t, a)
	w := postBulkTest(t, a, q)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	<-entered
	j := a.nodeCheckSnapshot()["job"].(*nodeCheckJob)
	if w := postBulkTest(t, a, q); w.Code != 409 {
		t.Fatal("duplicate admitted", w.Code)
	}
	cancel := func(id uint64) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/node-checks/current?job_id=%d", id), nil))
		return w
	}
	if w := cancel(j.ID + 1); w.Code != 409 {
		t.Fatal("stale cancel accepted")
	}
	if w := cancel(j.ID); w.Code != 200 {
		t.Fatal(w.Code)
	}
	<-cleaning
	if release, e := a.Operations.Exclusive(context.Background()); !errors.Is(e, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("released before cleanup")
	}
	close(finish)
	j = awaitBulk(t, a)
	if j.State != "canceled" || j.Completed != 0 {
		t.Fatal("cancel reported as done", j)
	}
	if release, e := a.Operations.Exclusive(context.Background()); e != nil {
		t.Fatal("gate leaked")
	} else {
		release()
	}
}
func TestAllVLESSStopsOnNetworkChange(t *testing.T) {
	a, _ := newNodeJobTest(t, 3)
	a.nodeChecks.bulkWait = bulkTestWait
	var changed atomic.Bool
	a.FreshProfile = func(context.Context) (string, error) {
		if changed.Load() {
			return "wan-abcdef012345", nil
		}
		return "wan-0123456789ab", nil
	}
	var calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		changed.Store(true)
		return bulkTestResult(q), nil
	})
	if w := postBulkTest(t, a, allBulkRequest(t, a)); w.Code != 202 {
		t.Fatal(w.Code)
	}
	j := awaitBulk(t, a)
	if j.State != "failed" || j.ErrorCode != "BULK_NETWORK_CHANGED" || j.Completed != 0 || calls.Load() != 1 {
		t.Fatal("stale result/continued queue", j)
	}
}
func TestAllVLESSWaitsForDueRecovery(t *testing.T) {
	a, _ := newNodeJobTest(t, 1)
	a.nodeChecks.bulkWait = bulkTestWait
	a.reconciler.started = true
	a.reconciler.doc.Operations = []automationOperation{{Kind: "node-recovery", State: "backoff", NextRun: time.Now().Add(-time.Minute)}}
	var calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		return bulkTestResult(q), nil
	})
	if w := postBulkTest(t, a, allBulkRequest(t, a)); w.Code != 202 {
		t.Fatal(w.Code)
	}
	time.Sleep(25 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("bulk overtook pending recovery")
	}
	a.reconciler.mu.Lock()
	a.reconciler.doc.Operations[0].NextRun = time.Now().Add(time.Minute)
	a.reconciler.mu.Unlock()
	if j := awaitBulk(t, a); j.Completed != 1 {
		t.Fatal(j)
	}
}
func TestAllVLESSRequestOutlivesBrowserAndDefendsStoppedState(t *testing.T) {
	a, _ := newNodeJobTest(t, 2)
	a.nodeChecks.bulkWait = bulkTestWait
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return bulkTestResult(q), nil
	})
	raw, _ := json.Marshal(allBulkRequest(t, a))
	ctx, cancel := context.WithCancel(context.Background())
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/node-checks", strings.NewReader(string(raw))).WithContext(ctx))
	cancel()
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	if j := awaitBulk(t, a); j.Completed != 2 {
		t.Fatal("browser context owned queue")
	}
}

func bulkDeleteCall(t *testing.T, a *App, q nodeCleanupRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(q)
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/nodes/delete-batch", strings.NewReader(string(raw))))
	return w
}
func bulkPreview(t *testing.T, a *App) (nodeCleanupRequest, int, int) {
	t.Helper()
	s, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	q := nodeCleanupRequest{Mode: allVLESSScope, Generation: s.Generation, Confirm: "DELETE_ALL_VLESS", Preview: true}
	w := bulkDeleteCall(t, a, q)
	var p struct {
		Review              string
		Candidates, Skipped []nodeCleanupItem
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	q.Preview = false
	q.Review = p.Review
	return q, len(p.Candidates), len(p.Skipped)
}
func TestDeleteAllVLESSOver64PreservesOtherProtocolAndReferences(t *testing.T) {
	a, ids := newNodeJobTest(t, 83)
	withBulkConfig(t, a)
	if e := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + ids[0]}); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Nodes.CreateGroup(context.Background(), "Reserve", "fallback", []string{ids[1]}, "", time.Minute, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Nodes.Import(context.Background(), nodestore.Source{ID: "other", Kind: "manual"}, "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@edge.example:8388", time.Now(), time.Hour, false); e != nil {
		t.Fatal(e)
	}
	q, n, skipped := bulkPreview(t, a)
	if n != 81 || skipped != 2 {
		t.Fatal(n, skipped)
	}
	before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	if len(before.Nodes) != 84 {
		t.Fatal("preview deleted nodes")
	}
	w := bulkDeleteCall(t, a, q)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, e := a.Nodes.Snapshot(context.Background(), time.Now())
	if e != nil || len(after.Nodes) != 3 || after.Generation != before.Generation+1 {
		t.Fatal("not single atomic deletion", after.Generation, len(after.Nodes), e)
	}
	for _, n := range after.Nodes {
		if strings.EqualFold(n.Protocol, "vless") && n.ID != ids[0] && n.ID != ids[1] {
			t.Fatal("unused VLESS remains")
		}
	}
	if a.Store.Get().Services["telegram"].Route != "sing-box:"+ids[0] {
		t.Fatal("route changed")
	}
	if w := bulkDeleteCall(t, a, q); w.Code != 409 {
		t.Fatal("stale confirmation replayed")
	}
}
func TestDeleteAllVLESSRejectsPreviewDriftAndNoConsent(t *testing.T) {
	for _, kind := range []string{"no-review", "new-import", "reference-changed", "forged-scope"} {
		t.Run(kind, func(t *testing.T) {
			a, ids := newNodeJobTest(t, 2)
			withBulkConfig(t, a)
			q, _, _ := bulkPreview(t, a)
			switch kind {
			case "no-review":
				q.Review = ""
			case "new-import":
				_, _ = a.Nodes.SetAlias(context.Background(), ids[0], "Changed", time.Now())
			case "reference-changed":
				_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + ids[0]})
			case "forged-scope":
				q.NodeIDs = []string{ids[0]}
			}
			w := bulkDeleteCall(t, a, q)
			if w.Code != 400 && w.Code != 409 {
				t.Fatal(w.Code, w.Body.String())
			}
			s, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if len(s.Nodes) != 2 {
				t.Fatal("preview drift deleted nodes")
			}
		})
	}
}
