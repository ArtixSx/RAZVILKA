package app

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFetchAndCheckRequestRequiresExactBoundedConsent(t *testing.T) {
	for _, q := range []nodeCheckJobRequest{
		{Mode: "service", ServiceID: "x", Feed: &providerfeed.Request{PresetID: "goida-vless"}},
		{Mode: "tcp", ServiceID: "x", Feed: &providerfeed.Request{}, Confirm: "FETCH_AND_CHECK_NODES"},
		{Mode: "service", Feed: &providerfeed.Request{}, Confirm: "FETCH_AND_CHECK_NODES"},
		{Mode: "service", ServiceID: "x", Feed: &providerfeed.Request{}, NodeIDs: []string{"n"}, Confirm: "FETCH_AND_CHECK_NODES"},
		{Mode: "service", ServiceID: "x", FeedID: "x", Limit: 65, Confirm: "FETCH_AND_CHECK_NODES"},
		{Mode: "service", ServiceID: "x", FeedID: "x", Feed: &providerfeed.Request{}, Confirm: "FETCH_AND_CHECK_NODES"},
	} {
		if validNodeCheckJobRequest(q) {
			t.Fatalf("accepted unsafe request mode=%s", q.Mode)
		}
	}
	if !validNodeCheckJobRequest(nodeCheckJobRequest{Mode: "service", ServiceID: "x", FeedID: "x", Limit: 12, Confirm: "FETCH_AND_CHECK_NODES"}) {
		t.Fatal("valid fetch refused")
	}
	if !validNodeCheckJobRequest(nodeCheckJobRequest{Mode: "tcp", NodeIDs: []string{"n"}}) {
		t.Fatal("legacy explicit checker broken")
	}
}
func TestFetched304ChecksOnlySameSourceWithoutCreatingFreshness(t *testing.T) {
	now := time.Now()
	nodes := []nodestore.Node{
		{ID: "one", Origins: []nodestore.Origin{{SourceID: "a", ReceivedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}},
		{ID: "other", Origins: []nodestore.Origin{{SourceID: "b", ReceivedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}},
		{ID: "expired", Origins: []nodestore.Origin{{SourceID: "a", ReceivedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Second)}}},
		{ID: "disabled", Disabled: true, Origins: []nodestore.Origin{{SourceID: "a", ReceivedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}},
	}
	ids, _ := fetchedCheckNodeIDs(providerfeed.Result{SourceID: "a", NotModified: true}, nodestore.Snapshot{Nodes: nodes}, 12)
	if !slices.Equal(ids, []string{"one"}) {
		t.Fatal(ids)
	}
}
func TestNodeCancelWrongIDCannotCancelAnotherOperation(t *testing.T) {
	a, ids := newNodeJobTest(t, 1)
	entered := make(chan struct{})
	ended := make(chan struct{})
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(ended)
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	w := postNodeJob(t, a, ids, "service")
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	<-entered
	jobID := a.nodeCheckSnapshot()["job"].(*nodeCheckJob).ID
	for _, suffix := range []string{"", fmt.Sprintf("?job_id=%d", jobID+1)} {
		w = httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("DELETE", "/api/v1/node-checks/current"+suffix, nil))
		if w.Code == 200 {
			t.Fatal("cancel accepted without correct ID")
		}
		select {
		case <-ended:
			t.Fatal("wrong cancel reached worker")
		default:
		}
	}
	w = httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/node-checks/current?job_id=%d", jobID), nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	joinNodeJob(t, a)
}
func TestCleanupProtectsReferencesAndGeneration(t *testing.T) {
	a, ids := newNodeJobTest(t, 2)
	var err error
	a.Store, err = config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + ids[0]}); err != nil {
		t.Fatal(err)
	}
	snap, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	call := func(generation uint64, preview bool) *httptest.ResponseRecorder {
		b, _ := json.Marshal(nodeCleanupRequest{NodeIDs: ids, Generation: generation, Mode: "selected", Preview: preview, Confirm: "DELETE_NODES"})
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/nodes/delete-batch", strings.NewReader(string(b))))
		return w
	}
	if w := call(snap.Generation+1, true); w.Code != 409 {
		t.Fatal("stale generation accepted", w.Code, w.Body.String())
	}
	w := call(snap.Generation, true)
	var preview struct{ Candidates, Skipped []nodeCleanupItem }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &preview) != nil || len(preview.Candidates) != 1 || len(preview.Skipped) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call(snap.Generation, false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	if len(after.Nodes) != 1 || after.Nodes[0].ID != ids[0] {
		t.Fatal("deleted referenced node")
	}
	if lease, e := a.Operations.Exclusive(context.Background()); e != nil {
		t.Fatal("cleanup retained lease", e)
	} else {
		lease()
	}
}
func TestCleanupRefusesConcurrentMutation(t *testing.T) {
	a, ids := newNodeJobTest(t, 1)
	a.Store, _ = config.Load(filepath.Join(t.TempDir(), "config.json"))
	snap, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	lease, e := a.Operations.Enter(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer lease()
	b, _ := json.Marshal(nodeCleanupRequest{NodeIDs: ids, Generation: snap.Generation, Mode: "selected", Preview: false, Confirm: "DELETE_NODES"})
	w := httptest.NewRecorder()
	a.nodeCleanup(w, httptest.NewRequest("POST", "/api/v1/nodes/delete-batch", strings.NewReader(string(b))))
	if w.Code != http.StatusConflict {
		t.Fatal(w.Code)
	}
}

// Uses real HTTP handlers, NodeStore, root lifetime and operation gate. Only
// external HTTP and the engine check are substituted; no public nodes are used.
func TestFetchThenCheckRunsAfterBrowserRequestEnds(t *testing.T) {
	a, ids := newNodeJobTest(t, 2)
	a.NodeFeeds = providerfeed.New(a.Nodes)
	entered, proceed := make(chan struct{}), make(chan struct{})
	a.nodeChecks.fetchSource = func(ctx context.Context, request nodeCheckJobRequest) (providerfeed.Result, error) {
		close(entered)
		select {
		case <-proceed:
		case <-ctx.Done():
			return providerfeed.Result{}, ctx.Err()
		}
		return providerfeed.Result{SourceID: "manual", NodeIDs: ids[:1], Imported: 1}, nil
	}
	checked := make(chan string, 2)
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked <- r.NodeID
		return autofallbackResult(r, true), nil
	})
	reqContext, closeBrowser := context.WithCancel(context.Background())
	b, _ := json.Marshal(nodeCheckJobRequest{Mode: "service", ServiceID: "telegram", Confirm: "FETCH_AND_CHECK_NODES", Feed: &providerfeed.Request{PresetID: "goida-vless", Limit: 12}})
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/node-checks", strings.NewReader(string(b))).WithContext(reqContext))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	<-entered
	if a.nodeCheckSnapshot()["job"].(*nodeCheckJob).Phase != "fetching" {
		t.Fatal("fetch phase not visible")
	}
	closeBrowser()
	select {
	case <-checked:
		t.Fatal("checker started before source finished")
	default:
	}
	close(proceed)
	job := joinNodeJob(t, a)
	if job.State != "completed" || job.Total != 1 || job.Completed != 1 || len(job.Results) != 1 || !job.Results[0].Available || job.Results[0].Verdict != "PASS" {
		t.Fatalf("unexpected result: %+v", job)
	}
	if id := <-checked; id != ids[0] {
		t.Fatal("checked an unrelated source member")
	}
	select {
	case <-checked:
		t.Fatal("checked outside returned source")
	default:
	}
	if lease, e := a.Operations.Exclusive(context.Background()); e != nil {
		t.Fatal(e)
	} else {
		lease()
	}
}

func TestCancelDuringSourceFetchDoesNotStartChecker(t *testing.T) {
	a, _ := newNodeJobTest(t, 1)
	a.NodeFeeds = providerfeed.New(a.Nodes)
	entered, cleanup := make(chan struct{}), make(chan struct{})
	a.nodeChecks.fetchSource = func(ctx context.Context, _ nodeCheckJobRequest) (providerfeed.Result, error) {
		close(entered)
		<-ctx.Done()
		close(cleanup)
		return providerfeed.Result{}, ctx.Err()
	}
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Error("checker started after canceled source")
		return dataplane.NodeCheckResult{}, nil
	})
	b, _ := json.Marshal(nodeCheckJobRequest{Mode: "service", ServiceID: "telegram", Confirm: "FETCH_AND_CHECK_NODES", Feed: &providerfeed.Request{PresetID: "goida-vless", Limit: 12}})
	w := httptest.NewRecorder()
	a.nodeCheckJobs(w, httptest.NewRequest("POST", "/api/v1/node-checks", strings.NewReader(string(b))))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	<-entered
	id := a.nodeCheckSnapshot()["job"].(*nodeCheckJob).ID
	w = httptest.NewRecorder()
	a.nodeCheckJobCurrent(w, httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/node-checks/current?job_id=%d", id), nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	job := joinNodeJob(t, a)
	if job.State != "canceled" || job.Completed != 0 {
		t.Fatalf("wrong cancellation %+v", job)
	}
	select {
	case <-cleanup:
	default:
		t.Fatal("cleanup not joined")
	}
}

func TestCleanupControlCannotUseLeakedOrNonAvailablePASS(t *testing.T) {
	now := time.Now()
	n := nodestore.Node{ID: "n", Health: nodestore.Health{History: []nodestore.CheckRecord{{NetworkProfile: "wan", RoutePathID: "sing-box:n", Verdict: "PASS", TestLevel: "service", State: "available", CheckedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}}}}
	s := nodestore.Snapshot{Nodes: []nodestore.Node{n}}
	if !recentCleanupControl(s, "wan", now) {
		t.Fatal("valid control refused")
	}
	s.Nodes[0].Health.History[0].DirectLeak = true
	if recentCleanupControl(s, "wan", now) {
		t.Fatal("leaked path accepted as control")
	}
	s.Nodes[0].Health.History[0].DirectLeak = false
	s.Nodes[0].Health.History[0].State = "unknown"
	if recentCleanupControl(s, "wan", now) {
		t.Fatal("unknown state accepted as control")
	}
}
