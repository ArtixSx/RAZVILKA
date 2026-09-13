package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type testNodePinger func(context.Context, []byte) dataplane.NodePingResult

func (f testNodePinger) Ping(ctx context.Context, raw []byte) dataplane.NodePingResult {
	return f(ctx, raw)
}

type jobNodeChecker func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error)

func (f jobNodeChecker) Check(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	return f(ctx, request)
}
func (jobNodeChecker) Recover(context.Context) error { return nil }

func newNodeJobTest(t *testing.T, count int) (*App, []string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var profiles []string
	for i := 0; i < count; i++ {
		profiles = append(profiles, fmt.Sprintf("vless://123e4567-e89b-12d3-a456-426614174000@node%d.example:443?security=tls&sni=node%d.example", i, i))
	}
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, strings.Join(profiles, "\n"), time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(snapshot.Nodes))
	for i, node := range snapshot.Nodes {
		ids[i] = node.ID
	}
	a := &App{Nodes: store, FreshProfile: stableNodeProfile, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", ProbeURL: "https://telegram.org/"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	a.StartNodeChecks(ctx)
	t.Cleanup(func() {
		cancel()
		stop, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		if err := a.WaitNodeChecks(stop); err != nil {
			t.Error(err)
		}
	})
	return a, ids
}

func postNodeJob(t *testing.T, a *App, ids []string, mode string) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(nodeCheckJobRequest{NodeIDs: ids, Mode: mode, ServiceID: "telegram"})
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/node-checks", strings.NewReader(string(raw))))
	return w
}

func joinNodeJob(t *testing.T, a *App) *nodeCheckJob {
	t.Helper()
	a.nodeChecks.mu.Lock()
	done := a.nodeChecks.done
	a.nodeChecks.mu.Unlock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("job did not finish")
	}
	return a.nodeCheckSnapshot()["job"].(*nodeCheckJob)
}

func TestNodeCheckTCPBatchIsBoundedPassiveAndRetainsAdmission(t *testing.T) {
	a, ids := newNodeJobTest(t, 4)
	before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	entered := make(chan struct{}, 4)
	finish := make(chan struct{})
	var active, peak atomic.Int32
	a.NodePinger = testNodePinger(func(ctx context.Context, raw []byte) dataplane.NodePingResult {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		entered <- struct{}{}
		select {
		case <-finish:
		case <-ctx.Done():
		}
		return dataplane.NodePingResult{Reachable: true, LatencyMS: 37, Message: "TCP отвечает."}
	})
	w := postNodeJob(t, a, ids, "tcp")
	if w.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("HTTP return released job admission")
	}
	if duplicate := postNodeJob(t, a, ids, "tcp"); duplicate.Code != http.StatusConflict {
		t.Fatal("overlapping job admitted")
	}
	close(finish)
	job := joinNodeJob(t, a)
	if job.State != "completed" || job.Completed != 4 || peak.Load() != 2 {
		t.Fatalf("bad batch: %+v peak %d", job, peak.Load())
	}
	after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	if !reflect.DeepEqual(before, after) {
		t.Fatal("TCP success changed node proof or persistent state")
	}
	if len(a.nodeCheckSnapshot()["pings"].([]nodeCheckItem)) != 4 {
		t.Fatal("passive ping cache missing")
	}
	for _, item := range job.Results {
		if !item.Reachable || item.Available || item.LatencyMS != 37 || item.DurationMS != 0 {
			t.Fatalf("TCP became service authority: %+v", item)
		}
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("finished job retained admission")
	} else {
		release()
	}
}

func TestNodeCheckServiceCancelRemainsAvailableAndJoinsCleanup(t *testing.T) {
	a, ids := newNodeJobTest(t, 3)
	entered, cleaning, finishCleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, _ dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(cleaning)
		<-finishCleanup
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	if w := postNodeJob(t, a, ids, "service"); w.Code != http.StatusAccepted {
		t.Fatalf("start %d %s", w.Code, w.Body.String())
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("check did not start")
	}
	if release, err := a.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("service job lacks exclusive admission")
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		w := httptest.NewRecorder()
		path := "/api/v1/node-checks/current"
		if method == http.MethodDelete {
			path += fmt.Sprintf("?job_id=%d", a.nodeCheckSnapshot()["job"].(*nodeCheckJob).ID)
		}
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(method, path, nil))
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status/cancel blocked: %d", w.Code)
		}
	}
	select {
	case <-cleaning:
	case <-time.After(time.Second):
		t.Fatal("cancel did not reach checker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if a.WaitNodeChecks(ctx) == nil {
		t.Fatal("shutdown failed to join pending cleanup")
	}
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("cleanup admission released early")
	}
	close(finishCleanup)
	job := joinNodeJob(t, a)
	if job.State != "canceled" || calls.Load() != 1 {
		t.Fatalf("cancellation advanced queue: %+v calls %d", job, calls.Load())
	}
	if w := postNodeJob(t, a, ids, "tcp"); w.Code != http.StatusServiceUnavailable {
		t.Fatal("shutdown accepted new work")
	}
}

func TestNodeCheckTCPStaleEpochRevokesPassiveSuccess(t *testing.T) {
	a, ids := newNodeJobTest(t, 1)
	var changed atomic.Bool
	a.FreshProfile = func(context.Context) (string, error) {
		if changed.Load() {
			return "wan-abcdef012345", nil
		}
		return "wan-0123456789ab", nil
	}
	a.NodePinger = testNodePinger(func(context.Context, []byte) dataplane.NodePingResult {
		changed.Store(true)
		return dataplane.NodePingResult{Reachable: true, LatencyMS: 21, Message: "TCP отвечает."}
	})
	if w := postNodeJob(t, a, ids, "tcp"); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	job := joinNodeJob(t, a)
	if len(job.Results) != 1 || job.Results[0].Reachable || job.Results[0].LatencyMS != 0 {
		t.Fatalf("stale success retained: %+v", job)
	}
}

func TestNodeCheckServiceFailureDoesNotBecomeAvailable(t *testing.T) {
	a, ids := newNodeJobTest(t, 2)
	var active, peak atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		n := active.Add(1)
		defer active.Add(-1)
		if n > peak.Load() {
			peak.Store(n)
		}
		now := time.Now().UTC()
		return dataplane.NodeCheckResult{ProbeID: "node-check-0123456789abcdef01234567", NodeID: request.NodeID, ServiceID: request.Service.ID, NetworkProfile: request.NetworkProfile, RoutePathID: "sing-box:" + request.NodeID, FinishedAt: now, ExpiresAt: now.Add(time.Minute), Stage: "service", Verdict: evidence.VerdictError, Available: false, TestLevel: "service", LatencyMS: 1000, Message: "Сервис недоступен."}, nil
	})
	if w := postNodeJob(t, a, ids, "service"); w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	job := joinNodeJob(t, a)
	if job.Completed != 2 || peak.Load() != 1 {
		t.Fatalf("nonsequential service job: %+v", job)
	}
	for _, result := range job.Results {
		if result.Available || result.LatencyMS != 0 || result.DurationMS != 1000 {
			t.Fatalf("bad service result: %+v", result)
		}
	}
	snapshot, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	for _, node := range snapshot.Nodes {
		if node.State == "available" {
			t.Fatal("failed check became selectable")
		}
	}
}

func TestNodeCheckRejectsInvalidBatchBeforeWorker(t *testing.T) {
	a, ids := newNodeJobTest(t, 1)
	a.NodePinger = testNodePinger(func(context.Context, []byte) dataplane.NodePingResult {
		t.Error("invalid batch ran")
		return dataplane.NodePingResult{}
	})
	for _, raw := range []string{
		`{"node_ids":[],"mode":"tcp"}`,
		`{"node_ids":["missing"],"mode":"tcp"}`,
		`{"node_ids":["` + ids[0] + `","` + ids[0] + `"],"mode":"tcp"}`,
		`{"node_ids":["` + ids[0] + `"],"mode":"unsafe"}`,
		`{"node_ids":["` + ids[0] + `"],"mode":"tcp","url":"http://192.168.1.1"}`,
		`{"node_ids":["` + ids[0] + `"],"mode":"tcp"}{}`,
	} {
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/node-checks", strings.NewReader(raw)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid batch status %d", w.Code)
		}
	}
	if a.nodeCheckSnapshot()["job"].(*nodeCheckJob) != nil {
		t.Fatal("invalid batch created job")
	}
}
