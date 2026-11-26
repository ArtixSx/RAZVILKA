package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

// Exercise the managed feed worker and AUTO together. The HTTPS subscription is
// served locally. Exact-node verdicts and host route operations are fixtures.
func TestAutonomyDownloadedVLESSRejectSelectRecheckReplace(t *testing.T) {
	ctx := context.Background()
	a, _, adapter := autonomousIntegrationFixture(t)
	before := a.Store.Get()
	client := d10TLSFeedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/approved" {
			http.NotFound(w, r)
			return
		}
		for _, host := range []string{"one.invalid", "two.invalid", "three.invalid"} {
			fmt.Fprintf(w, "vless://123e4567-e89b-12d3-a456-426614174000@%s:443?security=tls\n", host)
		}
	}))
	root := filepath.Join(t.TempDir(), "feeds")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	feeds, err := providerfeed.OpenWithDependencies(a.Nodes, root, client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	a.NodeFeeds = feeds
	source, err := feeds.Save(ctx, "", providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.test/approved", Limit: 3}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, stop := context.WithCancel(ctx)
	a.StartNodeFeeds(workerCtx)
	t.Cleanup(func() {
		stop()
		join, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := a.WaitNodeFeeds(join); err != nil {
			t.Error(err)
		}
		if err := feeds.Close(); err != nil {
			t.Error(err)
		}
	})
	job, err := feeds.QueueSync(source.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	job = d10WaitFeedJob(t, feeds, job.ID)
	if job.Status != "completed" || job.Result == nil || len(job.Result.NodeIDs) != 3 {
		t.Fatal("managed source failed to import the three candidates", job.Status, job.ErrorCode)
	}
	ids := slices.Clone(job.Result.NodeIDs)
	slices.Sort(ids)
	d10Options(a, ids)
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.SourceIDs = []string{source.SourceID}
	err = a.persistAutonomyLocked(ctx)
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	rejected := map[string]bool{ids[0]: true}
	var checks []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if !slices.Contains(ids, req.NodeID) {
			t.Fatal("AUTO checked a node outside the approved feed")
		}
		checks = append(checks, req.NodeID)
		return d10Result(req, "sing-box", !rejected[req.NodeID]), nil
	})
	const service = "my-independent-site"
	checkRoute := func(id string) {
		t.Helper()
		cfg := a.Store.Get()
		route := cfg.AppliedServices[service]
		if selectedRoute(route) != "sing-box:"+id || !slices.Equal(route.Sources, []string{"192.168.1.50/32"}) || !reflect.DeepEqual(cfg.Services["youtube"], before.Services["youtube"]) {
			t.Fatal("selected node, device scope or unrelated service changed unexpectedly")
		}
	}
	a.autonomyRound(ctx, time.Now())
	if !slices.Equal(checks, ids[:2]) || !slices.Contains(adapter.calls, "commit") {
		t.Fatal("first rejected, then usable candidate were not checked before commit", len(checks), autonomyTestState(a).State)
	}
	checkRoute(ids[1])
	checks, adapter.calls = nil, nil
	autonomyTestDue(a, false)
	a.autonomyRound(ctx, time.Now())
	if !slices.Contains(checks, ids[1]) || slices.Contains(adapter.calls, "commit") || autonomyTestState(a).State != "healthy" {
		t.Fatal("a healthy assigned node did not survive recheck")
	}
	checkRoute(ids[1])
	rejected[ids[1]] = true
	checks, adapter.calls = nil, nil
	autonomyTestDue(a, false)
	a.autonomyRound(ctx, time.Now())
	if autonomyTestState(a).Failures != 1 || slices.Contains(adapter.calls, "commit") {
		t.Fatal("one service rejection caused premature replacement")
	}
	checkRoute(ids[1])
	checks = nil
	autonomyTestDue(a, true)
	a.autonomyRound(ctx, time.Now())
	if !slices.Contains(checks, ids[2]) || !slices.Contains(adapter.calls, "canary") || !slices.Contains(adapter.calls, "commit") {
		t.Fatal("replacement missing fresh exact-node check or guarded commit", autonomyTestState(a).State)
	}
	checkRoute(ids[2])
}
