package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

type connectivityJobChecker struct {
	run func(context.Context, dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error)
}

func (c connectivityJobChecker) Check(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	panic("service check called")
}
func (c connectivityJobChecker) Recover(context.Context) error { return nil }
func (c connectivityJobChecker) CheckConnectivity(ctx context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
	return c.run(ctx, r)
}
func readyConnectivity(r dataplane.NodeConnectivityRequest) dataplane.NodeConnectivityResult {
	now := time.Now().UTC()
	return dataplane.NodeConnectivityResult{NodeID: r.NodeID, NetworkProfile: r.NetworkProfile, Engine: "sing-box", ProbeID: "connectivity-001", CheckedAt: now, ExpiresAt: now.Add(dataplane.NodeConnectivityTTL), Ready: true, CleanupVerified: true, Verdict: evidence.VerdictPass, Stage: "connectivity", HTTPStatus: 204, DirectControl: "measured"}
}

func TestNodeConnectivityDurableJobIsSeparateFromServiceHistory(t *testing.T) {
	a, q := durableNodeFixture(t, 1)
	q.Mode = "connectivity"
	q.ServiceID = ""
	a.NodeChecker = connectivityJobChecker{run: func(_ context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
		return readyConnectivity(r), nil
	}}
	before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	cfg := a.Store.Get()
	id := enqueueNodeFixture(t, a, q)
	a.runDurableServiceJob(context.Background(), time.Now())
	job := durableJobAt(t, a, id)
	if job.State != "completed" || job.Cursor != 1 {
		t.Fatal(job)
	}
	view := a.nodeCheckCurrentView()
	v := view["job"].(*nodeCheckJob)
	if v.Mode != "connectivity" || v.ServiceID != "" || v.Passed != 1 || len(v.Results) != 1 || v.Results[0].Available || !v.Results[0].ConnectivityReady || !v.Results[0].CleanupVerified || v.Results[0].TestLevel != "connectivity" {
		t.Fatalf("job=%+v", v)
	}
	if rows := view["connectivity"].([]nodeCheckItem); len(rows) != 1 || !rows[0].ConnectivityReady {
		t.Fatal(rows)
	}
	after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	if before.Generation != after.Generation || !reflect.DeepEqual(cfg, a.Store.Get()) {
		t.Fatal("common probe wrote history/settings")
	}
}

func TestNodeConnectivityRejectsServiceFeedAndUnownedInputs(t *testing.T) {
	a, q := durableNodeFixture(t, 1)
	q.Mode = "connectivity"
	if validNodeCheckJobRequest(q) {
		t.Fatal("nonempty service accepted")
	}
	q.ServiceID = ""
	if !validNodeCheckJobRequest(q) {
		t.Fatal("explicit common selection rejected")
	}
	q.FeedID = "feed-fixture"
	if validNodeCheckJobRequest(q) {
		t.Fatal("connectivity fetch accepted")
	}
	q.FeedID = ""
	a.NodeChecker = connectivityJobChecker{run: func(context.Context, dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
		t.Fatal("unowned runtime invoked")
		return dataplane.NodeConnectivityResult{}, nil
	}}
	row := a.runNodeConnectivity(context.Background(), q.NodeIDs[0], "wan-0123456789ab")
	if row.ConnectivityReady || row.CleanupVerified || row.ErrorCode != "node-resource-refused" {
		t.Fatal(row)
	}
}

func TestNodeConnectivityExcludedTargetStartsNoRuntime(t *testing.T) {
	a, q := durableNodeFixture(t, 1)
	q.Mode = "connectivity"
	q.ServiceID = ""
	installNodeResourcePolicy(t, a, []config.ResourceMatch{{Kind: "exact", Value: "www.gstatic.com"}}, false)
	rev := a.Store.Get().Revision
	q.ExpectedRevision = &rev
	a.NodeChecker = connectivityJobChecker{run: func(context.Context, dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
		t.Fatal("excluded target probed")
		return dataplane.NodeConnectivityResult{}, nil
	}}
	id := enqueueNodeFixture(t, a, q)
	a.runDurableServiceJob(context.Background(), time.Now())
	if j := durableJobAt(t, a, id); j.State != "completed" {
		t.Fatal(j)
	}
	row := a.nodeCheckCurrentView()["job"].(*nodeCheckJob).Results[0]
	if row.ConnectivityReady || row.ErrorCode != "node-resource-refused" {
		t.Fatal(row)
	}
}

func TestNodeConnectivityClosesStopAndCleanupBeforeReady(t *testing.T) {
	for _, kind := range []string{"stop", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			a, q := durableNodeFixture(t, 1)
			q.Mode = "connectivity"
			q.ServiceID = ""
			if kind == "stop" {
				cfg := a.Store.Get()
				cfg.AppliedServices = map[string]config.ServiceState{"telegram": {Enabled: true, Route: "direct"}}
				path := filepath.Join(t.TempDir(), "config.json")
				raw, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				a.Store, err = config.Load(path)
				if err != nil {
					t.Fatal(err)
				}
				rev := a.Store.Get().Revision
				q.ExpectedRevision = &rev
			}
			a.NodeChecker = connectivityJobChecker{run: func(_ context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
				v := readyConnectivity(r)
				if kind == "stop" {
					if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": "direct"}, a.Store.Get().Revision); err != nil {
						t.Fatal(err)
					}
				} else {
					v.Ready = false
					v.CleanupVerified = false
					v.Stage = "cleanup"
					v.ErrorCode = "node-cleanup-failed"
				}
				return v, nil
			}}
			id := enqueueNodeFixture(t, a, q)
			a.runDurableServiceJob(context.Background(), time.Now())
			for _, row := range a.nodeCheckSnapshot()["connectivity"].([]nodeCheckItem) {
				if row.ConnectivityReady || row.CleanupVerified {
					t.Fatal("late failure promoted", row)
				}
			}
			if kind == "cleanup" && !a.Operations.Snapshot().Fenced {
				t.Fatal("cleanup gap did not fence")
			}
			_ = durableJobAt(t, a, id)
		})
	}
}

func TestNodeConnectivityCacheExpiresAndNeverStoresServiceAvailability(t *testing.T) {
	a := &App{}
	now := time.Now().UTC()
	a.rememberNodeConnectivityLocked(nodeCheckItem{NodeID: "node-fixture", TestLevel: "connectivity", CheckedAt: now, ExpiresAt: now.Add(dataplane.NodeConnectivityTTL), ConnectivityReady: true, CleanupVerified: true})
	if len(a.nodeConnectivitySnapshotLocked(now)) != 1 {
		t.Fatal("missing current observation")
	}
	if len(a.nodeConnectivitySnapshotLocked(now.Add(dataplane.NodeConnectivityTTL))) != 0 {
		t.Fatal("expired observation reused")
	}
}

func TestNodeConnectivityTransportFailuresReachBoundedWriter(t *testing.T) {
	a, q := durableNodeFixture(t, 1)
	q.Mode = "connectivity"
	q.ServiceID = ""
	calls := 0
	a.NodeChecker = connectivityJobChecker{run: func(_ context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
		calls++
		v := readyConnectivity(r)
		v.Ready, v.Stage, v.ErrorCode, v.DirectControl, v.Verdict, v.HTTPStatus = false, "transport", "node-transport-failed", "not_run", evidence.VerdictError, 0
		v.ProbeID = fmt.Sprintf("transport-check-%d", calls)
		return v, nil // ExactNodeChecker's real transport-failure contract.
	}}
	for i := 0; i < 2; i++ {
		q.IdempotencyKey = fmt.Sprintf("connectivity-transport-request-%d", i)
		id := enqueueNodeFixture(t, a, q)
		a.runDurableServiceJob(context.Background(), time.Now())
		if j := durableJobAt(t, a, id); j.State != "completed" {
			t.Fatal(j)
		}
	}
	if len(a.nodeChecks.connectivityTransportFailures) != 1 {
		t.Fatal("missing writer key", a.nodeChecks.connectivityTransportFailures)
	}
	for _, rows := range a.nodeChecks.connectivityTransportFailures {
		if len(rows) != 2 || rows[0].ProbeID == rows[1].ProbeID || !rows[0].CleanupVerified || !rows[1].CleanupVerified {
			t.Fatal("missing verified pair", rows)
		}
		a.rememberNodeConnectivityLocked(rows[1])
		if len(a.nodeChecks.connectivityTransportFailures[q.NodeIDs[0]+"\x00sing-box\x00"+rows[1].NetworkProfile]) != 2 {
			t.Fatal("duplicate probe changed pair")
		}
		positive := rows[1]
		positive.ProbeID = "fresh-ready"
		positive.ConnectivityReady = true
		positive.ErrorCode = ""
		positive.Stage = "connectivity"
		positive.DirectControl = "measured"
		positive.Verdict = "PASS"
		a.rememberNodeConnectivityLocked(positive)
	}
	if len(a.nodeChecks.connectivityTransportFailures) != 0 {
		t.Fatal("positive did not clear its pair")
	}
}
