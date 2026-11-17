//go:build linux && !razvilka_native_fixture

package app

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nativecheckfixture"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Embedding preserves actual Capacity/EngineID/ScreenTransport and Recover.
// Only completed original Check observations are copied for CSV publication.
type nativeMeasuredChecker struct {
	measureNetwork bool
	t              *testing.T
	*dataplane.ExactNodeChecker
	mu      sync.Mutex
	results []dataplane.NodeCheckResult
}

func (c *nativeMeasuredChecker) Check(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	var observations *probecheck.NetworkMeasurements
	if c.measureNetwork {
		ctx, observations = probecheck.WithNetworkMeasurements(ctx)
		defer observations.Close()
	}
	result, err := c.ExactNodeChecker.Check(ctx, r)
	if observations != nil {
		raw, _ := json.Marshal(observations.Close())
		c.t.Logf("actual_service_network_phases=%s diagnostic_only=true", raw)
	}
	c.mu.Lock()
	c.results = append(c.results, result)
	c.mu.Unlock()
	return result, err
}

func TestNativeVLESSQueueHTTPPerformance(t *testing.T) {
	if os.Getenv("RAZVILKA_NODE_NATIVE_PERF") != "1" {
		t.Skip("requires check-node-native-performance.sh")
	}
	// Script supplies a fresh private mount namespace and tmpfs /opt, then execs
	// THIS controller at the production fixed path. No fake history grant.
	executable, err := os.Executable()
	if err != nil || executable != "/opt/bin/razvilka" {
		t.Fatal("requires installed test controller in disposable /opt")
	}
	fixture := nativecheckfixture.Start(t)
	for _, p := range []string{"/opt/etc/razvilka", "/opt/razvilka/state", "/opt/etc/razvilka/nodes"} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := config.Load("/opt/etc/razvilka/config.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open("/opt/etc/razvilka/nodes")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	profiles := fixture.NodeURL + "\n" + strings.Replace(fixture.NodeURL, "@"+nativecheckfixture.ServerIP+":", "@node.example:", 1)
	snapshot, err := nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, profiles, time.Now(), time.Hour, false)
	if err != nil || len(snapshot.Nodes) != 2 {
		t.Fatalf("import native profiles: %v nodes=%d", err, len(snapshot.Nodes))
	}
	var ids []string
	for _, node := range snapshot.Nodes {
		ids = append(ids, node.ID)
	}
	sort.Strings(ids)
	checker := &nativeMeasuredChecker{measureNetwork: os.Getenv("RAZVILKA_NODE_PERF_QUEUE_PROFILE") == "1", t: t, ExactNodeChecker: dataplane.NewExactXrayNodeCheckerSlots(filepath.Join(fixture.Root, "client"), 1)}
	checker.Binary, checker.Port = fixture.Binary, 29185
	checker.FreshProfile = func(context.Context) (string, error) { return nativecheckfixture.Profile, nil }
	history := updatecheck.NewNodeHistoryAdmission(nodestore.RequiredPrivateHistoryReadVersion, nodestore.ExactHistoryReadVersion)
	if err := history.CheckWrite(context.Background(), nodestore.ExactHistoryReadVersion); err != nil {
		t.Fatalf("actual original controller history admission: %v", err)
	}
	a := &App{Store: store, Nodes: nodes, FreshProfile: checker.FreshProfile, NodeChecker: checker, NodeCheckers: map[string]dataplane.NodeChecker{"xray": checker}, NodeHistoryWriteGuard: history.CheckWrite, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Fixture", ProbeURL: fixture.ProbeURL, Strategy: []string{"xray"}}}}}
	for _, id := range ids {
		selected, err := a.compatibleNodeEngine(context.Background(), "sing-box", id)
		if err != nil || selected != "xray" {
			t.Fatalf("actual installed inventory/canonical profile dispatch failed: engine=%s error=%v", selected, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.StartNodeChecks(ctx)
	t.Cleanup(func() {
		cancel()
		stop, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if err := a.WaitNodeChecks(stop); err != nil {
			t.Error(err)
		}
	})
	initReconcilerFixture(t, a, time.Now())
	a.reconciler.doc.Operations = futureNodeQueueOperations(time.Now())
	for i := range a.reconciler.doc.Operations {
		a.reconciler.doc.Operations[i].ConfigFingerprint = automationConfigFingerprint(store.Get())
		a.reconciler.doc.Operations[i].Reason = "scheduled"
	}
	if err := a.persistReconcilerLocked(ctx); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	exchange := func(method, path string, body any) ([]byte, int) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		request, err := http.NewRequest(method, server.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return data, response.StatusCode
	}
	rows := [][]string{{"scenario", "sample", "phase", "post_started_utc", "post_to_http_readback_monotonic_ms", "queue_wait_ms", "enqueue_to_server_completion_ms", "readback_http_ms", "http_received_utc", "completed", "native_checks", "cleanup", "check_results_json"}}
	rows[0] = append(rows[0], nativecheckfixture.ResourceCSVHeaders...)
	for _, scenario := range []string{"single", "selected-batch", "all-vless"} {
		var samples []float64
		for sample := 0; sample < 13; sample++ {
			fixture.SetService("live", 40*time.Millisecond)
			revision := store.Get().Revision
			request := nodeCheckJobRequest{NodeIDs: ids, Mode: "service", ServiceID: "telegram", ExpectedRevision: &revision, IdempotencyKey: fmt.Sprintf("native-perf-%s-%02d", scenario, sample)}
			if scenario == "single" {
				request.NodeIDs = ids[:1]
			}
			if scenario == "all-vless" {
				request = durableCatalogRequest(t, a)
				request.IdempotencyKey = fmt.Sprintf("native-perf-%s-%02d", scenario, sample)
			}
			checker.mu.Lock()
			before := len(checker.results)
			checker.mu.Unlock()
			release, err := a.Operations.Exclusive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			resources, err := nativecheckfixture.StartResourceSample()
			if err != nil {
				release()
				t.Fatal("queue resource observation", err)
			}
			defer resources.Stop()
			start := time.Now()
			data, status := exchange("POST", "/api/v1/node-checks", request)
			if status != 202 {
				release()
				t.Fatalf("enqueue HTTP%d %s", status, data)
			}
			// Real controlled queue residence BEFORE the first dispatcher admission;
			// no fake time advancement, no second queue and no busy retry shortening.
			time.Sleep(25 * time.Millisecond)
			release()
			var view struct{ Job nodeCheckJob }
			deadline := time.Now().Add(90 * time.Second)
			for {
				a.runDurableServiceJob(ctx, time.Now())
				readStart := time.Now()
				data, status = exchange("GET", "/api/v1/node-checks/current", nil)
				received := time.Now()
				if status != 200 || json.Unmarshal(data, &view) != nil {
					t.Fatalf("readback HTTP%d", status)
				}
				if view.Job.State == "completed" {
					usage, resourceErr := resources.Stop()
					if resourceErr != nil {
						t.Fatal("queue resource closing observation", resourceErr)
					}
					if view.Job.Timing == nil || view.Job.Timing.QueueWaitMS == nil || view.Job.Timing.TotalMS == nil || view.Job.Timing.TotalKind != "enqueue-to-server-completion" {
						t.Fatal("missing original admission/completion span")
					}
					checker.mu.Lock()
					results := append([]dataplane.NodeCheckResult(nil), checker.results[before:]...)
					checker.mu.Unlock()
					count := 2
					if scenario == "single" {
						count = 1
					}
					if len(results) != count || view.Job.Passed != count {
						t.Fatalf("native checker not used/passed: calls=%d passed=%d job=%+v", len(results), view.Job.Passed, view.Job)
					}
					for _, result := range results {
						if !result.Available || result.CleanupStatus != dataplane.NodeCleanupVerified {
							t.Fatalf("native completion/cleanup missing: %+v", result)
						}
					}
					phase := "repeated"
					if sample == 0 {
						phase = "first-scenario-check"
					} else {
						samples = append(samples, float64(received.Sub(start))/float64(time.Millisecond))
					}
					encoded, _ := json.Marshal(results)
					row := []string{scenario, strconv.Itoa(sample), phase, start.UTC().Format(time.RFC3339Nano), fmt.Sprintf("%.3f", float64(received.Sub(start))/float64(time.Millisecond)), strconv.FormatInt(*view.Job.Timing.QueueWaitMS, 10), strconv.FormatInt(*view.Job.Timing.TotalMS, 10), fmt.Sprintf("%.3f", float64(received.Sub(readStart))/float64(time.Millisecond)), received.UTC().Format(time.RFC3339Nano), strconv.Itoa(view.Job.Completed), strconv.Itoa(len(results)), "verified", string(encoded)}
					rows = append(rows, append(row, usage.CSV()...))
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("native queue did not finish: %+v", view.Job)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		sort.Float64s(samples)
		t.Logf("current original App queue+native Check+HTTP delivery scenario=%s repeated N=%d p50=%.3fms p95=%.3fms controlled queue25ms; not browser paint", scenario, len(samples), samples[5], samples[11])
	}
	output := os.Getenv("RAZVILKA_NODE_PERF_OUTPUT")
	if output == "" {
		t.Fatal("output directory required")
	}
	file, err := os.Create(filepath.Join(output, "queue-http-current.csv"))
	if err != nil {
		t.Fatal(err)
	}
	writer := csv.NewWriter(file)
	err = writer.WriteAll(rows)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
}
