package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNodeJobTimingPreservesUnknownAndCompletionBoundary(t *testing.T) {
	start := time.Now().UTC()
	admitted := start.Add(2 * time.Second)
	finished := admitted.Add(time.Second)
	observed := finished.Add(8 * time.Second)
	timing := nodeJobTimingView(start, &nodeJobTiming{FirstAdmittedAt: &admitted}, &finished, observed)
	if timing.QueueWaitMS == nil || *timing.QueueWaitMS != 2000 || timing.TotalMS == nil || *timing.TotalMS != 3000 || timing.TotalKind != "enqueue-to-server-completion" {
		t.Fatal("server readback delay changed completion duration")
	}
	unknown := nodeJobTimingView(start, nil, &finished, observed)
	if unknown.QueueWaitMS != nil || unknown.FirstAdmittedAt != nil {
		t.Fatal("restart fabricated admission observation")
	}
	if nodeJobTimingView(time.Time{}, nil, nil, observed) != nil {
		t.Fatal("missing enqueue fabricated timing")
	}
	invalid := start.Add(-time.Second)
	timing = nodeJobTimingView(start, &nodeJobTiming{FirstAdmittedAt: &invalid}, &invalid, observed)
	if timing.QueueWaitMS != nil || timing.TotalMS != nil {
		t.Fatal("clock reversal fabricated elapsed timing")
	}
}
func TestDurableNodeTimingStartsAtActualExclusiveAdmission(t *testing.T) {
	a, q := durableNodeFixture(t, 1)
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := enqueueNodeFixture(t, a, q)
	a.runDurableServiceJob(context.Background(), time.Now())
	before := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if before.Timing == nil || before.Timing.QueueWaitMS != nil || before.Timing.FirstAdmittedAt != nil {
		t.Fatal("queued worker was reported as admitted")
	}
	release()
	a.runDurableServiceJob(context.Background(), time.Now().Add(6*time.Second))
	after := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if after.ID != id || after.State != "completed" || after.Timing == nil || after.Timing.FirstAdmittedAt == nil || after.Timing.QueueWaitMS == nil || after.Timing.TotalMS == nil || after.Timing.TotalKind != "enqueue-to-server-completion" {
		t.Fatal("completed job lost queue/admission timing")
	}
	raw, _ := json.Marshal(a.reconciler.doc)
	if strings.Contains(string(raw), "first_admitted_at") {
		t.Fatal("process timing persisted as recovery authority")
	}
	a.nodeChecks.mu.Lock()
	a.nodeChecks.batchResults = nil
	a.nodeChecks.job = nil
	a.nodeChecks.mu.Unlock()
	historical := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if historical.Timing == nil || historical.Timing.QueueWaitMS != nil {
		t.Fatal("process restart fabricated queue timing")
	}
}
func TestDurableNodeLocalTimingExperiment(t *testing.T) {
	if os.Getenv("RAZVILKA_QUEUE_PERF") != "1" {
		t.Skip("opt-in modeled queue measurement")
	}
	rows := [][]string{{"scenario", "sample", "phase", "queue_to_first_admission_ms", "enqueue_to_server_completion_ms", "http_readback_ms", "completed", "checker_delay_ms"}}
	for _, scenario := range []string{"single", "selected-batch", "all-vless"} {
		t.Run(scenario, func(t *testing.T) {
			var totals []int64
			for sample := 0; sample < 13; sample++ {
				count := 1
				if scenario != "single" {
					count = 2
				}
				a, q := durableNodeFixture(t, count)
				if scenario == "all-vless" {
					q = durableCatalogRequest(t, a)
				}
				a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
					start := time.Now()
					for range 4 {
						select {
						case <-ctx.Done():
							return dataplane.NodeCheckResult{}, ctx.Err()
						case <-time.After(5 * time.Millisecond):
						}
					}
					result := autofallbackResult(request, true)
					result.StartedAt = start
					result.FinishedAt = time.Now()
					result.ExpiresAt = result.FinishedAt.Add(time.Hour)
					result.LatencyMS = result.FinishedAt.Sub(start).Milliseconds()
					result.CleanupStatus = dataplane.NodeCleanupVerified
					return result, nil
				})
				release, err := a.Operations.Exclusive(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				id := enqueueNodeFixture(t, a, q)
				a.runDurableServiceJob(context.Background(), time.Now())
				time.Sleep(10 * time.Millisecond)
				release()
				for i := 0; i < count+1; i++ {
					a.runDurableServiceJob(context.Background(), time.Now().Add(time.Duration(i+1)*6*time.Second))
					if durableJobAt(t, a, id).State == "completed" {
						break
					}
				}
				readStart := time.Now()
				response := controlRequest(a, "GET", "/api/v1/node-checks/current", nil)
				readElapsed := time.Since(readStart)
				var view struct{ Job nodeCheckJob }
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &view) != nil || view.Job.State != "completed" || view.Job.Timing == nil || view.Job.Timing.QueueWaitMS == nil || view.Job.Timing.TotalMS == nil {
					t.Fatalf("readback failed HTTP%d", response.Code)
				}
				phase := "repeated"
				if sample == 0 {
					phase = "first-fixture"
				} else {
					totals = append(totals, *view.Job.Timing.TotalMS)
				}
				rows = append(rows, []string{scenario, strconv.Itoa(sample), phase, strconv.FormatInt(*view.Job.Timing.QueueWaitMS, 10), strconv.FormatInt(*view.Job.Timing.TotalMS, 10), fmt.Sprintf("%.3f", float64(readElapsed)/float64(time.Millisecond)), strconv.Itoa(view.Job.Completed), "20"})
			}
			sort.Slice(totals, func(i, j int) bool { return totals[i] < totals[j] })
			t.Logf("modeled queue N=%d p50=%dms p95=%dms", len(totals), totals[5], totals[11])
		})
	}
	if path := os.Getenv("RAZVILKA_QUEUE_PERF_CSV"); path != "" {
		file, err := os.Create(path)
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
}
