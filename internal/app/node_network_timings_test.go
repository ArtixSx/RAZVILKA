package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func TestNodeNetworkTimingsActualHTTPOriginalInvocation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("private-service-response"))
	}))
	defer server.Close()
	for _, mode := range []string{"current", "old-result", "foreign-service", "foreign-route", "canceled", "forged-only"} {
		t.Run(mode, func(t *testing.T) {
			a, ids := newNodeJobTest(t, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.NodeChecker = jobNodeChecker(func(checkCtx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				started := time.Now().UTC()
				if mode != "forged-only" {
					client := probecheck.TimingClient(checkCtx, server.Client())
					req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, server.URL, nil)
					if err != nil {
						t.Fatal(err)
					}
					response, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_, err = io.Copy(io.Discard, response.Body)
					closeErr := response.Body.Close()
					if err != nil || closeErr != nil {
						t.Fatal(err, closeErr)
					}
				}
				r := autofallbackResult(request, false)
				r.StartedAt, r.FinishedAt = started, time.Now().UTC()
				r.CleanupStatus = dataplane.NodeCleanupVerified
				r.NetworkTimings = []probecheck.NetworkTiming{{Kind: "private-checker-secret", Sequence: 1}}
				switch mode {
				case "old-result":
					r.StartedAt = started.Add(-time.Minute)
				case "foreign-service":
					r.ServiceID = "other"
				case "foreign-route":
					r.RoutePathID = "xray:" + request.NodeID
				case "canceled":
					cancel()
					return r, context.Canceled
				}
				return r, nil
			})
			row := a.runNodeCheckItem(ctx, "service", ids[0], a.Catalog.Services[0], "", nil)
			if row.Available {
				t.Fatal("timing promoted failed service", row)
			}
			if mode == "current" {
				if len(row.NetworkTimings) != 1 || !row.NetworkTimings[0].TLS.Observed || !row.NetworkTimings[0].Body.Observed || row.NetworkTimings[0].BodyBytes != int64(len("private-service-response")) {
					t.Fatal("actual TLS/body timings lost", row.NetworkTimings)
				}
			} else if len(row.NetworkTimings) != 0 {
				t.Fatal("foreign or arbitrary timing published", mode, row.NetworkTimings)
			}
			raw, err := json.Marshal(row)
			if err != nil || strings.Contains(string(raw), "private-") || strings.Contains(string(raw), server.URL) {
				t.Fatal("private material entered timing DTO")
			}
			history, err := json.Marshal(nodeHistory(t, a, ids[0]))
			if err != nil || strings.Contains(string(history), "network_timings") {
				t.Fatal("diagnostic changed durable history")
			}
		})
	}
}

func TestNodeNetworkTimingsClosedCopyAndSnapshots(t *testing.T) {
	row := probecheck.NetworkTiming{Sequence: 1, Kind: "service-http", Status: "failed", TLS: probecheck.NetworkPhase{Observed: true, Status: "incomplete", DurationUS: 10}}
	for _, mode := range []string{"valid", "kind", "status", "phase", "negative", "missing", "sequence"} {
		r := row
		switch mode {
		case "kind":
			r.Kind = "secret"
		case "status":
			r.Status = "secret"
		case "phase":
			r.TLS.Status = "secret"
		case "negative":
			r.TotalUS = -1
		case "missing":
			r.TLS.Observed = false
		case "sequence":
			r.Sequence = 2
		}
		got := closedNodeNetworkTimings([]probecheck.NetworkTiming{r})
		if (len(got) == 1) != (mode == "valid") {
			t.Fatal(mode, got)
		}
	}
	rows := make([]probecheck.NetworkTiming, 40)
	for i := range rows {
		rows[i] = row
		rows[i].Sequence = i + 1
	}
	if len(closedNodeNetworkTimings(rows)) != 32 {
		t.Fatal("unbounded timeline")
	}
	a := &App{}
	job := &nodeCheckJob{ID: 1, Results: []nodeCheckItem{{NetworkTimings: []probecheck.NetworkTiming{row}}}}
	a.nodeChecks.job = job
	a.nodeChecks.batchResults = map[uint64]*nodeCheckJob{1: job}
	snapshot := a.nodeCheckSnapshot()["job"].(*nodeCheckJob)
	snapshot.Results[0].NetworkTimings[0].Status = "changed"
	batch := a.nodeBatchMemoryResults()[1]
	batch.Results[0].NetworkTimings[0].TLS.Status = "changed"
	if job.Results[0].NetworkTimings[0] != row {
		t.Fatal("snapshot aliases original timing")
	}
}
