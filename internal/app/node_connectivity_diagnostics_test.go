package app

import (
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"strings"
	"testing"
	"time"
)

func TestNodeConnectivityDTOClosedDiagnosticsAndReadiness(t *testing.T) {
	for _, mode := range []string{"pass", "failure", "cleanup", "foreign", "hostile"} {
		t.Run(mode, func(t *testing.T) {
			a, q := durableNodeFixture(t, 1)
			a.NodeChecker = connectivityJobChecker{run: func(_ context.Context, req dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
				r := readyConnectivity(req)
				r.Stages = []dataplane.NodeCheckStage{{ID: "egress", Status: "passed", Duration: 123, Message: "private endpoint token secret"}, {ID: "connectivity", Status: "passed", Duration: 45}}
				if mode == "failure" {
					r.Ready = false
					r.Verdict = evidence.VerdictError
					r.Stage = "egress"
					r.ErrorCode = "node-egress-failed"
					r.ProxyEgressError = "tls_timeout"
					r.Stages[0].Status = "failed"
				}
				if mode == "cleanup" {
					r.Ready = false
					r.CleanupVerified = false
					r.Stage = "cleanup"
					r.ErrorCode = "node-cleanup-failed"
					r.Stages = append(r.Stages, dataplane.NodeCheckStage{ID: "cleanup", Status: "failed", Duration: 3})
				}
				if mode == "foreign" {
					r.NodeID = "foreign"
					r.ProxyEgressError = "http_status"
				}
				if mode == "hostile" {
					r.ProxyEgressError = "private endpoint token secret"
					r.DirectEgressError = "private endpoint token secret"
					r.Stages = append(r.Stages, dataplane.NodeCheckStage{ID: "private endpoint token secret", Status: "passed"}, dataplane.NodeCheckStage{ID: "egress", Status: "private endpoint token secret"}, dataplane.NodeCheckStage{ID: "egress", Status: "failed", Duration: -1})
				}
				return r, nil
			}}
			q.Mode, q.ServiceID = "connectivity", ""
			enqueueNodeFixture(t, a, q)
			a.runDurableServiceJob(context.Background(), time.Now())
			job := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
			rows := job.Results
			if mode == "cleanup" {
				rows = a.nodeCheckCurrentView()["connectivity"].([]nodeCheckItem)
			}
			if len(rows) != 1 {
				t.Fatal("missing diagnostic result", job)
			}
			row := rows[0]
			if mode == "foreign" {
				if len(row.Stages) != 0 || row.ProxyEgressError != "" {
					t.Fatal("foreign diagnostics admitted", row)
				}
				return
			}
			if len(row.Stages) < 2 || row.Stages[0].Duration != 123 || row.Stages[1].Duration != 45 {
				t.Fatal("stage timing lost", row)
			}
			if mode == "failure" && (row.ProxyEgressError != "tls_timeout" || row.DirectEgressError != "" || row.ConnectivityReady || !row.CleanupVerified) {
				t.Fatal(row)
			}
			if mode == "pass" && (!row.ConnectivityReady || !row.CleanupVerified || row.Available) {
				t.Fatal(row)
			}
			if mode == "cleanup" && (row.ConnectivityReady || row.CleanupVerified || row.ErrorCode != "node-cleanup-failed") {
				t.Fatal(row)
			}
			if mode == "hostile" && (row.ProxyEgressError != "unavailable" || row.DirectEgressError != "unavailable" || len(row.Stages) != 2) {
				t.Fatal(row)
			}
			raw, _ := json.Marshal(row)
			if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "endpoint") {
				t.Fatal("private checker message escaped", string(raw))
			}
		})
	}
}
func TestNodeConnectivityDiagnosticStagesBounded(t *testing.T) {
	rows := make([]dataplane.NodeCheckStage, 100)
	for i := range rows {
		rows[i] = dataplane.NodeCheckStage{ID: "egress", Status: "failed", Duration: 1}
	}
	if len(closedNodeCheckStages(rows)) != 32 {
		t.Fatal("unbounded diagnostics")
	}
}
