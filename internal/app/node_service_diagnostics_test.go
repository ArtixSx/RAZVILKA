package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNodeServiceDTOClosedEgressDiagnosticsPreserveFailure(t *testing.T) {
	for _, mode := range []string{"egress", "hostile", "foreign-node", "foreign-route", "foreign-network", "canceled", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			result := dataplane.NodeCheckResult{
				NodeID: "node-unit", NetworkProfile: "wan-unit", RoutePathID: "sing-box:node-unit",
				ProbeID: "node-check-0123456789abcdef01234567", StartedAt: now.Add(-11 * time.Second), FinishedAt: now,
				ExpiresAt: now.Add(time.Minute), LatencyMS: 11000, TestLevel: "protocol", Stage: "egress",
				Verdict: evidence.VerdictError, ErrorCode: "node-egress-failed", Message: "bounded failure",
				DirectControl: "measured", ProxyEgressError: "dial_timeout", CleanupStatus: dataplane.NodeCleanupVerified,
				Stages: []dataplane.NodeCheckStage{{ID: "transport", Status: "passed", Duration: 10, Message: "private endpoint token secret"}, {ID: "egress", Status: "failed", Duration: 10000}},
			}
			var checkErr error
			switch mode {
			case "hostile":
				result.ProxyEgressError, result.DirectEgressError = "private endpoint token secret", "private endpoint token secret"
				result.Stages = append(result.Stages, dataplane.NodeCheckStage{ID: "private endpoint token secret", Status: "failed"}, dataplane.NodeCheckStage{ID: "egress", Status: "private endpoint token secret"}, dataplane.NodeCheckStage{ID: "egress", Status: "failed", Duration: -1})
			case "foreign-node":
				result.NodeID = "foreign"
			case "foreign-route":
				result.RoutePathID = "xray:node-unit"
			case "foreign-network":
				result.NetworkProfile = "wan-other"
			case "canceled":
				checkErr = context.Canceled
			case "cleanup":
				result.Stage, result.ErrorCode, result.CleanupStatus = "cleanup", "node-cleanup-failed", dataplane.NodeCleanupFailed
			}
			row := nodeCheckItemFromResult("node-unit", "wan-unit", result, checkErr, "sing-box")
			if row.Available || row.ConnectivityReady {
				t.Fatal("diagnostics granted readiness", row)
			}
			if strings.HasPrefix(mode, "foreign-") {
				if row.ProxyEgressError != "" || row.DirectEgressError != "" || len(row.Stages) != 0 {
					t.Fatal("foreign diagnostics admitted", row)
				}
				return
			}
			if len(row.Stages) != 2 || row.Stages[0].Duration != 10 || row.Stages[1].Duration != 10000 || row.DirectControl != "measured" {
				t.Fatal("pre-service timings/control lost", row)
			}
			if mode == "hostile" {
				if row.ProxyEgressError != "unavailable" || row.DirectEgressError != "unavailable" {
					t.Fatal("unknown categories escaped", row)
				}
			} else if row.ProxyEgressError != "dial_timeout" || row.DirectEgressError != "" {
				t.Fatal("closed category lost", row)
			}
			if mode == "cleanup" {
				if row.CleanupVerified || row.CleanupStatus != dataplane.NodeCleanupFailed || row.Verdict != "INCONCLUSIVE" || row.ErrorCode != "node-cleanup-failed" {
					t.Fatal("cleanup refusal changed", row)
				}
			} else if mode == "canceled" {
				if row.Verdict != "INCONCLUSIVE" || row.TestLevel != "unconfirmed" || row.ErrorCode != nodeCheckFailureCode(context.Canceled) {
					t.Fatal("cancellation changed", row)
				}
			} else if row.Verdict != string(result.Verdict) || row.TestLevel != result.TestLevel || row.ErrorCode != result.ErrorCode || row.Stage != "egress" || row.DurationMS != 11000 || !row.CleanupVerified || row.ProbeID != result.ProbeID || !row.ExpiresAt.Equal(result.ExpiresAt) {
				t.Fatal("diagnostics changed failure semantics", row)
			}
			raw, err := json.Marshal(row)
			if err != nil || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "private endpoint") {
				t.Fatal("free-form checker diagnostics escaped")
			}
		})
	}
}
