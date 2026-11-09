package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestEarlyCheckerFailureReportsClosedReasonAndStops(t *testing.T) {
	for _, row := range []struct {
		err  error
		code string
	}{
		{dataplane.ErrExactNodeNetworkChanged, "node-network-changed"},
		{dataplane.ErrExactNodeBusy, "node-checker-busy"},
		{dataplane.ErrExactNodeUnavailable, "node-checker-unavailable"},
		{dataplane.ErrExactNodeRuntime, "node-runtime-unavailable"},
		{context.Canceled, "node-check-canceled"},
		{context.DeadlineExceeded, "node-check-deadline"},
		{errors.New("private-endpoint"), "node-check-failed"},
	} {
		t.Run(row.code, func(t *testing.T) {
			store := privateStoreFixture(t, 2)
			checker := &checkerFixture{engine: "xray", check: func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				return dataplane.NodeCheckResult{}, fmt.Errorf("private-profile: %w", row.err)
			}}
			var out bytes.Buffer
			code := evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) { return "wan-0123456789ab", nil }, 2, json.NewEncoder(&out))
			reports := decodeReports(t, out.Bytes())
			if code != 1 || len(reports) != 2 || reports[0].Code != row.code || reports[0].HTTPSPass || reports[1].Finished || reports[1].Code != "checker-error" || checker.checks != 1 || checker.recovers != 1 || strings.Contains(out.String(), "private-") {
				t.Fatal("early error lost classification, leaked data or continued", code, reports)
			}
		})
	}
}

func TestEvaluationTimingsAreSafeAndIncludeCleanup(t *testing.T) {
	store := privateStoreFixture(t, 2)
	checker := &checkerFixture{engine: "xray"}
	checker.check = func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		time.Sleep(12 * time.Millisecond) // Models the whole synchronous check, including cleanup.
		result := positiveFixture(r, "xray")
		result.Stages = []dataplane.NodeCheckStage{
			{ID: "runtime_ready", Status: "passed", Duration: 7, Message: "private-node password"},
			{ID: "cleanup", Status: "failed", Duration: 5, Message: "private-node password"},
			{ID: "service", Status: "private-status", Duration: -1},
			{ID: "private-node", Status: "passed", Duration: 99},
		}
		result.Stage, result.ErrorCode = "cleanup", "node-cleanup-failed"
		return result, nil
	}
	var out bytes.Buffer
	code := evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) {
		time.Sleep(3 * time.Millisecond)
		return "wan-0123456789ab", nil
	}, 2, json.NewEncoder(&out))
	rows := decodeReports(t, out.Bytes())
	if code != 1 || len(rows) != 2 || checker.checks != 1 || rows[0].HTTPSPass || rows[1].Finished {
		t.Fatal("timings altered cleanup failure semantics", code, rows)
	}
	candidate := rows[0]
	if candidate.PreparationMS < 3 || candidate.CheckMS < 12 || candidate.ElapsedMS < candidate.CheckMS || rows[1].ElapsedMS < candidate.ElapsedMS {
		t.Fatal("wall timings omit preparation/check/cleanup", rows)
	}
	if len(candidate.Stages) != 2 || candidate.Stages[0].ID != "runtime_ready" || candidate.Stages[1].DurationMS != 5 || strings.Contains(out.String(), "private-") {
		t.Fatal("unsafe or lost timing data", out.String())
	}
}

func TestCandidateWaitIncludesPriorCheckAndTimingCountIsBounded(t *testing.T) {
	store := privateStoreFixture(t, 2)
	checker := &checkerFixture{engine: "xray", check: func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		time.Sleep(10 * time.Millisecond)
		result := positiveFixture(r, "xray")
		for range 100 {
			result.Stages = append(result.Stages, dataplane.NodeCheckStage{ID: "service", Status: "passed", Duration: 1})
		}
		return result, nil
	}}
	var out bytes.Buffer
	code := evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) { return "wan-0123456789ab", nil }, 2, json.NewEncoder(&out))
	rows := decodeReports(t, out.Bytes())
	if code != 0 || len(rows) != 3 || rows[1].WaitMS < rows[0].CheckMS || rows[0].CheckMS < 10 || len(rows[0].Stages) != 32 {
		t.Fatal("sequential wait or bounded report failed", code, rows)
	}
}

func TestUnmatchedResultCannotAttributeStagesToRequestedNode(t *testing.T) {
	for _, mismatch := range []string{"node", "service", "engine", "profile", "stale", "future", "expired"} {
		t.Run(mismatch, func(t *testing.T) {
			store := privateStoreFixture(t, 2)
			checker := &checkerFixture{engine: "xray", check: func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				time.Sleep(5 * time.Millisecond)
				result := positiveFixture(r, "xray")
				result.Stages = []dataplane.NodeCheckStage{{ID: "service", Status: "passed", Duration: 12345}, {ID: "cleanup", Status: "passed", Duration: 12345}}
				switch mismatch {
				case "node":
					result.NodeID = "node-" + strings.Repeat("f", 64)
				case "service":
					result.ServiceID = "different-service"
				case "engine":
					result.RoutePathID = "sing-box:" + r.NodeID
				case "profile":
					result.NetworkProfile = "different-profile"
				case "stale":
					result.StartedAt = result.StartedAt.Add(-time.Hour)
				case "future":
					result.FinishedAt = result.FinishedAt.Add(time.Hour)
				case "expired":
					result.ExpiresAt = result.ExpiresAt.Add(-2 * time.Hour)
				}
				return result, nil
			}}
			var out bytes.Buffer
			code := evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) {
				time.Sleep(2 * time.Millisecond)
				return "wan-0123456789ab", nil
			}, 2, json.NewEncoder(&out))
			rows := decodeReports(t, out.Bytes())
			if code != 2 || len(rows) != 3 || !rows[2].Finished || rows[2].Passed != 0 {
				t.Fatal("mismatched evidence affected completion or acceptance", code, rows)
			}
			for _, candidate := range rows[:2] {
				if candidate.Fresh || candidate.HTTPSPass || len(candidate.Stages) != 0 || candidate.NodeID == "" || candidate.CheckMS < 5 || candidate.PreparationMS < 2 {
					t.Fatal("foreign stages published or owned wrapper observations lost", candidate)
				}
			}
			if rows[1].WaitMS < rows[0].CheckMS || strings.Contains(out.String(), `"stages":`) {
				t.Fatal("foreign timing retained or sequential wait omitted", rows)
			}
		})
	}
}
