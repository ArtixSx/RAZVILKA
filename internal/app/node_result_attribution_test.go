package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNodeResultAttribution(t *testing.T) {
	for _, mode := range []string{"current", "service", "node", "route", "profile", "old-start", "stale", "expired", "future", "reversed", "long-ttl", "empty-profile"} {
		t.Run(mode, func(t *testing.T) {
			finished := time.Now().UTC()
			started := finished.Add(-time.Second)
			result := dataplane.NodeCheckResult{
				NodeID: "node-unit", ServiceID: "service-unit", RoutePathID: "xray:node-unit", NetworkProfile: "wan-unit",
				StartedAt: started, FinishedAt: finished, ExpiresAt: finished.Add(time.Minute),
				Available: true, Verdict: evidence.VerdictPass, TestLevel: "service", Stage: "service", LatencyMS: 12,
				ProbeID: "node-check-0123456789abcdef01234567", CleanupStatus: dataplane.NodeCleanupVerified,
				DirectControl: "measured", ProxyEgressError: "dial_timeout", ServiceErrorCategory: "service_timeout",
				Stages: []dataplane.NodeCheckStage{{ID: "transport", Status: "passed", Duration: 12}},
			}
			observation := nodeCheckObservation{ServiceID: "service-unit", StartedAt: started, FinishedAt: finished}
			profile := "wan-unit"
			switch mode {
			case "service":
				result.ServiceID = "other"
			case "node":
				result.NodeID = "other"
			case "route":
				result.RoutePathID = "sing-box:node-unit"
			case "profile":
				result.NetworkProfile = "other"
			case "old-start":
				result.StartedAt = started.Add(-time.Second)
			case "stale":
				result.StartedAt, result.FinishedAt = finished.Add(-6*time.Minute), finished.Add(-6*time.Minute)
			case "expired":
				result.ExpiresAt = finished
			case "future":
				result.FinishedAt = finished.Add(time.Second)
			case "reversed":
				result.FinishedAt = started.Add(-time.Second)
			case "long-ttl":
				result.ExpiresAt = finished.Add(25 * time.Hour)
			case "empty-profile":
				profile = ""
			}
			row := nodeCheckItemFromResult("node-unit", profile, result, nil, "xray", observation)
			ping := screenPing("node-unit", profile, result, "xray", observation, true)
			if mode == "current" || mode == "old-start" {
				if !row.Available || len(row.Stages) != 1 || !row.CleanupVerified || !ping.Reachable {
					t.Fatal("current observation lost", row, ping)
				}
				return
			}
			if row.Available || len(row.Stages) != 0 || row.CleanupVerified || row.Stage != "" || row.ProbeID != "" || row.DirectControl != "" || row.ProxyEgressError != "" || row.ServiceErrorCategory != "" || !row.ExpiresAt.IsZero() || row.DurationMS != 0 || ping.NodeID != "" {
				t.Fatal("unattributed result escaped", row, ping)
			}
			result.ErrorCode = "node-cleanup-failed"
			row = nodeCheckItemFromResult("node-unit", profile, result, dataplane.ErrExactNodeUnavailable, "xray", observation)
			if row.Available || row.CleanupVerified || row.CleanupStatus != dataplane.NodeCleanupFailed || row.ErrorCode != "node-cleanup-failed" || row.Verdict != "INCONCLUSIVE" || len(row.Stages) != 0 {
				t.Fatal("unsafe cleanup hidden", row)
			}
		})
	}
}

func TestNodePartialScreenAttribution(t *testing.T) {
	for _, mode := range []string{"current", "service", "old-start", "future-start", "finished", "expiry", "cleanup", "unknown-stage-status"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			o := nodeCheckObservation{ServiceID: "service-unit", StartedAt: now.Add(-time.Second), FinishedAt: now}
			r := dataplane.NodeCheckResult{NodeID: "node-unit", ServiceID: "service-unit", NetworkProfile: "wan-unit", RoutePathID: "xray:node-unit", StartedAt: now,
				Stages: []dataplane.NodeCheckStage{{ID: "transport", Status: "passed", Duration: 12}}}
			switch mode {
			case "service":
				r.ServiceID = "other"
			case "old-start":
				r.StartedAt = o.StartedAt.Add(-time.Second)
			case "future-start":
				r.StartedAt = now.Add(time.Second)
			case "finished":
				r.FinishedAt = now
			case "expiry":
				r.ExpiresAt = now.Add(time.Minute)
			case "cleanup":
				r.ErrorCode = "node-cleanup-failed"
			case "unknown-stage-status":
				r.Stages[0].Status = "other"
			}
			ping := screenPing("node-unit", "wan-unit", r, "xray", o, false)
			if mode == "current" {
				if !ping.Reachable || ping.LatencyMS != 12 || !ping.CheckedAt.Equal(now) || !ping.ExpiresAt.IsZero() || ping.Available {
					t.Fatal("legitimate unfinished screen lost or promoted", ping)
				}
			} else if ping.NodeID != "" {
				t.Fatal("foreign or completed partial screen admitted", ping)
			}
		})
	}
}

// A failed joined screen must stop both a later screen batch and full checks.
type attributionCleanupScreener struct {
	calls, screens atomic.Int32
}

func (*attributionCleanupScreener) Capacity() int                 { return 1 }
func (*attributionCleanupScreener) Recover(context.Context) error { return nil }
func (c *attributionCleanupScreener) Check(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	c.calls.Add(1)
	return dataplane.NodeCheckResult{}, nil
}
func (c *attributionCleanupScreener) ScreenTransport(_ context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, bool, error) {
	c.screens.Add(1)
	r := autofallbackResult(q, false)
	r.ServiceID = "foreign-service"
	r.StartedAt = time.Now().Add(-time.Hour)
	r.ErrorCode = "node-cleanup-failed"
	r.Stages = []dataplane.NodeCheckStage{{ID: "transport", Status: "passed", Duration: 12}}
	return r, false, errors.New("joined cleanup refused")
}
func TestDurableScreenForeignCleanupStopsFurtherWork(t *testing.T) {
	a, request := durableNodeFixture(t, 3)
	checker := &attributionCleanupScreener{}
	a.NodeChecker = checker
	id := enqueueNodeFixture(t, a, request)
	a.runDurableServiceJob(context.Background(), time.Now())
	job := durableJobAt(t, a, id)
	if checker.screens.Load() != 1 || checker.calls.Load() != 0 || !a.Operations.Snapshot().Fenced || job.State != "failed" || job.CleanupOutcome != "unverified" || job.Cursor != 0 {
		t.Fatal("screen cleanup did not fence before later work", checker.screens.Load(), checker.calls.Load(), job)
	}
	for _, node := range request.NodeIDs {
		if len(nodeHistory(t, a, node)) != 0 {
			t.Fatal("foreign result entered history")
		}
	}
	a.runDurableServiceJob(context.Background(), time.Now().Add(time.Minute))
	if checker.screens.Load() != 1 || checker.calls.Load() != 0 {
		t.Fatal("fenced job continued")
	}
	if pings := a.nodeCheckCurrentView()["pings"].([]nodeCheckItem); len(pings) != 0 {
		t.Fatal("foreign screen produced ping", pings)
	}
}

func TestNodeCheckJobAttributionAfterHistoryAdmission(t *testing.T) {
	for _, mode := range []string{"current", "fresh-earlier", "foreign-service", "stale", "foreign-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			a, ids := newNodeJobTest(t, 1)
			a.NodeChecker = jobNodeChecker(func(_ context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				r := autofallbackResult(q, true)
				r.CleanupStatus = dataplane.NodeCleanupVerified
				r.Stages = []dataplane.NodeCheckStage{{ID: "transport", Status: "passed", Duration: 12}}
				switch mode {
				case "fresh-earlier":
					r.StartedAt, r.FinishedAt = time.Now().Add(-2*time.Second), time.Now().Add(-time.Second)
				case "foreign-service", "foreign-cleanup":
					r.ServiceID = "other"
				case "stale":
					r.StartedAt, r.FinishedAt = time.Now().Add(-7*time.Minute), time.Now().Add(-6*time.Minute)
				}
				if mode == "foreign-cleanup" {
					r.ErrorCode = "node-cleanup-failed"
					return r, errors.New("private-checker-error")
				}
				return r, nil
			})
			row := a.runNodeCheckItem(context.Background(), "service", ids[0], a.Catalog.Services[0], "", nil)
			history := nodeHistory(t, a, ids[0])
			if mode == "current" || mode == "fresh-earlier" {
				if !row.Available || !row.CleanupVerified || len(row.Stages) != 1 || len(history) != 1 {
					t.Fatal("accepted fresh result projection changed", row, history)
				}
				return
			}
			if row.Available || row.CleanupVerified || len(row.Stages) != 0 || len(history) != 0 || row.Verdict != "INCONCLUSIVE" {
				t.Fatal("history refusal attributed foreign/stale result", row, history)
			}
			if mode == "foreign-cleanup" && (row.ErrorCode != "node-cleanup-failed" || row.CleanupStatus != dataplane.NodeCleanupFailed) {
				t.Fatal("history refusal hid unsafe cleanup", row)
			}
		})
	}
}
