package main

import (
	"context"
	"errors"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

// Classify failures that happen before a result exists without serializing the
// error text: runtime errors can contain private endpoints or profile values.
func safeCheckerError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "node-check-canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "node-check-deadline"
	case errors.Is(err, dataplane.ErrExactNodeNetworkChanged):
		return "node-network-changed"
	case errors.Is(err, dataplane.ErrExactNodeBusy):
		return "node-checker-busy"
	case errors.Is(err, dataplane.ErrExactNodeRuntime):
		return "node-runtime-unavailable"
	case errors.Is(err, dataplane.ErrExactNodeUnavailable):
		return "node-checker-unavailable"
	default:
		return "node-check-failed"
	}
}

func safeNodeID(id string) string {
	if len(id) == 69 && strings.HasPrefix(id, "node-") && strings.Trim(id[5:], "0123456789abcdef") == "" {
		return id
	}
	return ""
}

func safeStage(stage string) string {
	switch stage {
	case "dns", "transport", "configuration", "protocol", "egress", "service", "service_ip", "route_identity", "cleanup", "deadline", "canceled", "unsupported":
		return stage
	default:
		return "unknown"
	}
}

func safeVerdict(v evidence.Verdict) string {
	switch v {
	case evidence.VerdictPass, evidence.VerdictPartial, evidence.VerdictBlocked, evidence.VerdictMisrouted, evidence.VerdictInconclusive, evidence.VerdictError:
		return string(v)
	default:
		return "INCONCLUSIVE"
	}
}

func safeCheckCode(code string) string {
	switch code {
	case "", "node-dns-failed", "node-transport-failed", "node-runtime-config-rejected", "node-protocol-start-failed", "node-egress-failed", "node-direct-leak",
		"node-service-failed", "node-service-ip-path-failed", "node-service-not-confirmed", "node-route-mismatch", "node-cleanup-failed", "node-network-changed", "node-check-deadline", "node-check-canceled",
		"node-route-runtime-changed", "node-route-identity-failed", "node-route-owner-missing", "node-route-config-mismatch", "node-route-process-mismatch":
		return code
	default:
		return "node-check-failed"
	}
}

// Only closed diagnostic identifiers and nonnegative durations cross the report
// boundary. Runtime messages may contain private endpoints or profile values.
type safeTimingStage struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
}

func safeTimings(stages []dataplane.NodeCheckStage) []safeTimingStage {
	var out []safeTimingStage
	for _, stage := range stages {
		if len(out) == 32 {
			break
		}
		if stage.Duration < 0 {
			continue
		}
		switch stage.ID {
		case "dns", "transport", "tcp_connect", "configuration", "runtime_start", "runtime_ready", "protocol", "egress", "service", "service_ip", "route_identity", "cleanup":
		default:
			continue
		}
		status := ""
		switch stage.Status {
		case "passed", "failed", "skipped":
			status = stage.Status
		default:
			continue
		}
		out = append(out, safeTimingStage{ID: stage.ID, Status: status, DurationMS: max(stage.Duration, 0)})
	}
	return out
}
