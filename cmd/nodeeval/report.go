package main

import (
	"strings"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

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
