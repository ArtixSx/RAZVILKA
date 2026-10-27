package app

import "github.com/ArtixSx/razvilka/internal/dataplane"

// Diagnostic stages omit free-form messages from checker plugins. These rows
// describe timing only and never establish readiness or service proof.
type nodeCheckDiagnosticStage struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Duration int64  `json:"duration_ms,omitempty"`
}

func closedNodeEgressError(value string) string {
	switch value {
	case "", "canceled", "timeout", "unavailable", "socks_connect", "tcp_connect", "tls_handshake", "certificate", "http_status", "body_parse", "http_transport", "dial_timeout", "tls_timeout", "response_timeout":
		return value
	}
	return "unavailable"
}
func closedNodeCheckStages(stages []dataplane.NodeCheckStage) []nodeCheckDiagnosticStage {
	var out []nodeCheckDiagnosticStage
	for _, s := range stages[:min(len(stages), 32)] {
		switch s.ID {
		case "dns", "tcp_connect", "transport", "configuration", "protocol", "route_identity", "egress", "service", "service_ip", "connectivity", "cleanup":
		default:
			continue
		}
		switch s.Status {
		case "passed", "failed", "skipped":
		default:
			continue
		}
		if s.Duration < 0 {
			continue
		}
		out = append(out, nodeCheckDiagnosticStage{ID: s.ID, Status: s.Status, Duration: s.Duration})
	}
	return out
}
