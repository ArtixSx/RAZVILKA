package app

import (
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

const nodeServiceRateLimitMessage = "Сервис ограничил частоту проверок (HTTP 429). Сделана пауза для этого сервиса; маршрут сохранён, доступность пока не подтверждена."

// Scheduling only. The exact checker currently does not retain Retry-After,
// so use a local bounded 60-second pause without changing route-observer policy.
// Contradictory TLS/route/cleanup results cannot acquire a rate-limit pause.
func nodeServiceRateLimitSeconds(r dataplane.NodeCheckResult, now time.Time) int {
	if r.Available || r.DirectLeak || r.DirectControl != "measured" || r.EgressIP == "" || r.TestLevel != "service" || r.ProbeID == "" ||
		r.StartedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) || r.FinishedAt.IsZero() || r.FinishedAt.After(now) || !r.ExpiresAt.After(now) || r.NodeID == "" || r.ServiceID == "" || r.NetworkProfile == "" {
		return 0
	}
	domain := r.Stage == "service" && r.Verdict == evidence.VerdictPartial && r.HTTPStatus == 429 && r.ErrorCode == "http-429"
	// The existing literal-IP checker retains the domain's successful status,
	// but coerces an unavailable IP proof into these two ERROR verdicts. Accept
	// only its exact 429 evidence shape; ordinary path errors stay failures.
	ip := r.Stage == "service_ip" && r.Verdict == evidence.VerdictError && r.HTTPStatus >= 200 && r.HTTPStatus < 300 && r.ErrorCode == "node-service-ip-path-failed"
	if !domain && !ip {
		return 0
	}
	engine, node, ok := strings.Cut(r.RoutePathID, ":")
	if !ok || node != r.NodeID || engine != "sing-box" && engine != "xray" {
		return 0
	}
	p := r.Evidence
	expected := evidence.VerdictPartial
	if ip {
		expected = evidence.VerdictError
	}
	if !p.Valid() || p.ProbeID == "" || p.Stage != "service" || p.StartedAt.Before(r.StartedAt) || p.FinishedAt.After(now) || p.FinishedAt.After(r.FinishedAt) || p.Verdict != expected || p.HTTPStatus != 429 || p.ErrorCode != "http-429" || p.Outcome != evidence.OutcomeEdgeUnsuitable || p.RouteProofError != "" || p.NegativeControlMatched || p.EgressIP != r.EgressIP ||
		p.Engine != engine || p.Service != r.ServiceID || p.NetworkProfile != r.NetworkProfile || p.RoutePathID != r.RoutePathID || p.ExpectedRoutePathID != r.RoutePathID || p.ObservedRoutePathID != r.RoutePathID {
		return 0
	}
	return 60
}

func pauseNodeAutofallbackRateLimit(entry nodeAutofallbackEntry, result dataplane.NodeCheckResult, now time.Time) (nodeAutofallbackEntry, bool) {
	seconds := nodeServiceRateLimitSeconds(result, now)
	if seconds == 0 {
		return entry, false
	}
	until := now.Add(time.Duration(seconds) * time.Second)
	if entry.status.NextCheckAt.Before(until) {
		entry.status.NextCheckAt = until
	}
	entry.status.State, entry.status.Message = "unknown", nodeServiceRateLimitMessage
	entry.status.Failures, entry.status.Healthy, entry.status.CandidateID = 0, false, ""
	entry.status.CooldownUntil = &until
	return entry, true
}
