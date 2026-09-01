package cloudflareprovider

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const (
	MaxTraceBytes   = 16 << 10
	MaxScanAttempts = 3
	MinScanPasses   = 2
)

var ErrTraceEvidence = errors.New("invalid Cloudflare trace evidence")

// TraceEvidence is produced only by ParseCloudflareTrace. The private valid
// bit prevents an arbitrary public struct literal from becoming proof.
type TraceEvidence struct {
	IP    string `json:"ip"`
	Colo  string `json:"colo"`
	WARP  string `json:"warp"`
	valid bool
}

// ParseCloudflareTrace parses the bounded text response from a request already
// scoped through the candidate. It does no network I/O and rejects duplicate
// or ambiguous fields.
func ParseCloudflareTrace(raw []byte) (TraceEvidence, error) {
	if len(raw) == 0 || len(raw) > MaxTraceBytes || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return TraceEvidence{}, ErrTraceEvidence
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) != line || line == "" {
			return TraceEvidence{}, ErrTraceEvidence
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || value == "" || len(key) > 64 || len(value) > 1024 || len(fields) >= 64 || fields[key] != "" || strings.ContainsAny(key, " \t\r") || strings.ContainsAny(value, "\r") {
			return TraceEvidence{}, ErrTraceEvidence
		}
		fields[key] = value
	}
	address, err := netip.ParseAddr(fields["ip"])
	colo := fields["colo"]
	warp := fields["warp"]
	if err != nil || address.String() != fields["ip"] || !publicScanAddress(address) || len(colo) != 3 || !upperASCII(colo) || (warp != "on" && warp != "off") {
		return TraceEvidence{}, ErrTraceEvidence
	}
	return TraceEvidence{IP: address.String(), Colo: colo, WARP: warp, valid: true}, nil
}

func upperASCII(value string) bool {
	for _, item := range []byte(value) {
		if item < 'A' || item > 'Z' {
			return false
		}
	}
	return true
}

func publicScanAddress(address netip.Addr) bool {
	return publicfetch.PublicAddress(address)
}

type ScanAttempt struct {
	Candidate        CandidatePreview       `json:"candidate"`
	StartedAt        time.Time              `json:"started_at"`
	FinishedAt       time.Time              `json:"finished_at"`
	Reachable        bool                   `json:"reachable"`
	HandshakeAt      time.Time              `json:"handshake_at,omitempty"`
	EgressIP         string                 `json:"egress_ip,omitempty"`
	DirectEgressIP   string                 `json:"direct_egress_ip,omitempty"`
	Trace            TraceEvidence          `json:"trace"`
	ServiceID        string                 `json:"service_id"`
	Service          evidence.ProbeEvidence `json:"service"`
	ConfirmedMTU     int                    `json:"confirmed_mtu,omitempty"`
	CleanupConfirmed bool                   `json:"cleanup_confirmed"`
}

type AttemptEvaluation struct {
	Verified   bool   `json:"verified"`
	Stage      string `json:"stage"`
	ReasonCode string `json:"reason_code"`
}

// EvaluateScanAttempt accepts no declared status. It derives the result from
// independent route facts and therefore cannot promote TCP reachability, a
// generic HTTP response or a Cloudflare trace alone to verified WARP.
func EvaluateScanAttempt(attempt ScanAttempt, now time.Time, ttl time.Duration) AttemptEvaluation {
	fail := func(stage, reason string) AttemptEvaluation {
		return AttemptEvaluation{Stage: stage, ReasonCode: reason}
	}
	candidate := attempt.Candidate
	if !candidate.valid || candidate.Verification != "built-unverified" || candidate.RoutePathID == "" || candidate.RoutePathID != candidateRoutePathID(candidate) {
		return fail("candidate", "candidate-identity-invalid")
	}
	if ttl <= 0 || attempt.StartedAt.IsZero() || attempt.FinishedAt.Before(attempt.StartedAt) || attempt.FinishedAt.After(now.Add(time.Minute)) || now.Sub(attempt.FinishedAt) > ttl {
		return fail("freshness", "attempt-stale-or-invalid")
	}
	if !attempt.CleanupConfirmed {
		return fail("cleanup", "cleanup-unconfirmed")
	}
	if !attempt.Reachable {
		return fail("reachability", "endpoint-unreachable")
	}
	if attempt.HandshakeAt.IsZero() || attempt.HandshakeAt.Before(attempt.StartedAt) || attempt.HandshakeAt.After(attempt.FinishedAt) {
		return fail("handshake", "handshake-unconfirmed")
	}
	egress, egressErr := netip.ParseAddr(attempt.EgressIP)
	direct, directErr := netip.ParseAddr(attempt.DirectEgressIP)
	if egressErr != nil || directErr != nil || !publicScanAddress(egress) || !publicScanAddress(direct) {
		return fail("egress", "egress-evidence-invalid")
	}
	if egress == direct {
		return fail("egress", "direct-leak-detected")
	}
	traceAddress, traceErr := netip.ParseAddr(attempt.Trace.IP)
	if !attempt.Trace.valid || traceErr != nil || attempt.Trace.WARP != "on" || traceAddress != egress {
		return fail("trace", "warp-trace-unconfirmed")
	}
	service := attempt.Service
	if !validServiceID(attempt.ServiceID) || service.Service != attempt.ServiceID || service.StartedAt.Before(attempt.StartedAt) || service.FinishedAt.After(attempt.FinishedAt) || service.EgressIP != egress.String() ||
		!service.Fresh(now, ttl) || service.AssuranceLevel() != evidence.Service || service.RoutePathID != candidate.RoutePathID || service.ExpectedRoutePathID != candidate.RoutePathID || service.ObservedRoutePathID != candidate.RoutePathID || service.NegativeControlMatched {
		return fail("service", "exact-service-route-unconfirmed")
	}
	if attempt.ConfirmedMTU != candidate.MTU {
		return fail("mtu", "mtu-unconfirmed")
	}
	return AttemptEvaluation{Verified: true, Stage: "complete", ReasonCode: "verified"}
}

func validServiceID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, item := range []byte(value) {
		if !(item >= 'a' && item <= 'z' || item >= '0' && item <= '9' || item == '-') {
			return false
		}
	}
	return true
}

type ScanReport struct {
	RoutePathID string              `json:"route_path_id"`
	Verified    bool                `json:"verified"`
	Passes      int                 `json:"passes"`
	Attempts    int                 `json:"attempts"`
	Score       int                 `json:"score"`
	ValidUntil  time.Time           `json:"valid_until,omitempty"`
	Results     []AttemptEvaluation `json:"results"`
	ReasonCode  string              `json:"reason_code"`
}

// EvaluateScanReport requires two independent successful attempts. A cleanup
// failure in any attempt is fatal even if the service happened to respond.
func EvaluateScanReport(attempts []ScanAttempt, now time.Time, ttl time.Duration) ScanReport {
	report := ScanReport{Attempts: len(attempts), ReasonCode: "insufficient-attempts"}
	if len(attempts) < MinScanPasses || len(attempts) > MaxScanAttempts {
		return report
	}
	report.RoutePathID = attempts[0].Candidate.RoutePathID
	oldestFinish := attempts[0].FinishedAt
	cleanupFailed, identityMismatch := false, false
	for _, attempt := range attempts {
		if attempt.Candidate.RoutePathID != report.RoutePathID {
			identityMismatch = true
		}
		if !attempt.CleanupConfirmed {
			cleanupFailed = true
		}
		if attempt.FinishedAt.Before(oldestFinish) {
			oldestFinish = attempt.FinishedAt
		}
		result := EvaluateScanAttempt(attempt, now, ttl)
		report.Results = append(report.Results, result)
		if result.Verified {
			report.Passes++
		}
	}
	report.Score = report.Passes * 100 / len(attempts)
	report.ValidUntil = oldestFinish.Add(ttl)
	switch {
	case identityMismatch:
		report.ReasonCode = "candidate-identity-changed"
	case cleanupFailed:
		report.ReasonCode = "cleanup-unconfirmed"
	case report.Passes < MinScanPasses:
		report.ReasonCode = "insufficient-confirmed-attempts"
	default:
		report.Verified = true
		report.ReasonCode = "verified"
	}
	return report
}
