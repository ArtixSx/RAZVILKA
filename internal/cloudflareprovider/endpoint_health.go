package cloudflareprovider

import (
	"errors"
	"time"
)

var ErrEndpointHealth = errors.New("Cloudflare endpoint health evidence is invalid")

const (
	EndpointHealthUnverified = "unverified"
	EndpointHealthVerified   = "verified"
	EndpointHealthCooldown   = "cooldown"
)

type EndpointHealth struct {
	RoutePathID         string             `json:"route_path_id"`
	Endpoint            string             `json:"endpoint"`
	Catalog             EndpointAssessment `json:"catalog"`
	State               string             `json:"state"`
	Score               int                `json:"score"`
	ConsecutiveFailures int                `json:"consecutive_failures"`
	LastTestedAt        time.Time          `json:"last_tested_at"`
	LastVerifiedAt      time.Time          `json:"last_verified_at,omitempty"`
	EvidenceValidUntil  time.Time          `json:"evidence_valid_until,omitempty"`
	CooldownUntil       time.Time          `json:"cooldown_until,omitempty"`
	valid               bool
}

func (health EndpointHealth) Selectable(now time.Time) bool {
	return health.valid && health.State == EndpointHealthVerified && health.Score > 0 && !health.EvidenceValidUntil.IsZero() && now.Before(health.EvidenceValidUntil) &&
		(health.CooldownUntil.IsZero() || !now.Before(health.CooldownUntil))
}

// UpdateEndpointHealth derives state only from an internally evaluated report.
// Catalog recommendation influences UI priority but never substitutes for scan
// evidence. Changed candidate identity starts a separate health record.
func UpdateEndpointHealth(previous EndpointHealth, candidate CandidatePreview, report ScanReport, now time.Time) (EndpointHealth, error) {
	if !candidate.valid || candidate.RoutePathID == "" || candidate.RoutePathID != candidateRoutePathID(candidate) || !report.valid || report.RoutePathID != candidate.RoutePathID ||
		now.IsZero() || report.Attempts == 0 || len(report.Results) != report.Attempts {
		return EndpointHealth{}, ErrEndpointHealth
	}
	if previous.RoutePathID != "" && (!previous.valid || previous.RoutePathID != candidate.RoutePathID) {
		return EndpointHealth{}, ErrEndpointHealth
	}
	health := previous
	health.valid = true
	health.RoutePathID = candidate.RoutePathID
	health.Endpoint = candidate.Endpoint
	health.Catalog = candidate.EndpointCatalog
	health.LastTestedAt = now.UTC()
	if report.Verified {
		if report.Passes < MinScanPasses || report.ValidUntil.IsZero() || !report.ValidUntil.After(now) || report.Score < 1 || report.Score > 100 {
			return EndpointHealth{}, ErrEndpointHealth
		}
		health.State = EndpointHealthVerified
		health.Score = report.Score
		health.ConsecutiveFailures = 0
		health.LastVerifiedAt = now.UTC()
		health.EvidenceValidUntil = report.ValidUntil.UTC()
		health.CooldownUntil = time.Time{}
		return health, nil
	}
	health.State = EndpointHealthCooldown
	health.Score = report.Score
	if report.ReasonCode == "cleanup-unconfirmed" || report.ReasonCode == "runner-failed" || report.ReasonCode == "scan-canceled" || report.ReasonCode == "insufficient-attempts" || report.Score < 0 || report.Score > 100 {
		health.Score = 0
	}
	health.ConsecutiveFailures++
	health.EvidenceValidUntil = time.Time{}
	health.CooldownUntil = now.Add(endpointCooldown(health.ConsecutiveFailures)).UTC()
	return health, nil
}

func endpointCooldown(failures int) time.Duration {
	switch failures {
	case 1:
		return time.Minute
	case 2:
		return 5 * time.Minute
	default:
		return 30 * time.Minute
	}
}
