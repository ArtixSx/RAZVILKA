// Package evidence defines the shared proof levels used by control-plane
// subsystems. The levels describe what RAZVILKA actually observed; they must
// never be promoted from desired or planned state.
package evidence

import (
	"strings"
	"time"
)

// Level is an ordered assurance level. String values are part of the public
// API and are intentionally stable for the Web UI and exported diagnostics.
type Level string

const (
	None       Level = "none"
	Catalog    Level = "catalog"
	Configured Level = "configured"
	Runtime    Level = "runtime"
	Route      Level = "route-confirmed"
	Service    Level = "service-confirmed"
)

const ProbeSchemaVersion = 2

type Outcome string

const (
	OutcomeUnknown            Outcome = "unknown"
	OutcomeTransportReachable Outcome = "transport_reachable"
	OutcomeTLSValid           Outcome = "tls_valid"
	OutcomeServiceAccepted    Outcome = "service_accepted"
	OutcomeServiceBlocked     Outcome = "service_blocked"
	OutcomeContentMismatch    Outcome = "content_mismatch"
	OutcomeEdgeUnsuitable     Outcome = "edge_unsuitable"
)

// ProbeEvidence keeps independent facts about a probe. Level remains in the
// public API for compatibility, but new decisions derive it from Outcome and
// RoutePathID instead of treating every HTTP response as service success.
type ProbeEvidence struct {
	SchemaVersion  int       `json:"schema_version"`
	ProbeID        string    `json:"probe_id,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	NetworkProfile string    `json:"network_profile,omitempty"`
	Service        string    `json:"service,omitempty"`
	Subservice     string    `json:"subservice,omitempty"`
	IPFamily       string    `json:"ip_family,omitempty"`
	DNSPath        string    `json:"dns_path,omitempty"`
	RoutePathID    string    `json:"route_path_id,omitempty"`
	Engine         string    `json:"engine,omitempty"`
	Outbound       string    `json:"outbound,omitempty"`
	Interface      string    `json:"interface,omitempty"`
	EgressIP       string    `json:"egress_ip,omitempty"`
	EgressCountry  string    `json:"egress_country,omitempty"`
	EgressASN      string    `json:"egress_asn,omitempty"`
	Stage          string    `json:"stage,omitempty"`
	Outcome        Outcome   `json:"outcome"`
	HTTPStatus     int       `json:"http_status,omitempty"`
	LatencyMS      int64     `json:"latency_ms,omitempty"`
	LossPercent    float64   `json:"loss_percent,omitempty"`
	Confidence     float64   `json:"confidence,omitempty"`
	Source         string    `json:"source,omitempty"`
	ErrorCode      string    `json:"error_code,omitempty"`
}

func (probe ProbeEvidence) Valid() bool {
	if probe.SchemaVersion != ProbeSchemaVersion || probe.FinishedAt.IsZero() || probe.FinishedAt.Before(probe.StartedAt) {
		return false
	}
	switch probe.Outcome {
	case OutcomeUnknown, OutcomeTransportReachable, OutcomeTLSValid, OutcomeServiceAccepted, OutcomeServiceBlocked, OutcomeContentMismatch, OutcomeEdgeUnsuitable:
		return true
	default:
		return false
	}
}

func (probe ProbeEvidence) Fresh(now time.Time, ttl time.Duration) bool {
	return probe.Valid() && ttl > 0 && !probe.FinishedAt.After(now.Add(time.Minute)) && now.Sub(probe.FinishedAt) <= ttl
}

func (probe ProbeEvidence) AssuranceLevel() Level {
	if !probe.Valid() {
		return None
	}
	isolatedRoute := strings.TrimSpace(probe.RoutePathID) != ""
	switch probe.Outcome {
	case OutcomeServiceAccepted:
		if isolatedRoute {
			return Service
		}
		return Runtime
	case OutcomeTransportReachable, OutcomeTLSValid, OutcomeServiceBlocked, OutcomeContentMismatch, OutcomeEdgeUnsuitable:
		if isolatedRoute {
			return Route
		}
		return Runtime
	default:
		if isolatedRoute {
			return Route
		}
		return None
	}
}

func OutcomeFromProbe(status string, httpStatus int, errorCode string) Outcome {
	status = strings.ToLower(strings.TrimSpace(status))
	errorCode = strings.ToLower(strings.TrimSpace(errorCode))
	if strings.Contains(errorCode, "tls") || strings.Contains(errorCode, "certificate") || strings.Contains(errorCode, "content-mismatch") {
		return OutcomeContentMismatch
	}
	if status == "pass" && (httpStatus == 0 || httpStatus >= 200 && httpStatus < 400) {
		return OutcomeServiceAccepted
	}
	if httpStatus == 403 || httpStatus == 451 {
		return OutcomeServiceBlocked
	}
	if httpStatus == 401 || httpStatus == 407 || httpStatus == 429 {
		return OutcomeEdgeUnsuitable
	}
	if status == "partial" || httpStatus > 0 {
		return OutcomeTransportReachable
	}
	return OutcomeUnknown
}

var ranks = map[Level]int{
	None: 0, Catalog: 1, Configured: 2, Runtime: 3, Route: 4, Service: 5,
}

// Valid reports whether the level is one of the stable public values.
func (level Level) Valid() bool {
	_, ok := ranks[level]
	return ok
}

// AtLeast compares two assurance levels without relying on lexical ordering.
func (level Level) AtLeast(required Level) bool {
	actualRank, actualOK := ranks[level]
	requiredRank, requiredOK := ranks[required]
	return actualOK && requiredOK && actualRank >= requiredRank
}

// Stronger returns the higher valid level. Invalid values are treated as None.
func Stronger(left, right Level) Level {
	if !left.Valid() {
		left = None
	}
	if !right.Valid() {
		right = None
	}
	if ranks[right] > ranks[left] {
		return right
	}
	return left
}

// Weaker returns the lower valid level. It is used for aggregate status where
// one unproven route must keep the whole transaction from looking confirmed.
func Weaker(left, right Level) Level {
	if !left.Valid() {
		left = None
	}
	if !right.Valid() {
		right = None
	}
	if ranks[right] < ranks[left] {
		return right
	}
	return left
}

// FromProbe derives an assurance level from observed probe facts. A successful
// endpoint response on the current path proves runtime reachability, but not a
// particular bypass. Only an isolated, route-confirmed response proves that a
// service works through the named route.
func FromProbe(status string, routeConfirmed bool) Level {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "not-ready" || status == "pending" || status == "adapter-pending" || status == "" {
		return None
	}
	if routeConfirmed {
		if status == "pass" {
			return Service
		}
		return Route
	}
	return Runtime
}
