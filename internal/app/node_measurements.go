package app

import (
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodequality"
)

// This read-model complements, never replaces, authoritative NodeStore proof.
// No disk schema changes: pre-existing LatencyMS remains lifecycle duration.
func (a *App) rememberNodeMeasurement(r dataplane.NodeCheckResult) {
	now := time.Now().UTC()
	m := nodequality.Observation{Version: nodequality.Version, NodeID: r.NodeID, ServiceID: r.ServiceID, NetworkProfile: r.NetworkProfile, RoutePathID: r.RoutePathID, ProbeID: r.ProbeID, CheckedAt: r.FinishedAt, ExpiresAt: r.ExpiresAt}
	total := r.FinishedAt.Sub(r.StartedAt)
	if !r.StartedAt.IsZero() && total >= 0 && total <= 10*time.Minute {
		v := total.Milliseconds()
		m.TotalCheckMS = &v
	}
	for _, s := range r.Stages {
		if s.ID == "tcp_connect" && s.Status == "passed" && s.Duration >= 0 {
			v := s.Duration
			m.TCPConnectMS = &v
		}
	}
	// ProbeEvidence spans the actual HTTP request (through SOCKS) to response
	// headers, including any redirects. It excludes core startup/egress probes.
	// Only measurements attached to a successful, exact final check are used.
	if r.Available && !r.DirectLeak && r.Evidence.AssuranceLevel().AtLeast(evidence.Service) && r.Evidence.RoutePathID == r.RoutePathID && r.Evidence.ExpectedRoutePathID == r.RoutePathID && r.Evidence.ObservedRoutePathID == r.RoutePathID && r.Evidence.Service == r.ServiceID && r.Evidence.NetworkProfile == r.NetworkProfile && r.Evidence.Verdict == evidence.VerdictPass {
		duration := r.Evidence.FinishedAt.Sub(r.Evidence.StartedAt)
		if !r.Evidence.StartedAt.IsZero() && !r.Evidence.StartedAt.Before(r.StartedAt) && !r.Evidence.FinishedAt.After(r.FinishedAt) && duration >= 0 && duration <= 10*time.Minute {
			v := duration.Milliseconds()
			m.ProxyResponseMS = &v
		}
	}
	a.nodeChecks.mu.Lock()
	if a.nodeChecks.measurements == nil {
		a.nodeChecks.measurements = &nodequality.Cache{}
	}
	cache := a.nodeChecks.measurements
	a.nodeChecks.mu.Unlock()
	cache.Put(m, now)
}

func (a *App) nodeMeasurements() []nodequality.Observation {
	a.nodeChecks.mu.Lock()
	cache := a.nodeChecks.measurements
	a.nodeChecks.mu.Unlock()
	return cache.Snapshot(time.Now().UTC())
}
