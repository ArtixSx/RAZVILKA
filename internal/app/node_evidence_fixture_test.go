package app

import (
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

// Model a native checker service proof explicitly. This is a test fixture,
// never fallback logic that manufactures evidence for a production result.
func modeledNodeServiceProof(result dataplane.NodeCheckResult, engine string) dataplane.NodeCheckResult {
	started := result.StartedAt
	if started.IsZero() {
		started = result.FinishedAt.Add(-time.Second)
	}
	status := result.HTTPStatus
	if status == 0 {
		status = 200
	}
	result.Evidence = evidence.ProbeEvidence{SchemaVersion: evidence.ProbeSchemaVersion, ProbeID: result.ProbeID, Engine: engine,
		Service: result.ServiceID, NetworkProfile: result.NetworkProfile, RoutePathID: result.RoutePathID, ExpectedRoutePathID: result.RoutePathID, ObservedRoutePathID: result.RoutePathID,
		StartedAt: started, FinishedAt: result.FinishedAt, Verdict: evidence.VerdictPass, Outcome: evidence.OutcomeServiceAccepted, HTTPStatus: status}
	return result
}
