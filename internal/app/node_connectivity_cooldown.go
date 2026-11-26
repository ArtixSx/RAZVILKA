package app

import (
	"context"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// A scheduling hint only: two transport failures require a later successful
// OTHER node on the same executor/WAN before any automatic candidate is delayed.
// Reading never renews the fixed last-failure deadline or grants route proof.
func (a *App) nodeConnectivityTransportCoolingDown(nodeID, engine, network string, now time.Time) bool {
	if a == nil || nodeID == "" || network == "" || now.IsZero() || engine != "sing-box" && engine != "xray" {
		return false
	}
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	pair := a.nodeChecks.connectivityTransportFailures[nodeID+"\x00"+engine+"\x00"+network]
	if len(pair) != 2 || pair[0].ProbeID == pair[1].ProbeID || !pair[1].CheckedAt.After(pair[0].CheckedAt) || pair[1].CheckedAt.Sub(pair[0].CheckedAt) > dataplane.NodeConnectivityTTL || !now.Before(pair[1].CheckedAt.Add(dataplane.NodeConnectivityTTL)) {
		return false
	}
	for _, failed := range pair {
		if failed.NodeID != nodeID || failed.Engine != engine || failed.NetworkProfile != network || failed.ProbeID == "" || failed.CheckedAt.IsZero() || failed.CheckedAt.After(now) ||
			!failed.ExpiresAt.After(failed.CheckedAt) || failed.ExpiresAt.Sub(failed.CheckedAt) > dataplane.NodeConnectivityTTL || failed.TestLevel != "connectivity" || failed.Stage != "transport" ||
			failed.ErrorCode != "node-transport-failed" || failed.Verdict != "ERROR" || failed.DirectControl != "not_run" || !failed.CleanupVerified || failed.ConnectivityReady {
			return false
		}
	}
	for _, positive := range a.nodeChecks.connectivity {
		if positive.NodeID != "" && positive.NodeID != nodeID && positive.Engine == engine && positive.NetworkProfile == network && positive.ConnectivityReady && positive.CleanupVerified &&
			positive.ProbeID != "" && positive.TestLevel == "connectivity" && positive.Stage == "connectivity" && positive.Verdict == "PASS" && positive.ErrorCode == "" && positive.DirectControl == "measured" &&
			positive.CheckedAt.After(pair[1].CheckedAt) && !positive.CheckedAt.After(now) && positive.ExpiresAt.After(now) && positive.ExpiresAt.Sub(positive.CheckedAt) <= dataplane.NodeConnectivityTTL {
			return true
		}
	}
	return false
}

func (a *App) autonomyConnectivityCoolingDown(ctx context.Context, p autonomy.Policy, s autonomy.Service, engine, id, network string, now time.Time) bool {
	if s.ExpectedRoute != "auto" {
		return a.nodeConnectivityTransportCoolingDown(id, engine, network, now)
	}
	// Most candidates have no negative hint. Avoid material reads for them;
	// AUTO must still resolve the actual compatible executor before deferring.
	if !a.nodeConnectivityTransportCoolingDown(id, "sing-box", network, now) && !a.nodeConnectivityTransportCoolingDown(id, "xray", network, now) {
		return false
	}
	selected, err := a.autonomyCandidateEngine(ctx, p, s, engine, id)
	return err == nil && a.nodeConnectivityTransportCoolingDown(id, selected, network, now)
}
