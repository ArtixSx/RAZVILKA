package app

import (
	"sort"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodequality"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Only checks of the same service in the same network within this window
// describe how a node serves it now.
const autonomyStabilityWindow = 24 * time.Hour

type autonomyStability struct {
	passes, failures int
	attempted        bool
	latencyMS        int64 // median of passing checks; 0 when unknown
}

// nodeStability summarises the recorded service checks of one node. A PASS
// is a service-level success without a direct leak. Only attributed service
// rejections count as failures. Unknown/local/cleanup errors do not poison a
// node or its sources. Legacy LatencyMS is lifecycle time, never network RTT.
func nodeStability(n nodestore.Node, serviceID, profile string, now time.Time) autonomyStability {
	var result autonomyStability
	seen := map[string]bool{}
	for _, c := range n.Health.History {
		if c.ServiceID != serviceID || c.NetworkProfile != profile || c.RoutePathID != "sing-box:"+n.ID || c.CheckedAt.After(now) || now.Sub(c.CheckedAt) > autonomyStabilityWindow {
			continue
		}
		if c.ProbeID != "" {
			if seen[c.ProbeID] {
				continue
			}
			seen[c.ProbeID] = true
		}
		switch c.Verdict {
		case "PASS", "BLOCKED", "MISROUTED", "PARTIAL", "ERROR":
			result.attempted = true
		}
		switch c.Verdict {
		case "PASS":
			if c.TestLevel == "service" && !c.DirectLeak {
				result.passes++

			}
		default:
			if nodequality.ServiceFailure(c.Verdict, c.TestLevel, c.Stage, c.ErrorCode, c.DirectLeak) {
				result.failures++
			}
		}
	}
	return result
}

// more reports whether a has served the service more reliably than b: a
// higher smoothed success share, then more successes, then a lower latency.
func (a autonomyStability) more(b autonomyStability) bool {
	// (pa+1)/(pa+fa+2) > (pb+1)/(pb+fb+2) without floating point.
	left := (a.passes + 1) * (b.passes + b.failures + 2)
	right := (b.passes + 1) * (a.passes + a.failures + 2)
	if left != right {
		return left > right
	}
	if a.passes != b.passes {
		return a.passes > b.passes
	}
	if (a.latencyMS == 0) != (b.latencyMS == 0) {
		return a.latencyMS != 0
	}
	return a.latencyMS < b.latencyMS
}

// rankAutonomyNodes orders candidates by their record for this service in
// this network, so the most stable node becomes the primary and the first
// reserve to try. A healthy current node (keep) always stays first: a more
// stable reserve is not a reason to switch a working path.
func rankAutonomyNodes(snapshot nodestore.Snapshot, ids []string, keep, serviceID, profile string, now time.Time, measurements ...nodequality.Observation) []string {
	nodes := map[string]nodestore.Node{}
	for _, n := range snapshot.Nodes {
		nodes[n.ID] = n
	}
	score := map[string]autonomyStability{}
	// Index once: avoid nodes × observations × history on small routers.
	measuredByNode := map[string]nodequality.Observation{}
	for _, m := range measurements {
		if m.ServiceID != serviceID || m.NetworkProfile != profile || !m.Valid(now) || !now.Before(m.ExpiresAt) {
			continue
		}
		old, exists := measuredByNode[m.NodeID]
		if !exists || m.CheckedAt.After(old.CheckedAt) {
			measuredByNode[m.NodeID] = m
		}
	}
	for _, id := range ids {
		value := nodeStability(nodes[id], serviceID, profile, now)
		if m, exists := measuredByNode[id]; exists {
			for _, c := range nodes[id].Health.History {
				if c.Verdict != "PASS" || c.State != "available" || c.TestLevel != "service" || c.DirectLeak || c.ServiceID != serviceID || c.NetworkProfile != profile || c.RoutePathID != "sing-box:"+id || !now.Before(c.ExpiresAt) || m.ExpiresAt.After(c.ExpiresAt) {
					continue
				}
				if ms, ok := nodequality.ResponseMS(m, id, serviceID, profile, "sing-box:"+id, c.ProbeID, now); ok && m.CheckedAt.Equal(c.CheckedAt) {
					value.latencyMS = max(1, ms)
					break
				}
			}
		}
		score[id] = value
	}
	ranked := append([]string(nil), ids...)
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if keep != "" && (a == keep) != (b == keep) {
			return a == keep
		}
		if score[a].more(score[b]) {
			return true
		}
		if score[b].more(score[a]) {
			return false
		}
		return a < b
	})
	return ranked
}

// orderAutonomyCandidates decides which candidates the bounded rounds check
// first: nodes from sources that served this service better in this network
// during the last day, then nodes without a check, then by ID. A weak source
// with many nodes can no longer occupy every round ahead of a good one.
func orderAutonomyCandidates(snapshot nodestore.Snapshot, ids []string, serviceID, profile string, now time.Time) []string {
	nodes := map[string]nodestore.Node{}
	for _, n := range snapshot.Nodes {
		nodes[n.ID] = n
	}
	sources := map[string]*autonomyStability{}
	attempted := map[string]bool{}
	for _, n := range snapshot.Nodes {
		stability := nodeStability(n, serviceID, profile, now)
		attempted[n.ID] = stability.attempted
		seenOrigins := map[string]bool{}
		for _, o := range n.Origins {
			if seenOrigins[o.SourceID] {
				continue
			}
			seenOrigins[o.SourceID] = true
			total := sources[o.SourceID]
			if total == nil {
				total = &autonomyStability{}
				sources[o.SourceID] = total
			}
			total.passes += stability.passes
			total.failures += stability.failures
		}
	}
	best := func(id string) autonomyStability {
		var result autonomyStability
		for i, o := range nodes[id].Origins {
			if s := sources[o.SourceID]; s != nil && (i == 0 || s.more(result)) {
				result = autonomyStability{passes: s.passes, failures: s.failures}
			}
		}
		return result
	}
	checked := func(id string) bool { return attempted[id] }
	ordered := append([]string(nil), ids...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if sa, sb := best(a), best(b); sa.more(sb) || sb.more(sa) {
			return sa.more(sb)
		}
		if ca, cb := checked(a), checked(b); ca != cb {
			return !ca
		}
		return a < b
	})
	return ordered
}
