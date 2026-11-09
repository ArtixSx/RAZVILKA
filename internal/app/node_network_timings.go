package app

import "github.com/ArtixSx/razvilka/internal/probecheck"

// A bounded, independent copy for process-local job snapshots. These timings
// never enter durable history, quality ranking, capability or service evidence.
func closedNodeNetworkTimings(rows []probecheck.NetworkTiming) []probecheck.NetworkTiming {
	var out []probecheck.NetworkTiming
	validDuration := func(n int64) bool { return n >= 0 && n <= 600_000_000 }
	for _, r := range rows[:min(len(rows), 32)] {
		if r.Sequence != len(out)+1 || (r.Kind != "service-http" && r.Kind != "service-resolver") ||
			(r.Status != "complete" && r.Status != "failed" && r.Status != "incomplete") || !validDuration(r.TotalUS) ||
			r.TLSAttempts < 0 || r.TLSAttempts > 1024 || r.SOCKSAttempts < 0 || r.SOCKSAttempts > 1024 || r.BodyBytes < 0 || r.BodyBytes > 1<<30 {
			break
		}
		valid := true
		for _, phase := range []probecheck.NetworkPhase{r.DNS, r.SOCKS, r.TLS, r.TTFB, r.Body} {
			if !validDuration(phase.DurationUS) || (!phase.Observed && (phase.Status != "" || phase.DurationUS != 0)) ||
				(phase.Observed && phase.Status != "complete" && phase.Status != "failed" && phase.Status != "incomplete" && phase.Status != "multiple") {
				valid = false
			}
		}
		if !valid {
			break
		}
		out = append(out, r)
	}
	return out
}
