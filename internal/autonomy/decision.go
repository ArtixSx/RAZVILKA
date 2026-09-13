package autonomy

import (
	"slices"
	"time"
)

// Runtime never authorizes a route or replaces NodeStore proof. On restart the
// adapter resets NextCheck and health/failure confirmation, but retains budgets.
type Runtime struct {
	State            string      `json:"state"`
	Message          string      `json:"message"`
	NextCheck        time.Time   `json:"next_check"`
	CheckedAt        time.Time   `json:"checked_at"`
	ReserveCheckedAt time.Time   `json:"reserve_checked_at"`
	Failures         int         `json:"failures"`
	FailureNode      string      `json:"failure_node,omitempty"`
	Network          string      `json:"network,omitempty"`
	FirstFailure     time.Time   `json:"first_failure,omitempty"`
	LastFailure      time.Time   `json:"last_failure,omitempty"`
	Cursor           int         `json:"cursor"`
	Reserves         []string    `json:"reserves"`
	Switches         []time.Time `json:"switches"`
}

func (r *Runtime) Observe(node, network, verdict string, now time.Time, gap time.Duration) bool {
	if r.FailureNode != node || r.Network != network {
		r.Failures = 0
		r.FirstFailure = time.Time{}
		r.LastFailure = time.Time{}
	}
	r.FailureNode, r.Network = node, network
	switch verdict {
	case "PASS":
		r.Failures = 0
		r.FirstFailure = time.Time{}
		r.LastFailure = time.Time{}
		return false
	case "FAIL":
		if r.Failures == 0 {
			r.Failures = 1
			r.FirstFailure = now
			r.LastFailure = now
			return false
		}
		if !now.Before(r.LastFailure.Add(gap)) {
			r.Failures = 2
			r.LastFailure = now
		}
		return r.Failures >= 2
	default:
		// Ambiguity cannot contribute to a consecutive failure quorum.
		r.Failures = 0
		r.FirstFailure = time.Time{}
		r.LastFailure = time.Time{}
		return false
	}
}
func (r *Runtime) ReserveSwitch(now time.Time, limit int) bool {
	recent := []time.Time{}
	for _, at := range r.Switches {
		if at.After(now.Add(-time.Hour)) {
			recent = append(recent, at)
		}
	}
	r.Switches = recent
	if limit < 1 || len(recent) >= limit {
		return false
	}
	r.Switches = append(r.Switches, now)
	return true
}
func (r Runtime) Clone() Runtime {
	r.Reserves = slices.Clone(r.Reserves)
	r.Switches = slices.Clone(r.Switches)
	return r
}
func CandidateBatch(ids []string, current string, cursor, limit int) ([]string, int) {
	if len(ids) == 0 || limit < 1 {
		return []string{}, 0
	}
	cursor = ((cursor % len(ids)) + len(ids)) % len(ids)
	result := []string{}
	examined := 0
	for i := 0; i < len(ids) && len(result) < limit; i++ {
		id := ids[(cursor+i)%len(ids)]
		examined++
		if id != current {
			result = append(result, id)
		}
	}
	// Rotate by the examined batch, not the number of successes.
	return result, (cursor + max(1, examined)) % len(ids)
}
