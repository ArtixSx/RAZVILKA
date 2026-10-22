package app

import (
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

// selectAutonomyRound changes only ordering among already due services. One
// first-assignment search may go ahead of older routine checks, then the next
// slot uses the original oldest-NextCheck order. That ordinary slot guarantees
// progress for every other due service even while many first searches wait.
// ids keeps the worker's existing sorted tie order; no time, cursor, budget or
// authority is renewed here. All actual checks/Apply remain in the same worker.
func selectAutonomyRound(ids []string, doc autonomyDocument, cfg config.Config, now time.Time, ordinaryAfterFirstSearch bool) (string, bool) {
	if !doc.Policy.Enabled || !doc.Policy.SetupComplete || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
		return "", false
	}
	oldest, firstSearch := "", ""
	for _, id := range ids {
		s, r := doc.Services[id], doc.Runtime[id]
		if !s.Enabled || !s.Removing && !cfg.Services[id].Enabled || now.Before(r.NextCheck) {
			continue
		}
		if oldest == "" || r.NextCheck.Before(doc.Runtime[oldest].NextCheck) {
			oldest = id
		}
		if !ordinaryAfterFirstSearch && !s.Removing && !cfg.AppliedServices[id].Enabled && firstAutonomySearchDue(r, now) &&
			(firstSearch == "" || r.NextCheck.Before(doc.Runtime[firstSearch].NextCheck)) {
			firstSearch = id
		}
	}
	if firstSearch != "" {
		return firstSearch, true
	}
	return oldest, false
}

func firstAutonomySearchDue(r autonomy.Runtime, now time.Time) bool {
	t := r.Search
	if r.State != "searching" || t == nil || t.Halted || t.Exhausted || t.Cursor < 0 || t.Cursor >= len(t.Ordered) || now.Before(t.RetryAt) {
		return false
	}
	// A cooling candidate is not an opportunity to search sooner. The worker
	// still performs its own current network/scope pruning and eligibility
	// checks; this read-only hint neither clears nor extends any cooldown.
	for _, id := range t.Ordered[t.Cursor:] {
		cooling := false
		for _, failure := range r.CandidateFailures {
			if failure.NodeID == id && !now.Before(failure.ObservedAt) && now.Before(failure.Until) {
				cooling = true
				break
			}
		}
		if !cooling {
			return true
		}
	}
	return false
}
