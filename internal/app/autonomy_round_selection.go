package app

import (
	"slices"
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
func selectAutonomyRound(ids []string, doc autonomyDocument, cfg config.Config, now time.Time, ordinaryAfterFirstSearch bool, available ...[]string) (string, bool) {
	if !doc.Policy.Enabled || !doc.Policy.SetupComplete || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
		return "", false
	}
	oldest, firstSearch := "", ""
	for _, id := range ids {
		s, r := doc.Services[id], doc.Runtime[id]
		firstAssignment := !s.Removing && !cfg.AppliedServices[id].Enabled
		fresh := firstAssignment && freshAutonomySearchDue(r, now, available)
		// A newly populated empty traversal has no earlier candidate or failure
		// budget to protect. Its first check need not wait for the empty retry.
		if !s.Enabled || !s.Removing && !cfg.Services[id].Enabled || now.Before(r.NextCheck) && !(fresh && len(r.Search.Ordered) == 0) {
			continue
		}
		if oldest == "" || r.NextCheck.Before(doc.Runtime[oldest].NextCheck) {
			oldest = id
		}
		if !ordinaryAfterFirstSearch && firstAssignment && (firstAutonomySearchDue(r, now) || fresh) &&
			(firstSearch == "" || r.NextCheck.Before(doc.Runtime[firstSearch].NextCheck)) {
			firstSearch = id
		}
	}
	if firstSearch != "" {
		return firstSearch, true
	}
	return oldest, false
}

// nextAutonomySearchCheck lets the feeds operation honor cold search or
// first-start confirmation before its normal feed interval. The next turn
// still performs ordinary service selection, admission and scope checks.
func (a *App) nextAutonomySearchCheck(now time.Time) time.Time {
	if a.Store == nil {
		return time.Time{}
	}
	cfg := a.Store.Get()
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	doc := a.autonomy.doc
	if !a.autonomy.loaded || a.autonomy.blocked || !doc.Policy.Enabled || !doc.Policy.SetupComplete || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
		return time.Time{}
	}
	var next time.Time
	for id, s := range doc.Services {
		r := doc.Runtime[id]
		if !s.Enabled {
			continue
		}
		pending := r.State == "pending" && (cfg.Services[id].Enabled || handedOverUnassigned(cfg, s))
		confirmation := cfg.AppliedServices[id].Enabled && r.State == "unconfirmed" && r.Failures == 1 ||
			nfqws2FirstStartConfirmationPending(cfg, s, r)
		if !s.Removing && !pending && !confirmation && (!cfg.Services[id].Enabled || cfg.AppliedServices[id].Enabled || !firstAutonomySearchDue(r, now)) {
			continue
		}
		at := r.NextCheck
		if earliest := now.Add(reconcilerPollInterval); at.Before(earliest) {
			at = earliest
		}
		if next.IsZero() || at.Before(next) {
			next = at
		}
	}
	return next
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

// Fresh feed pages may arrive after an empty or consumed traversal was recorded.
// This hint only borrows the existing alternating first-search slot. The worker
// merges the page and rechecks current scope, cooldowns and consent as usual.
func freshAutonomySearchDue(r autonomy.Runtime, now time.Time, available [][]string) bool {
	t := r.Search
	if r.State != "searching" || t == nil || t.Halted || !t.Exhausted || t.Cursor < 0 || t.Cursor != len(t.Ordered) || now.Before(t.RetryAt) {
		return false
	}
	for _, page := range available {
		for _, id := range page {
			if id == "" || slices.Contains(t.Ordered, id) {
				continue
			}
			cooling := false
			for _, f := range r.CandidateFailures {
				if f.NodeID == id && !now.Before(f.ObservedAt) && now.Before(f.Until) {
					cooling = true
					break
				}
			}
			if !cooling {
				return true
			}
		}
	}
	return false
}
