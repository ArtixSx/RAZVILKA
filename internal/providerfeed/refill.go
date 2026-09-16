package providerfeed

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrRateLimited = errors.New("provider feed requested a retry delay")

// RefillDecision is public scheduling metadata, not node credentials or proof.
type RefillDecision struct {
	State         string    `json:"state"`
	SourceID      string    `json:"source_id,omitempty"`
	NextAllowedAt time.Time `json:"next_allowed_at,omitempty"`
}

// RequestRefill shortens a normal successful subscription interval only when
// an authorised service lacks reserve. It uses the existing worker, never
// synchronously fetches or replaces live routes. The caller owns the current
// autonomy consent and application operation lease.
func (m *Manager) RequestRefill(ctx context.Context, allowed []string) (RefillDecision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		return RefillDecision{}, ctx.Err()
	}
	if m.storage == nil || m.closed || m.fenced || !m.jobs.started || m.jobs.stopping {
		return RefillDecision{}, ErrStore
	}
	now := m.now().UTC()
	seen := map[string]bool{}
	type candidate struct {
		id  string
		due time.Time
	}
	var candidates []candidate
	for _, id := range allowed {
		if seen[id] {
			continue
		}
		seen[id] = true
		i := m.sourceIndexLocked(id)
		if i < 0 || !m.storage.doc.Sources[i].Enabled {
			continue
		}
		for _, j := range m.jobs.entries {
			if j.view.SourceID == id && (j.view.Status == "queued" || j.view.Status == "running") {
				return RefillDecision{State: "queued", SourceID: id}, nil
			}
		}
		s := m.states[id].state
		due := now
		if !s.LastAttemptAt.IsZero() {
			due = s.LastAttemptAt.Add(MinRefreshMinutes * time.Minute)
		}
		// Respect error backoff / Retry-After, including a crash during the last fetch.
		if (m.storage.doc.Sources[i].Failures > 0 || s.ErrorCode != "" || s.Status == "fetching") && s.NextRefreshAt.After(due) {
			due = s.NextRefreshAt
		}
		if s.RetryAfterAt.After(due) {
			due = s.RetryAfterAt
		}
		candidates = append(candidates, candidate{id, due})
	}
	if len(candidates) == 0 {
		return RefillDecision{State: "no-enabled-source"}, nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].due.Equal(candidates[j].due) {
			return candidates[i].id < candidates[j].id
		}
		return candidates[i].due.Before(candidates[j].due)
	})
	c := candidates[0]
	if now.Before(c.due) {
		return RefillDecision{State: "waiting", SourceID: c.id, NextAllowedAt: c.due}, nil
	}
	// Keep the demand durable using the existing due field; no new journal schema.
	old := m.states[c.id]
	next := old
	next.state.NextRefreshAt = now
	m.states[c.id] = next
	if err := m.persistLocked(ctx); err != nil {
		return RefillDecision{}, err
	}
	if _, err := m.queueLocked(c.id, true); err != nil {
		return RefillDecision{}, err
	}
	return RefillDecision{State: "queued", SourceID: c.id}, nil
}

func retryAfter(value string, now time.Time) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	var until time.Time
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return time.Time{}
		}
		// Never multiply untrusted integers into an overflowing duration.
		if seconds > int64(MaxRefreshMinutes*60) {
			seconds = int64(MaxRefreshMinutes * 60)
		}
		until = now.Add(time.Duration(seconds) * time.Second)
	} else if parsed, err := http.ParseTime(value); err == nil {
		until = parsed
	}
	if !until.After(now) {
		return time.Time{}
	}
	if cap := now.Add(MaxRefreshMinutes * time.Minute); until.After(cap) {
		until = cap
	}
	return until.UTC()
}
