package providerfeed

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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
	return m.RequestRefillRanked(ctx, allowed, nil)
}

// RequestRefillRanked uses local, service-specific usefulness only among due
// sources. New sources and sources untried for an hour get an exploration turn;
// persisted attempt times prevent restarts/polling from resetting that order.
// Cooldowns and Retry-After always win over usefulness and aging.
func (m *Manager) RequestRefillRanked(ctx context.Context, allowed []string, useful map[string]int) (RefillDecision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		return RefillDecision{}, ctx.Err()
	}
	if len(allowed) > MaxFeeds || len(useful) > MaxFeeds {
		return RefillDecision{}, ErrRequest
	}
	if m.storage == nil || m.closed || m.fenced || !m.jobs.started || m.jobs.stopping {
		return RefillDecision{}, ErrStore
	}
	now := m.now().UTC()
	seen := map[string]bool{}
	type candidate struct {
		id        string
		due       time.Time
		attempt   time.Time
		failures  int
		utility   int
		publisher string
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
		candidates = append(candidates, candidate{id: id, due: due, attempt: s.LastAttemptAt, failures: m.storage.doc.Sources[i].Failures, utility: max(0, min(512, useful[id])), publisher: refillPublisherKey(m.storage.doc.Sources[i])})
	}
	if len(candidates) == 0 {
		return RefillDecision{State: "no-enabled-source"}, nil
	}
	// Known publisher collections share one exploration age. More links to the
	// same approved repository cannot reset that age or multiply its usefulness.
	// These are scheduling hints, never operator identity or health evidence.
	type publisher struct {
		attempt           time.Time
		utility, failures int
		ready             bool
	}
	publishers := map[string]publisher{}
	for _, c := range candidates {
		p := publishers[c.publisher]
		if c.attempt.After(p.attempt) {
			p.attempt = c.attempt
		}
		if !now.Before(c.due) {
			// A cooled-down collection can age the publisher, but cannot lend
			// utility or a lower failure count to a different ready sibling.
			p.utility = max(p.utility, c.utility)
			if !p.ready || c.failures < p.failures {
				p.failures = c.failures
			}
			p.ready = true
		}
		publishers[c.publisher] = p
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		readyA, readyB := !now.Before(a.due), !now.Before(b.due)
		if readyA != readyB {
			return readyA
		}
		if !readyA {
			if !a.due.Equal(b.due) {
				return a.due.Before(b.due)
			}
			return a.id < b.id
		}
		pa, pb := publishers[a.publisher], publishers[b.publisher]
		agedPublisher := func(p publisher) bool {
			return p.attempt.IsZero() || !now.Before(p.attempt.Add(4*MinRefreshMinutes*time.Minute))
		}
		if a.publisher != b.publisher {
			if agedPublisher(pa) != agedPublisher(pb) {
				return agedPublisher(pa)
			}
			if agedPublisher(pa) {
				if !pa.attempt.Equal(pb.attempt) {
					return pa.attempt.Before(pb.attempt)
				}
			} else {
				if pa.failures != pb.failures {
					return pa.failures < pb.failures
				}
				if pa.utility != pb.utility {
					return pa.utility > pb.utility
				}
			}
			// Complete the publisher order independently of its members, so
			// within-publisher exploration cannot make the comparator cyclic.
			if !pa.attempt.Equal(pb.attempt) {
				return pa.attempt.Before(pb.attempt)
			}
			return a.publisher < b.publisher
		}
		aged := func(c candidate) bool {
			return c.attempt.IsZero() || !now.Before(c.attempt.Add(4*MinRefreshMinutes*time.Minute))
		}
		if aged(a) != aged(b) {
			return aged(a)
		}
		if !aged(a) {
			if a.failures != b.failures {
				return a.failures < b.failures
			}
			if a.utility != b.utility {
				return a.utility > b.utility
			}
		}
		if !a.attempt.Equal(b.attempt) {
			return a.attempt.Before(b.attempt)
		}
		return a.id < b.id
	})
	c := candidates[0]
	if now.Before(c.due) {
		return RefillDecision{State: "waiting", SourceID: c.id, NextAllowedAt: c.due}, nil
	}
	// Keep the demand durable using the existing due field; no new journal schema.
	undo := m.checkpointLocked()
	old := m.states[c.id]
	next := old
	next.state.NextRefreshAt = now
	m.states[c.id] = next
	if err := m.persistLocked(ctx); err != nil {
		if !m.fenced {
			undo()
		}
		return RefillDecision{}, err
	}
	if _, err := m.queueLocked(c.id, true); err != nil {
		return RefillDecision{}, err
	}
	return RefillDecision{State: "queued", SourceID: c.id}, nil
}

// Group only repository identities from the trusted builtin catalogue. Custom
// token-bearing URLs are not decoded into publisher/ASN claims and retain
// independent scheduling. This never enables a builtin outside allowed IDs.
func refillPublisherKey(s subscription) string {
	for _, preset := range builtinPresets {
		if preset.ID != s.Request.PresetID {
			continue
		}
		u, err := url.Parse(preset.URL)
		if err != nil {
			break
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if u.Host == "raw.githubusercontent.com" && len(parts) >= 2 {
			return "builtin-github:" + strings.ToLower(parts[0]+"/"+parts[1])
		}
		return "builtin:" + preset.ID
	}
	return "source:" + s.ID
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
