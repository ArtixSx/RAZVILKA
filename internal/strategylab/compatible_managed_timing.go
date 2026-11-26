package strategylab

import (
	"context"
	"errors"
	"sync"
	"time"
)

const managedCompatibilityTimingLimit = 96

// ManagedCompatibilityTiming is diagnostic duration data, never source,
// process, compatibility or cleanup authority. Labels are fixed in source.
type ManagedCompatibilityTiming struct {
	Stage            string `json:"stage"`
	Phase            string `json:"phase"`
	StartMS          int64  `json:"start_ms"`
	ElapsedMS        int64  `json:"elapsed_ms"`
	RemainingStartMS int64  `json:"remaining_start_ms"`
	RemainingEndMS   int64  `json:"remaining_end_ms"`
	Complete         bool   `json:"complete"`
	Failed           bool   `json:"failed"`
	Cancelled        bool   `json:"cancelled"`
	Deadline         bool   `json:"deadline"`
}

// ManagedCompatibilityTimingSnapshot is a bounded detached observation. Missing
// or unfinished rows mean incomplete diagnostics, not successful retirement.
type ManagedCompatibilityTimingSnapshot struct {
	Schema  int                          `json:"schema"`
	Dropped uint64                       `json:"dropped"`
	Entries []ManagedCompatibilityTiming `json:"entries"`
}

type managedCompatibilityTiming struct {
	mu      sync.Mutex
	started time.Time
	count   int
	dropped uint64
	entries [managedCompatibilityTimingLimit]ManagedCompatibilityTiming
}

func managedTimingRemaining(ctx context.Context) int64 {
	if ctx == nil {
		return -1
	}
	if deadline, ok := ctx.Deadline(); ok {
		return time.Until(deadline).Milliseconds()
	}
	return -1
}

func (t *managedCompatibilityTiming) begin(ctx context.Context, stage, phase string) func(error) {
	if t == nil {
		return func(error) {}
	}
	started := time.Now()
	t.mu.Lock()
	if t.count == len(t.entries) {
		t.dropped++
		t.mu.Unlock()
		return func(error) {}
	}
	index := t.count
	t.count++
	t.entries[index] = ManagedCompatibilityTiming{Stage: stage, Phase: phase, StartMS: started.Sub(t.started).Milliseconds(), RemainingStartMS: managedTimingRemaining(ctx)}
	t.mu.Unlock()
	return func(err error) {
		elapsed, remaining := time.Since(started).Milliseconds(), managedTimingRemaining(ctx)
		t.mu.Lock()
		defer t.mu.Unlock()
		row := &t.entries[index]
		row.ElapsedMS, row.RemainingEndMS, row.Complete = elapsed, remaining, true
		row.Failed = err != nil
		if ctx != nil {
			row.Cancelled = errors.Is(ctx.Err(), context.Canceled)
			row.Deadline = errors.Is(ctx.Err(), context.DeadlineExceeded)
		}
	}
}

func (i *managedCompatibilityInvocation) beginTiming(ctx context.Context, stage, phase string) func(error) {
	if i == nil {
		return func(error) {}
	}
	return i.timing.begin(ctx, stage, phase)
}

func managedTiming(ctx context.Context, stage, phase string) func(error) {
	if ctx != nil {
		if i, _ := ctx.Value(managedCompatibilityContextKey{}).(*managedCompatibilityInvocation); i != nil {
			return i.timing.begin(ctx, stage, phase)
		}
	}
	return func(error) {}
}

func (t *managedCompatibilityTiming) snapshot() ManagedCompatibilityTimingSnapshot {
	if t == nil {
		return ManagedCompatibilityTimingSnapshot{Schema: 1}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return ManagedCompatibilityTimingSnapshot{Schema: 1, Dropped: t.dropped, Entries: append([]ManagedCompatibilityTiming(nil), t.entries[:t.count]...)}
}

// ManagedCompatibilityTimings only copies the latest same-process diagnostic
// buffer. It performs no file, process, control, network or source observation.
// Callers must separately establish actual joined cleanup before publishing it.
func (m *Manager) ManagedCompatibilityTimings() ManagedCompatibilityTimingSnapshot {
	if m == nil {
		return ManagedCompatibilityTimingSnapshot{Schema: 1}
	}
	m.mu.RLock()
	var p *SupervisedCompatibilityProvider
	switch v := m.Validator.(type) {
	case CompatibleValidator:
		p, _ = v.Provider.(*SupervisedCompatibilityProvider)
	case *CompatibleValidator:
		if v != nil {
			p, _ = v.Provider.(*SupervisedCompatibilityProvider)
		}
	}
	m.mu.RUnlock()
	if p == nil {
		return ManagedCompatibilityTimingSnapshot{Schema: 1}
	}
	p.mu.Lock()
	timing := p.managedTiming
	p.mu.Unlock()
	return timing.snapshot()
}
