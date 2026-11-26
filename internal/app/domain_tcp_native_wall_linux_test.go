//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type domainNativeReadinessSample struct {
	StartOffsetNS int64  `json:"start_offset_ns"`
	EndOffsetNS   int64  `json:"end_offset_ns"`
	PhaseBefore   string `json:"phase_before"`
	PhaseAfter    string `json:"phase_after"`
	Outcome       string `json:"outcome"`
}

type domainNativeReadinessTrace struct {
	Samples []domainNativeReadinessSample `json:"samples"`
	Dropped int                           `json:"dropped"`
}

func (r *domainNativeReadinessTrace) append(origin, began, ended time.Time, before, after string, readyErr, contextErr error) {
	// The strict 12s and optional 30s fixture poll every 100ms. Cap diagnostic
	// storage regardless of poll cadence or any later fixture modification.
	if len(r.Samples) >= 320 {
		r.Dropped++
		return
	}
	outcome := "refused"
	switch {
	case readyErr == nil && contextErr == nil:
		outcome = "ready"
	case errors.Is(readyErr, context.DeadlineExceeded) || errors.Is(contextErr, context.DeadlineExceeded):
		outcome = "deadline"
	case errors.Is(readyErr, context.Canceled) || errors.Is(contextErr, context.Canceled):
		outcome = "cancelled"
	}
	r.Samples = append(r.Samples, domainNativeReadinessSample{
		StartOffsetNS: began.Sub(origin).Nanoseconds(), EndOffsetNS: ended.Sub(origin).Nanoseconds(),
		PhaseBefore: before, PhaseAfter: after, Outcome: outcome,
	})
}

func TestDomainNativeReadinessTracePreservesTheWitnessWindow(t *testing.T) {
	origin := time.Now()
	limit := origin.Add(12 * time.Second)
	var trace domainNativeReadinessTrace
	trace.append(origin, origin, origin.Add(time.Millisecond), "waiting", "waiting", errors.New("owner refused"), nil)
	trace.append(origin, limit.Add(-time.Millisecond), limit, "waiting", "open", nil, context.DeadlineExceeded)
	for index, want := range []string{"refused", "deadline"} {
		if trace.Samples[index].Outcome != want {
			t.Fatal("readiness outcome differs from caller's context", trace.Samples[index])
		}
	}
	if sample := trace.Samples[1]; sample.PhaseBefore == sample.PhaseAfter || sample.EndOffsetNS != (12*time.Second).Nanoseconds() || sample.StartOffsetNS <= trace.Samples[0].EndOffsetNS {
		t.Fatal("phase transition or real deadline was lost", sample)
	}
	trace = domainNativeReadinessTrace{}
	trace.append(origin, limit.Add(-time.Second), limit.Add(-time.Millisecond), "open", "open", nil, nil)
	if got := trace.Samples[0]; got.Outcome != "ready" || got.EndOffsetNS >= (12*time.Second).Nanoseconds() {
		t.Fatal("timely witness was not recorded", got)
	}
}

type domainNativeWallMark struct {
	Stage    string `json:"stage"`
	OffsetNS int64  `json:"offset_ns"`
}

// The parent and its LAN peer share the system clock. Intervals on each
// track use Go's monotonic clock. Different tracks describe overlapping work.
type domainNativeWallTrace struct {
	start time.Time
	mu    sync.Mutex
	marks []domainNativeWallMark
}

func newDomainNativeWallTrace() *domainNativeWallTrace {
	return &domainNativeWallTrace{start: time.Now()}
}

func (p *domainNativeWallTrace) mark(stage string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.marks) < 32 {
		p.marks = append(p.marks, domainNativeWallMark{Stage: stage, OffsetNS: time.Since(p.start).Nanoseconds()})
	}
}

func (p *domainNativeWallTrace) log(t *testing.T, track string) {
	t.Helper()
	p.mu.Lock()
	data, err := json.Marshal(struct {
		Track       string                 `json:"track"`
		StartUnixNS int64                  `json:"start_unix_ns"`
		Marks       []domainNativeWallMark `json:"marks"`
	}{track, p.start.UnixNano(), p.marks})
	p.mu.Unlock()
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("DOMAIN_WALL_TRACE: %s", data)
}

func domainNativeObservation(t *testing.T, track string, earliest, latest time.Time, observations any) {
	t.Helper()
	data, err := json.Marshal(struct {
		Track          string `json:"track"`
		EarliestUnixNS int64  `json:"earliest_unix_ns"`
		LatestUnixNS   int64  `json:"latest_unix_ns"`
		Observations   any    `json:"observations"`
	}{track, earliest.UnixNano(), latest.UnixNano(), observations})
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("DOMAIN_ROUTER_OBSERVATION: %s", data)
}
