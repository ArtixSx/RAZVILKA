//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// Local, bounded timing only: no context, source, lease or result is retained.
// A stage includes its original source validation and command/process reads.
// Durations are intervals, not an additive estimate of available deadline.
type wgRuntimeInactiveMeasurement struct {
	enabled, active, overflow bool
	started, stageStarted     time.Time
	current                   wgRuntimeInactiveTiming
	rows                      [40]wgRuntimeInactiveTiming
	count                     int
}

type wgRuntimeInactiveTiming struct {
	pass, slot, family int
	stage, outcome     string
	nanos              int64
}

func beginWGRuntimeInactiveMeasurement() wgRuntimeInactiveMeasurement {
	if os.Getenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK") == "" {
		return wgRuntimeInactiveMeasurement{}
	}
	return wgRuntimeInactiveMeasurement{enabled: true, started: time.Now()}
}

func (m *wgRuntimeInactiveMeasurement) begin(pass int, stage string, slot, family int) {
	if !m.enabled {
		return
	}
	m.end(nil, true)
	valid := pass == 1 || pass == 2
	switch stage {
	case "ownership", "links", "processes":
		valid = valid && slot == 0 && family == 0
	case "rules":
		valid = valid && slot == 0 && (family == 4 || family == 6)
	case "table-reference", "table-empty":
		valid = valid && slot >= 0 && slot < 3 && (family == 4 || family == 6)
	default:
		valid = false
	}
	if !valid {
		pass, stage, slot, family = 0, "invalid", 0, 0
	}
	m.current = wgRuntimeInactiveTiming{pass: pass, stage: stage, slot: slot, family: family}
	m.stageStarted, m.active = time.Now(), true
}

func wgRuntimeInactiveOutcome(err error, completed bool) string {
	if !completed {
		return "aborted"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if err != nil {
		return "refused"
	}
	return "completed"
}

func (m *wgRuntimeInactiveMeasurement) end(err error, completed bool) {
	if !m.enabled || !m.active {
		return
	}
	m.current.nanos = time.Since(m.stageStarted).Nanoseconds()
	m.current.outcome = wgRuntimeInactiveOutcome(err, completed)
	if m.count < len(m.rows) {
		m.rows[m.count] = m.current
		m.count++
	} else {
		m.overflow = true
	}
	m.active = false
}

func (m *wgRuntimeInactiveMeasurement) finish(err error, completed bool) {
	if !m.enabled {
		return
	}
	m.end(err, completed)
	// All output occurs after the original body, including its deferred exits.
	m.writeTo(log.Writer(), time.Since(m.started).Nanoseconds(), wgRuntimeInactiveOutcome(err, completed))
	m.enabled = false
}

func (m *wgRuntimeInactiveMeasurement) writeTo(w io.Writer, total int64, outcome string) {
	fmt.Fprintf(w, "actual_wg_runtime_inactive total_ns=%d outcome=%s records=%d overflow=%t\n", total, outcome, m.count, m.overflow)
	for _, row := range m.rows[:m.count] {
		fmt.Fprintf(w, "actual_wg_runtime_inactive_stage pass=%d stage=%s slot=%d family=%d elapsed_ns=%d outcome=%s\n", row.pass, row.stage, row.slot, row.family, row.nanos, row.outcome)
	}
}
