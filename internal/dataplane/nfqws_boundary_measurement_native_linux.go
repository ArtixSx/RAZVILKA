//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// One synchronous invocation, with no authority or context retained. IDs only
// correlate rows from this invocation; they are not an execution identity.
// Nested intervals are not additive. Logging happens after the original body.
type nfqwsBoundaryMeasurement struct {
	enabled, active, overflow       bool
	id                              uint64
	kind, role, detail              string
	started, stageStarted, deadline time.Time
	finite                          bool
	openingRemaining                int64
	rows                            [5]nfqwsBoundaryTiming
	count                           int
	stage                           string
}
type nfqwsBoundaryTiming struct {
	stage, outcome   string
	nanos, remaining int64
}

var nfqwsBoundaryNextID atomic.Uint64

func beginNFQWSBoundaryMeasurement(ctx context.Context, kind, role string) nfqwsBoundaryMeasurement {
	if os.Getenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK") == "" {
		return nfqwsBoundaryMeasurement{}
	}
	valid := kind == "policy-apply" || kind == "counter" || kind == "owner-read"
	if role != "unspecified" && (kind != "counter" || (role != "negative-before" && role != "negative-after" && role != "positive-after")) {
		valid = false
	}
	if !valid {
		kind, role = "invalid", "invalid"
	}
	m := nfqwsBoundaryMeasurement{enabled: true, id: nfqwsBoundaryNextID.Add(1), kind: kind, role: role, started: time.Now()}
	if ctx != nil {
		m.deadline, m.finite = ctx.Deadline()
	}
	m.openingRemaining = m.remaining()
	return m
}
func (m *nfqwsBoundaryMeasurement) remaining() int64 {
	if !m.finite {
		return 0
	}
	return time.Until(m.deadline).Nanoseconds() // Signed: expired is never clamped to zero.
}
func nfqwsBoundaryStageValid(kind, stage string) bool {
	switch kind {
	case "policy-apply":
		return stage == "prepare" || stage == "effects" || stage == "guard" || stage == "complete-readback"
	case "counter":
		return stage == "capture-opening" || stage == "command" || stage == "format" || stage == "parse" || stage == "capture-closing"
	case "owner-read":
		return stage == "admission" || stage == "receipt-opening" || stage == "verify-opening" || stage == "queue" || stage == "receipt-closing"
	}
	return false
}
func (m *nfqwsBoundaryMeasurement) begin(stage string) {
	if !m.enabled {
		return
	}
	m.end(nil, true)
	if !nfqwsBoundaryStageValid(m.kind, stage) {
		stage = "invalid"
	}
	m.stage, m.detail, m.stageStarted, m.active = stage, "none", time.Now(), true
}
func (m *nfqwsBoundaryMeasurement) cause(cause string) {
	if !m.enabled {
		return
	}
	switch cause {
	case "protected-path", "decode-known", "not-live-context", "state-files-control", "provider-current", "network-identity", "process-identities", "provider-closing", "image-compare-or-verify":
		m.detail = cause
	default:
		m.detail = "invalid"
	}
}
func nfqwsBoundaryOutcome(err error, returned bool) string {
	if !returned {
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
	return "returned-nil"
}
func (m *nfqwsBoundaryMeasurement) end(err error, returned bool) {
	if !m.enabled || !m.active {
		return
	}
	row := nfqwsBoundaryTiming{m.stage, nfqwsBoundaryOutcome(err, returned), time.Since(m.stageStarted).Nanoseconds(), m.remaining()}
	if m.count < len(m.rows) {
		m.rows[m.count] = row
		m.count++
	} else {
		m.overflow = true
	}
	m.active = false
}
func (m *nfqwsBoundaryMeasurement) finish(ctx context.Context, err error, returned bool) {
	if !m.enabled {
		return
	}
	m.end(err, returned)
	caller := "nil"
	if ctx != nil {
		caller = nfqwsBoundaryOutcome(ctx.Err(), true)
	}
	m.writeTo(log.Writer(), time.Since(m.started).Nanoseconds(), nfqwsBoundaryOutcome(err, returned), caller)
	m.enabled = false
}
func (m *nfqwsBoundaryMeasurement) writeTo(w io.Writer, total int64, outcome, caller string) {
	var line strings.Builder
	fmt.Fprintf(&line, "actual_nfq_boundary id=%d kind=%s role=%s total_ns=%d outcome=%s ctx=%s finite=%t opening_remaining_ns=%d closing_remaining_ns=%d cause=%s records=%d overflow=%t", m.id, m.kind, m.role, total, outcome, caller, m.finite, m.openingRemaining, m.remaining(), m.detail, m.count, m.overflow)
	for _, row := range m.rows[:m.count] {
		fmt.Fprintf(&line, " stage=%s:%s:%d:%d", row.stage, row.outcome, row.nanos, row.remaining)
	}
	fmt.Fprintln(w, line.String()) // One bounded line; no locks span context/error callbacks.
}
