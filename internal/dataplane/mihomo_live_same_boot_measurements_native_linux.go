//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"sort"
	"sync"
	"time"
)

type MihomoSameBootNativeMeasurement struct {
	Phase       string
	Calls       uint64
	Nanoseconds int64
}
type mihomoSameBootMeasurementsKey struct{}
type mihomoSameBootMeasurements struct {
	mu     sync.Mutex
	self   *mihomoSameBootMeasurements
	active bool
	rows   map[string]MihomoSameBootNativeMeasurement
}

// Pure diagnostics. No callback is added to a native observation/Start; the
// original operation and its errors run exactly once, under the same deadline.
func WithMihomoSameBootNativeMeasurements(ctx context.Context, use func(context.Context) error) (rows []MihomoSameBootNativeMeasurement, resultErr error) {
	if ctx == nil || use == nil {
		return nil, ErrMihomoLiveRetirement
	}
	m := &mihomoSameBootMeasurements{active: true, rows: map[string]MihomoSameBootNativeMeasurement{}}
	m.self = m
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.active = false
		for _, r := range m.rows {
			rows = append(rows, r)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Phase < rows[j].Phase })
	}()
	resultErr = use(context.WithValue(ctx, mihomoSameBootMeasurementsKey{}, m))
	return
}
func mihomoSameBootMeasureContext(ctx context.Context, phase string) func() {
	if ctx == nil {
		return func() {}
	}
	switch phase {
	case "phase-opening", "phase-intent", "phase-sidecar", "phase-policy", "phase-forwarding", "phase-archive", "phase-terminal", "phase-completed", "prepare", "run", "source-before-sidecar", "source-current", "absence", "absence-tool-read", "home-current", "native-stage", "native-witness-callback", "metadata-current":
	default:
		return func() {}
	}
	m, _ := ctx.Value(mihomoSameBootMeasurementsKey{}).(*mihomoSameBootMeasurements)
	if m == nil || m.self != m {
		return func() {}
	}
	started := time.Now()
	return func() {
		elapsed := time.Since(started)
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.active {
			return
		}
		r := m.rows[phase]
		r.Phase = phase
		r.Calls++
		r.Nanoseconds += int64(elapsed)
		m.rows[phase] = r
	}
}
func mihomoSameBootNativeTiming(c *mihomoSameBootRetirementCursor, phase string) func() {
	if c == nil || c.self != c || c.manager == nil || c.manager.StateRoot != "/opt/razvilka/state/dataplane" {
		return func() {}
	}
	return mihomoSameBootMeasureContext(c.ctx, phase)
}
func mihomoSameBootNativeOwnerTiming(o *mihomoSameBootCleanup, phase string) func() {
	if o == nil || o.self != o || o.inputs == nil || o.inputs.statePath != "/opt/razvilka/state/dataplane" {
		return func() {}
	}
	return mihomoSameBootMeasureContext(o.inputs.ctx, phase)
}

// Refusal-only documentary counts. Never inspect Error/Is/Unwrap, execute a
// callback or change the original error, read ordering, clocks or ownership.
func mihomoSameBootNativeFailure(ctx context.Context, stage string, err error) error {
	if err == nil || ctx == nil {
		return err
	}
	switch stage {
	case "owner", "inputs-opening", "plan-inputs", "policy-close", "static-current", "static-close", "read-opening", "control-opening", "processes", "inputs-closing", "read-closing", "control-closing",
		"process-owner", "process-network", "process-parent-opening", "process-parent-pass", "process-parent-closing", "process-platform", "process-self-opening", "process-listener", "process-self-closing", "process-provider", "process-inventory-unknown", "process-inventory-proc.thread-net-path", "process-inventory-proc.self-exe", "process-inventory-proc.enumerate", "process-inventory-proc.pid-shape", "process-inventory-proc.stat-read", "process-inventory-proc.stat-decode", "process-inventory-proc.cmdline-read", "process-inventory-proc.cmdline-shape", "process-inventory-proc.cmdline-empty.kthread-flag-false", "process-inventory-proc.cmdline-empty.self-true", "process-inventory-proc.cmdline-nonempty.argc-bounded-false", "process-inventory-proc.cmdline-nonempty.argv0-nonempty-false", "process-inventory-proc.exe-read", "process-inventory-proc.exe-incarnation", "process-inventory-proc.controller-ownership", "process-inventory-proc.installer-role-open", "process-inventory-proc.argv-recheck", "process-inventory-proc.exe-recheck", "process-inventory-proc.stat-recheck", "process-inventory-proc.installer-role-close", "process-inventory-proc-socket.complete", "process-inventory-socket.tcp.read", "process-inventory-socket.tcp.parse", "process-inventory-socket.tcp6.read", "process-inventory-socket.tcp6.parse", "process-inventory-socket.udp.read", "process-inventory-socket.udp.parse", "process-inventory-socket.udp6.read", "process-inventory-socket.udp6.parse":
	default:
		return err
	}
	m, _ := ctx.Value(mihomoSameBootMeasurementsKey{}).(*mihomoSameBootMeasurements)
	if m == nil || m.self != m {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return err
	}
	phase := "failure-" + stage
	r := m.rows[phase]
	r.Phase = phase
	r.Calls++
	m.rows[phase] = r
	return err
}

// Inspect only the original direct private wrapper. Do not traverse error trees
// or format them. The shared recorder rejects every non-enumerated stage.
func mihomoSameBootNativeProcFailure(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	failure, ok := err.(*scopedDNSInactiveProcFailure)
	if !ok || failure == nil || len(failure.stage) > 64 {
		return mihomoSameBootNativeFailure(ctx, "process-inventory-unknown", err)
	}
	return mihomoSameBootNativeFailure(ctx, "process-inventory-"+failure.stage, err)
}
