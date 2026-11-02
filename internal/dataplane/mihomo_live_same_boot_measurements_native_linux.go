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
	case "phase-opening", "phase-intent", "phase-sidecar", "phase-policy", "phase-forwarding", "phase-archive", "phase-terminal", "phase-completed", "prepare", "run", "source-before-sidecar", "source-current", "absence", "home-current", "native-stage", "native-witness-callback", "metadata-current":
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
