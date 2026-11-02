//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"strconv"
	"sync"
)

type domainTCPGuardMeasurementKey struct{}
type domainTCPGuardMeasurement struct {
	mu     sync.Mutex
	open   bool
	counts map[string]int
}

// CI-only attribution of calls in ONE synchronous pure guard. It grants no
// file/kernel/tool scope, changes no command and never suppresses a read.
func domainTCPMeasurePureGuard(ctx context.Context, phase string) (context.Context, func()) {
	if ctx == nil {
		return ctx, func() {}
	}
	if _, nested := ctx.Value(domainTCPGuardMeasurementKey{}).(*domainTCPGuardMeasurement); nested {
		return ctx, func() {}
	}
	domainTCPNativeMetrics.Lock()
	active := domainTCPNativeMetrics.active
	domainTCPNativeMetrics.Unlock()
	if !active {
		return ctx, func() {}
	}
	m := &domainTCPGuardMeasurement{open: true, counts: make(map[string]int)}
	var once sync.Once
	return context.WithValue(ctx, domainTCPGuardMeasurementKey{}, m), func() {
		once.Do(func() {
			m.mu.Lock()
			m.open = false
			counts := m.counts
			m.mu.Unlock()
			for _, kind := range []string{"full-hash", "process-current", "mapping-current", "kernel-observe", "backend-read", "ip-four-read"} {
				count := counts[kind]
				label := strconv.Itoa(count)
				if count > 64 {
					label = "over64"
				}
				// Histogram: Calls is the number of guards with this ATTEMPT count;
				// no completed-read, byte count, packet or readiness claim follows.
				domainTCPMeasure("pure-" + phase + "/" + kind + "-attempts=" + label)(0)
			}
		})
	}
}

func domainTCPMeasureGuardRead(ctx context.Context, kind string) {
	if ctx == nil {
		return
	}
	m, _ := ctx.Value(domainTCPGuardMeasurementKey{}).(*domainTCPGuardMeasurement)
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.open {
		m.counts[kind]++
	}
}
