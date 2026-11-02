//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package dataplane

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type nfqwsProbeNativePhaseCounts struct {
	started   atomic.Uint64
	completed atomic.Uint64
	nanos     atomic.Int64
}

var nfqwsProbeNativePhases sync.Map // SAME original consumer only; no ordinary-build state.

func measureNFQWSProbeContextPhase(ctx context.Context, phase nfqwsProbeMeasuredPhase) func() {
	var e *nfqwsProbeExecution
	if ctx != nil {
		e, _ = ctx.Value(nfqwsProbeExecutionKey{}).(*nfqwsProbeExecution)
	}
	if e == nil && ctx != nil {
		active, _ := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
		return measureNFQWSActivePhase(active, phase)
	}
	return measureNFQWSProbePhase(e, phase)
}

func measureNFQWSProbePhase(e *nfqwsProbeExecution, phase nfqwsProbeMeasuredPhase) func() {
	if e == nil || e.self != e || e.consumer == nil || e.consumer.self != e.consumer || phase >= nfqwsProbePhaseCount {
		return func() {}
	}
	value, loaded := nfqwsProbeNativePhases.Load(e.consumer)
	if !loaded {
		value, _ = nfqwsProbeNativePhases.LoadOrStore(e.consumer, new([nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts))
	}
	count := &value.(*[nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts)[phase]
	count.started.Add(1)
	start := time.Now()
	return func() { count.nanos.Add(time.Since(start).Nanoseconds()); count.completed.Add(1) }
}

// These are inclusive diagnostic durations, NOT additive phase costs or an
// effect/source grant. Started includes attempts that have not yet returned.
type NativeFixtureNFQWSProbePhase struct {
	Started, Completed uint64
	Wall               time.Duration
}

func NativeFixtureNFQWSProbePhases(c *ManagedNFQWSProbeConsumer) map[string]NativeFixtureNFQWSProbePhase {
	out := map[string]NativeFixtureNFQWSProbePhase{}
	if c == nil || c.self != c {
		return out
	}
	value, ok := nfqwsProbeNativePhases.Load(c)
	if !ok {
		return out
	}
	counts := value.(*[nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts)
	for phase, name := range [...]string{"current", "owners", "environment", "epoch-source-runtime", "cleanup-current", "counter", "capture-current", "policy-apply", "policy-remove", "policy-readback"} {
		count := &counts[phase]
		out[name] = NativeFixtureNFQWSProbePhase{Started: count.started.Load(), Completed: count.completed.Load(), Wall: time.Duration(count.nanos.Load())}
	}
	return out
}

var nfqwsActiveNativePhases sync.Map // Diagnostic process lifetime only.
func measureNFQWSActivePhase(e *nfqws2ActiveExecution, phase nfqwsProbeMeasuredPhase) func() {
	if e == nil || e.self != e || e.material == nil || e.material.self != e.material || phase >= nfqwsProbePhaseCount {
		return func() {}
	}
	value, _ := nfqwsActiveNativePhases.LoadOrStore(e.material, new([nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts))
	count := &value.(*[nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts)[phase]
	count.started.Add(1)
	start := time.Now()
	return func() { count.nanos.Add(time.Since(start).Nanoseconds()); count.completed.Add(1) }
}

// Comparison output only: no callbacks, path data, state mutation or authority.
func NativeFixtureNFQWSActivePhases(material *NFQWSActiveMaterial) map[string]NativeFixtureNFQWSProbePhase {
	out := map[string]NativeFixtureNFQWSProbePhase{}
	if material == nil || material.self != material {
		return out
	}
	value, ok := nfqwsActiveNativePhases.Load(material)
	if !ok {
		return out
	}
	counts := value.(*[nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts)
	for phase, name := range [...]string{"current", "owners", "environment", "epoch-source-runtime", "cleanup-current", "counter", "capture-current", "policy-apply", "policy-remove", "policy-readback", "active-lan", "activate", "prepared-active"} {
		count := &counts[phase]
		out[name] = NativeFixtureNFQWSProbePhase{Started: count.started.Load(), Completed: count.completed.Load(), Wall: time.Duration(count.nanos.Load())}
	}
	return out
}
