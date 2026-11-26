//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"math"
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

var nfqwsActiveNativePopulation sync.Mutex

// This is a numeric process-wide population, not an owner observation. The
// native HTTP fixture runs serially and consumes this after its cleanup returns.
// Reject overlap, unfinished readers and counter regression instead of making
// an invalid delta look like zero. Nothing is reset or retained for authority.
func NativeFixtureBeginNFQWSActivePhaseMeasurement() (func() (map[string]NativeFixtureNFQWSProbePhase, error), error) {
	if !nfqwsActiveNativePopulation.TryLock() {
		return nil, errors.New("native active phase population already open")
	}
	before, err := nfqwsActivePhaseTotals()
	if err != nil {
		nfqwsActiveNativePopulation.Unlock()
		return nil, err
	}
	var once sync.Once
	return func() (map[string]NativeFixtureNFQWSProbePhase, error) {
		var out map[string]NativeFixtureNFQWSProbePhase
		err := errors.New("native active phase population already consumed")
		once.Do(func() {
			defer nfqwsActiveNativePopulation.Unlock()
			after, readErr := nfqwsActivePhaseTotals()
			if readErr != nil {
				err = readErr
				return
			}
			out, err = nfqwsActivePhaseDelta(before, after)
		})
		return out, err
	}, nil
}

type nfqwsActivePhaseSnapshot map[*[nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts][nfqwsProbePhaseCount]NativeFixtureNFQWSProbePhase

func nfqwsActivePhaseTotals() (nfqwsActivePhaseSnapshot, error) {
	totals := make(nfqwsActivePhaseSnapshot)
	var failure error
	nfqwsActiveNativePhases.Range(func(_, value any) bool {
		counts, ok := value.(*[nfqwsProbePhaseCount]nfqwsProbeNativePhaseCounts)
		if !ok || counts == nil {
			failure = errors.New("native active phase counter type")
			return false
		}
		var values [nfqwsProbePhaseCount]NativeFixtureNFQWSProbePhase
		for i := range counts {
			c := NativeFixtureNFQWSProbePhase{counts[i].started.Load(), counts[i].completed.Load(), time.Duration(counts[i].nanos.Load())}
			if c.Started != c.Completed || c.Wall < 0 {
				failure = errors.New("native active phase incomplete or overflowing population")
				return false
			}
			values[i] = c
		}
		totals[counts] = values
		return true
	})
	return totals, failure
}

func nfqwsActivePhaseDelta(before, after nfqwsActivePhaseSnapshot) (map[string]NativeFixtureNFQWSProbePhase, error) {
	out := make(map[string]NativeFixtureNFQWSProbePhase)
	for source := range before {
		if _, ok := after[source]; !ok {
			return nil, errors.New("native active phase generation missing")
		}
	}
	for source, values := range after {
		for i, name := range nfqwsActivePhaseNames {
			b, a := before[source][i], values[i]
			if b.Started != b.Completed || a.Started != a.Completed || b.Wall < 0 || a.Started < b.Started || a.Completed < b.Completed || a.Wall < b.Wall {
				return nil, errors.New("native active phase counter regression or unfinished population")
			}
			d := NativeFixtureNFQWSProbePhase{a.Started - b.Started, a.Completed - b.Completed, a.Wall - b.Wall}
			v := out[name]
			if math.MaxUint64-v.Started < d.Started || math.MaxInt64-int64(v.Wall) < int64(d.Wall) {
				return nil, errors.New("native active phase delta overflow")
			}
			out[name] = NativeFixtureNFQWSProbePhase{v.Started + d.Started, v.Completed + d.Completed, v.Wall + d.Wall}
		}
	}
	return out, nil
}

var nfqwsActivePhaseNames = [nfqwsProbePhaseCount]string{"current", "owners", "environment", "epoch-source-runtime", "cleanup-current", "counter", "capture-current", "policy-apply", "policy-remove", "policy-readback", "active-lan", "activate", "prepared-active", "active-read-pair", "active-inventory-capture"}

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
	for phase, name := range nfqwsActivePhaseNames {
		count := &counts[phase]
		out[name] = NativeFixtureNFQWSProbePhase{Started: count.started.Load(), Completed: count.completed.Load(), Wall: time.Duration(count.nanos.Load())}
	}
	return out
}
