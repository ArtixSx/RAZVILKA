//go:build linux && razvilka_native_fixture

package startuptools

import (
	"runtime"
	"strings"
	"sync"
	"time"
)

type DomainNativeToolTiming struct {
	Calls   int64
	Elapsed time.Duration
}

type domainNativeGateHeld struct {
	start time.Time
	label string
}

var domainNativeGateMetrics struct {
	sync.Mutex
	epoch  uint64
	active bool
	values map[string]DomainNativeToolTiming
	held   map[*Lease]domainNativeGateHeld
}

func startDomainNativeGateMeasurement() {
	domainNativeGateMetrics.Lock()
	defer domainNativeGateMetrics.Unlock()
	domainNativeGateMetrics.epoch++
	domainNativeGateMetrics.active = true
	domainNativeGateMetrics.values = make(map[string]DomainNativeToolTiming)
	domainNativeGateMetrics.held = make(map[*Lease]domainNativeGateHeld)
}

func stopDomainNativeGateMeasurement() {
	domainNativeGateMetrics.Lock()
	defer domainNativeGateMetrics.Unlock()
	domainNativeGateMetrics.active = false
	clear(domainNativeGateMetrics.held)
}

// Completed diagnostic observations only. No pointer, caller argument or path
// leaves the fixture. In-flight intervals are excluded, not assumed complete.
func DomainNativeToolTimingSnapshot() map[string]DomainNativeToolTiming {
	domainNativeGateMetrics.Lock()
	defer domainNativeGateMetrics.Unlock()
	out := make(map[string]DomainNativeToolTiming, len(domainNativeGateMetrics.values))
	for k, v := range domainNativeGateMetrics.values {
		out[k] = v
	}
	return out
}

func domainNativeGateAdd(label string, elapsed time.Duration) {
	v := domainNativeGateMetrics.values[label]
	v.Calls++
	v.Elapsed += elapsed
	domainNativeGateMetrics.values[label] = v
}

// Closed stack-context labels, not inferred phase or authority. Attribution
// runs before the select timer; its cost is reported separately.
func domainNativeGateCaller() string {
	var pcs [64]uintptr
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs[:])])
	for {
		f, more := frames.Next()
		name := strings.TrimPrefix(f.Function, "github.com/ArtixSx/razvilka/internal/dataplane.")
		if i := strings.Index(name, ".func"); i >= 0 {
			name = name[:i]
		}
		switch name {
		case "(*DomainTCPOriginalScope).WithSyntheticPublication":
			return "dns-publication"
		case "(*DomainTCPOriginalScope).LookupPublished":
			return "accepted-lookup"
		case "(*DomainPolicyTCPCapture).guardPreparedFlow":
			return "accepted-guard"
		case "(*DomainPolicyTCPCapture).handleTCP":
			return "accepted-other"
		case "(*domainTCPCaptureExecutionResource).prepare":
			return "capture-prepare"
		case "(*syntheticBaselineExecutionResource).prepareBaseline":
			return "standby-prepare"
		}
		if !more {
			return "other"
		}
	}
}

func domainNativeGateWait(l *Lease) func(string) {
	domainNativeGateMetrics.Lock()
	if !domainNativeGateMetrics.active {
		domainNativeGateMetrics.Unlock()
		return func(string) {}
	}
	epoch := domainNativeGateMetrics.epoch
	domainNativeGateMetrics.Unlock()
	attribution := time.Now()
	label := domainNativeGateCaller()
	attributionElapsed := time.Since(attribution)
	start := time.Now()
	return func(outcome string) {
		end := time.Now()
		domainNativeGateMetrics.Lock()
		defer domainNativeGateMetrics.Unlock()
		if !domainNativeGateMetrics.active || domainNativeGateMetrics.epoch != epoch {
			return
		}
		switch outcome {
		case "acquired", "context", "lifetime", "observation-closed":
		default:
			outcome = "unknown"
		}
		domainNativeGateAdd("attribution", attributionElapsed)
		domainNativeGateAdd("wait/"+label+"/"+outcome, end.Sub(start))
		if outcome != "acquired" {
			return
		}
		if _, exists := domainNativeGateMetrics.held[l]; exists || len(domainNativeGateMetrics.held) >= 8 {
			domainNativeGateAdd("diagnostic/held-overflow-or-duplicate", 0)
			return
		}
		domainNativeGateMetrics.held[l] = domainNativeGateHeld{start: end, label: label}
	}
}

func domainNativeGateReleased(l *Lease) {
	end := time.Now()
	domainNativeGateMetrics.Lock()
	defer domainNativeGateMetrics.Unlock()
	if !domainNativeGateMetrics.active {
		return
	}
	held, ok := domainNativeGateMetrics.held[l]
	if !ok {
		domainNativeGateAdd("diagnostic/unmatched-release", 0)
		return
	}
	delete(domainNativeGateMetrics.held, l)
	domainNativeGateAdd("held/"+held.label, end.Sub(held.start))
}
