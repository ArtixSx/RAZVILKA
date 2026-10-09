package app

import (
	"context"
	"log"
	"sync"
	"time"
)

type managedNFQTimingKey struct{}

type managedNFQTimingKind uint8

const (
	managedNFQPhysicalAcquire managedNFQTimingKind = iota
	managedNFQPhysicalVerify
	managedNFQWANProfile
	managedNFQTimingKinds
)

type managedNFQTimingSample struct {
	calls   uint32
	elapsed time.Duration
}

// Diagnostic data only: no timer, source cache, owner or admission. Values
// propagate through the original context and never replace its deadline.
type managedNFQTimings struct {
	mu      sync.Mutex
	started time.Time
	samples [managedNFQTimingKinds]managedNFQTimingSample
}

func beginManagedNFQTimings(ctx context.Context) (context.Context, func(string, error)) {
	if ctx == nil {
		return ctx, func(string, error) {}
	}
	timings := &managedNFQTimings{started: time.Now()}
	return context.WithValue(ctx, managedNFQTimingKey{}, timings), func(outer string, err error) {
		timings.mu.Lock()
		samples := timings.samples
		timings.mu.Unlock()
		inner, reason := managedNFQFailureDiagnostic(err)
		if err == nil {
			inner, reason = "none", "none"
		}
		log.Printf("Managed NFQ original timing outer=%s inner=%s reason=%s total_ms=%d", outer, inner, reason, time.Since(timings.started).Milliseconds())
		for kind, sample := range samples {
			if sample.calls != 0 {
				label := [...]string{"physical-acquire", "physical-verify", "wan-profile"}[kind]
				log.Printf("Managed NFQ original timing leaf=%s calls=%d elapsed_ms=%d", label, sample.calls, sample.elapsed.Milliseconds())
			}
		}
	}
}

func recordManagedNFQTiming(ctx context.Context, kind managedNFQTimingKind, started time.Time) {
	if ctx == nil || kind >= managedNFQTimingKinds {
		return
	}
	timings, ok := ctx.Value(managedNFQTimingKey{}).(*managedNFQTimings)
	if !ok || timings == nil {
		return
	}
	timings.mu.Lock()
	defer timings.mu.Unlock()
	if timings.samples[kind].calls < 65535 {
		timings.samples[kind].calls++
		timings.samples[kind].elapsed += time.Since(started)
	}
}
