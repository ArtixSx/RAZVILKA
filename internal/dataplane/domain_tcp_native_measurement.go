//go:build linux && razvilka_native_fixture

package dataplane

import (
	"sync"
	"time"
)

type DomainTCPNativeMetric struct {
	Calls   int64
	Bytes   int64
	Elapsed time.Duration
}

var domainTCPNativeMetrics struct {
	sync.Mutex
	active bool
	values map[string]DomainTCPNativeMetric
}

// CI-only observation, never a scope, source or effect admission.
func StartDomainTCPNativeMeasurement() func() map[string]DomainTCPNativeMetric {
	domainTCPNativeMetrics.Lock()
	if domainTCPNativeMetrics.active {
		domainTCPNativeMetrics.Unlock()
		panic("overlapping domain native measurements")
	}
	domainTCPNativeMetrics.active = true
	domainTCPNativeMetrics.values = make(map[string]DomainTCPNativeMetric)
	domainTCPNativeMetrics.Unlock()
	var once sync.Once
	var result map[string]DomainTCPNativeMetric
	return func() map[string]DomainTCPNativeMetric {
		once.Do(func() {
			domainTCPNativeMetrics.Lock()
			defer domainTCPNativeMetrics.Unlock()
			domainTCPNativeMetrics.active = false
			result = domainTCPNativeMetrics.values
		})
		out := make(map[string]DomainTCPNativeMetric, len(result))
		for k, v := range result {
			out[k] = v
		}
		return out
	}
}
func domainTCPMeasure(name string) func(int64) {
	start := time.Now()
	domainTCPNativeMetrics.Lock()
	active := domainTCPNativeMetrics.active
	domainTCPNativeMetrics.Unlock()
	if !active {
		return func(int64) {}
	}
	return func(bytes int64) {
		domainTCPNativeMetrics.Lock()
		defer domainTCPNativeMetrics.Unlock()
		if !domainTCPNativeMetrics.active {
			return
		}
		v := domainTCPNativeMetrics.values[name]
		v.Calls++
		v.Bytes += bytes
		v.Elapsed += time.Since(start)
		domainTCPNativeMetrics.values[name] = v
	}
}
