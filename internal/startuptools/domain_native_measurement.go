//go:build linux && razvilka_native_fixture

package startuptools

import "sync"

var domainNativeToolMetrics struct {
	sync.Mutex
	active bool
	values map[string]int64
}

// CI-only counts of actual successfully started original children.
func StartDomainNativeToolMeasurement() func() map[string]int64 {
	domainNativeToolMetrics.Lock()
	if domainNativeToolMetrics.active {
		domainNativeToolMetrics.Unlock()
		panic("overlapping tool measurement")
	}
	startDomainNativeGateMeasurement()
	domainNativeToolMetrics.active = true
	domainNativeToolMetrics.values = make(map[string]int64)
	domainNativeToolMetrics.Unlock()
	var once sync.Once
	var result map[string]int64
	return func() map[string]int64 {
		once.Do(func() {
			domainNativeToolMetrics.Lock()
			defer domainNativeToolMetrics.Unlock()
			stopDomainNativeGateMeasurement()
			domainNativeToolMetrics.active = false
			result = domainNativeToolMetrics.values
		})
		out := make(map[string]int64, len(result))
		for k, v := range result {
			out[k] = v
		}
		return out
	}
}
func domainNativeToolStarted(kind string) {
	domainNativeToolMetrics.Lock()
	defer domainNativeToolMetrics.Unlock()
	if domainNativeToolMetrics.active {
		domainNativeToolMetrics.values[kind]++
	}
}
