//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package dataplane

import "sync/atomic"

// Process-local numeric diagnostics for one isolated native HTTP population.
// Never reset, and never retain an execution, Lease, callback or authority.
var nativeNFQInventoryReads [nfqInventoryEventCount]atomic.Uint64

func noteNFQInventoryRead(event int) {
	if event > 0 && event < len(nativeNFQInventoryReads) {
		nativeNFQInventoryReads[event].Add(1)
	}
}

// Snapshot remains readable after every original source closes. Counts report
// branch selection/completion only, not successful LAN/route acceptance.
func NativeFixtureNFQInventoryReadCounts() map[string]uint64 {
	names := [...]string{"unused", "fallback-foreign-participant", "fallback-no-lan", "fallback-mode", "fallback-context-nil", "fallback-custom-adapter", "fallback-custom-dispatch", "fallback-collector", "fallback-source", "fallback-plan-missing", "fallback-plan-lan", "fallback-plan-shape", "fallback-plan-intent", "eligible", "entered", "body-completed", "body-error", "completed", "error", "fallback-wg-owner", "fallback-wg-material", "fallback-wg-cleanup", "fallback-wg-inactivity-cleanup", "fallback-xray-owner", "fallback-xray-material", "fallback-xray-cleanup", "fallback-xray-execution", "fallback-xray-pre-resource", "fallback-xray-replacement", "fallback-xray-inventory", "fallback-xray-prepared", "fallback-nfq-retired", "fallback-nfq-probe-cleanup", "fallback-nfq-removal", "fallback-nfq-rollback", "source-coordinates", "source-cleanup", "source-execution", "source-material", "source-resource-binding", "source-runner", "source-adapter", "source-observer", "source-retired", "source-association", "owner-missing", "owner-opening-invalid", "owner-opening-no-activation", "owner-opening-deadline", "owner-opening-canceled", "owner-opening-other", "owner-observe-error", "owner-observe-mismatch", "owner-observe-transfer", "owner-closing-invalid", "owner-closing-deadline", "owner-closing-canceled", "owner-closing-other"}
	result := make(map[string]uint64, len(names)-1)
	for event := 1; event < len(names); event++ {
		result[names[event]] = nativeNFQInventoryReads[event].Load()
	}
	return result
}
