//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package components

import (
	"sync"
	"sync/atomic"
)

type managedNFQWSPayloadReadCounts struct {
	attempts atomic.Uint64
	bytes    atomic.Int64
}

var managedNFQWSPayloadReadMeasurements sync.Map // Original configured Manager only; data, not an owner.

func noteManagedNFQWSPayloadRead(m *Manager, n int64) {
	if m == nil || n < 0 {
		return
	}
	value, loaded := managedNFQWSPayloadReadMeasurements.Load(m)
	if !loaded {
		value, _ = managedNFQWSPayloadReadMeasurements.LoadOrStore(m, new(managedNFQWSPayloadReadCounts))
	}
	counts := value.(*managedNFQWSPayloadReadCounts)
	counts.attempts.Add(1)
	counts.bytes.Add(n)
}

// Member-read attempts and payload bytes returned for validation. Failed or
// partial attempts are included, so they are not successful source checks.
// Ordinary builds contain no counters; these values grant no admission.
func NativeFixtureManagedNFQWSPayloadReads(m *Manager) (uint64, int64) {
	value, ok := managedNFQWSPayloadReadMeasurements.Load(m)
	if !ok {
		return 0, 0
	}
	counts := value.(*managedNFQWSPayloadReadCounts)
	return counts.attempts.Load(), counts.bytes.Load()
}
