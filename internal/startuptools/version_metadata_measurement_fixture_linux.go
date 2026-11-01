//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import (
	"sync"
	"sync/atomic"
)

var nativeVersionMetadataAttempts sync.Map // SAME original *heldReview → *atomic.Uint64.

func noteVersionMetadataAttempt(r *heldReview) {
	count, _ := nativeVersionMetadataAttempts.LoadOrStore(r, new(atomic.Uint64))
	count.(*atomic.Uint64).Add(1)
}

// NativeFixtureVersionMetadataCount reports attempted complete metadata
// traversals of this original source, including failed attempts. It asserts
// neither successful completion nor source freshness and grants no admission.
// Counter state does not exist in ordinary builds.
func NativeFixtureVersionMetadataCount(l *Lease) uint64 {
	if l == nil || l.review == nil {
		return 0
	}
	count, ok := nativeVersionMetadataAttempts.Load(l.review)
	if !ok {
		return 0
	}
	return count.(*atomic.Uint64).Load()
}
