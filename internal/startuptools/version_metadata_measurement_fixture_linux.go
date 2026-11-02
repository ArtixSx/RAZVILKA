//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import (
	"sync"
	"sync/atomic"
)

type nativeVersionCounts struct {
	metadata atomic.Uint64
	children [3]atomic.Uint64
}

var nativeVersionMetadataAttempts sync.Map // SAME original *heldReview → *nativeVersionCounts.

func noteVersionMetadataAttempt(r *heldReview) {
	count, _ := nativeVersionMetadataAttempts.LoadOrStore(r, new(nativeVersionCounts))
	count.(*nativeVersionCounts).metadata.Add(1)
}

func noteVersionChildStart(r *heldReview, index int) {
	if index < 0 || index > 2 {
		return
	}
	count, _ := nativeVersionMetadataAttempts.LoadOrStore(r, new(nativeVersionCounts))
	count.(*nativeVersionCounts).children[index].Add(1)
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
	return count.(*nativeVersionCounts).metadata.Load()
}

// NativeFixtureVersionChildCount counts actual successful Start events for
// the two fixed aliases and IP, including children whose Wait later failed.
func NativeFixtureVersionChildCount(l *Lease) [3]uint64 {
	var out [3]uint64
	if l == nil || l.review == nil {
		return out
	}
	if count, ok := nativeVersionMetadataAttempts.Load(l.review); ok {
		for i := range out {
			out[i] = count.(*nativeVersionCounts).children[i].Load()
		}
	}
	return out
}
