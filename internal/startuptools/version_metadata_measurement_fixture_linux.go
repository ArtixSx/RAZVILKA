//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type nativeVersionCounts struct {
	metadata atomic.Uint64
	children [3]atomic.Uint64
}

var nativeVersionMetadataAttempts sync.Map // SAME original *heldReview → *nativeVersionCounts.

// NativeFixtureVersionMeasurement retains numeric counters only. It neither
// retains the Lease/review/FDs nor supplies any source or command authority.
// Capture before starting the measured operation, before that Lease can close.
type NativeFixtureVersionMeasurement struct {
	counts   *nativeVersionCounts
	metadata uint64
	children [3]uint64
}

func NativeFixtureMeasureVersions(l *Lease) *NativeFixtureVersionMeasurement {
	if l == nil || l.review == nil || l.closed.Load() {
		return nil
	}
	value, _ := nativeVersionMetadataAttempts.LoadOrStore(l.review, new(nativeVersionCounts))
	m := &NativeFixtureVersionMeasurement{counts: value.(*nativeVersionCounts)}
	m.metadata = m.counts.metadata.Load()
	for i := range m.children {
		m.children[i] = m.counts.children[i].Load()
	}
	return m
}

// Delta keeps the original generation even after Close clears Lease.review.
// A missing/regressed counter is invalid evidence, never a zero-cost result.
func (m *NativeFixtureVersionMeasurement) Delta() (uint64, [3]uint64, error) {
	var children [3]uint64
	if m == nil || m.counts == nil {
		return 0, children, fmt.Errorf("native version measurement unavailable")
	}
	metadata := m.counts.metadata.Load()
	for i := range children {
		children[i] = m.counts.children[i].Load()
	}
	if metadata < m.metadata || children[0] < m.children[0] || children[1] < m.children[1] || children[2] < m.children[2] {
		return 0, [3]uint64{}, fmt.Errorf("native version measurement regressed: metadata %d/%d children %v/%v", m.metadata, metadata, m.children, children)
	}
	for i := range children {
		children[i] -= m.children[i]
	}
	return metadata - m.metadata, children, nil
}

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
