package components

import (
	"sync"
	"sync/atomic"
)

// Exclusive byte storage only. No descriptor, identity, expected digest or
// comparison result survives the caller. The pool may discard storage at GC.
// Six schema1 members are individually bounded to one MiB plus the EOF byte.
type managedRuntimePayloadScratch struct {
	members [6][]byte
	compare [32 << 10]byte
}

var managedRuntimePayloadPool sync.Pool

// One nonblocking retained BYTE slot avoids GC/race eviction of the hot
// caller's storage. Six bounded members may retain at most 6*(1MiB+1), plus
// the fixed 32KiB comparison buffer. No identity, descriptor or proof lives
// here. Concurrent callers still use the existing independently owned pool.
var managedRuntimePayloadRetained struct {
	busy    atomic.Bool
	scratch managedRuntimePayloadScratch
}

func acquireManagedRuntimePayloadScratch() *managedRuntimePayloadScratch {
	if managedRuntimePayloadRetained.busy.CompareAndSwap(false, true) {
		return &managedRuntimePayloadRetained.scratch
	}
	if prior := managedRuntimePayloadPool.Get(); prior != nil {
		return prior.(*managedRuntimePayloadScratch)
	}
	return new(managedRuntimePayloadScratch)
}

func (s *managedRuntimePayloadScratch) member(index int, size int64) ([]byte, error) {
	if s == nil || index < 0 || index >= len(s.members) || size < 1 || size > 1<<20 {
		return nil, ErrManagedNFQWSBundle
	}
	length := int(size) + 1
	if cap(s.members[index]) < length {
		s.members[index] = make([]byte, length)
	}
	s.members[index] = s.members[index][:length]
	return s.members[index], nil
}

func releaseManagedRuntimePayloadScratch(s *managedRuntimePayloadScratch) {
	if s == nil {
		return
	}
	for _, data := range s.members {
		clear(data[:cap(data)])
	}
	clear(s.compare[:])
	if s == &managedRuntimePayloadRetained.scratch {
		// The original caller has detached slices and closed all descriptors
		// before release. Publish availability only after FULL capacity clear.
		managedRuntimePayloadRetained.busy.Store(false)
		return
	}
	managedRuntimePayloadPool.Put(s)
}
