package components

import "sync"

// Exclusive byte storage only. No descriptor, identity, expected digest or
// comparison result survives the caller. The pool may discard storage at GC.
// Six schema1 members are individually bounded to one MiB plus the EOF byte.
type managedRuntimePayloadScratch struct {
	members [6][]byte
	compare [32 << 10]byte
}

var managedRuntimePayloadPool sync.Pool

func acquireManagedRuntimePayloadScratch() *managedRuntimePayloadScratch {
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
	managedRuntimePayloadPool.Put(s)
}
