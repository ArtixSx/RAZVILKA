package components

import (
	"bytes"
	"runtime"
	"testing"
)

func TestManagedRuntimeRetainedScratchBusyFallbackAndFullClear(t *testing.T) {
	first := acquireManagedRuntimePayloadScratch()
	if first != &managedRuntimePayloadRetained.scratch {
		t.Fatal("retained slot unexpectedly busy")
	}
	defer releaseManagedRuntimePayloadScratch(first)
	for i := range first.members {
		data, err := first.member(i, 65536)
		if err != nil {
			t.Fatal(err)
		}
		for j := range data {
			data[j] = 0xa5
		}
		if _, err := first.member(i, 5); err != nil {
			t.Fatal(err)
		}
	}
	for i := range first.compare {
		first.compare[i] = 0xa5
	}
	other := acquireManagedRuntimePayloadScratch()
	if other == first {
		t.Fatal("busy slot shared storage")
	}
	for i := range other.members {
		data, err := other.member(i, 17)
		if err != nil || !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("fallback not fresh", err)
		}
	}
	releaseManagedRuntimePayloadScratch(other)
}

func TestManagedRuntimeRetainedScratchSurvivesGCAndPanicAfterClear(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected panic disappeared")
			}
		}()
		s := acquireManagedRuntimePayloadScratch()
		defer releaseManagedRuntimePayloadScratch(s)
		if s != &managedRuntimePayloadRetained.scratch {
			t.Fatal("retained slot unexpectedly busy")
		}
		for i := range s.members {
			data, err := s.member(i, 65536)
			if err != nil {
				t.Fatal(err)
			}
			for j := range data {
				data[j] = 0xff
			}
			if _, err := s.member(i, 3); err != nil {
				t.Fatal(err)
			}
		}
		for i := range s.compare {
			s.compare[i] = 0xff
		}
		panic("test-only exit from owned borrower")
	}()
	runtime.GC()
	runtime.GC()
	s := acquireManagedRuntimePayloadScratch()
	defer releaseManagedRuntimePayloadScratch(s)
	if s != &managedRuntimePayloadRetained.scratch {
		t.Fatal("GC discarded retained storage")
	}
	for _, data := range s.members {
		if cap(data) < 65537 || !bytes.Equal(data[:cap(data)], make([]byte, cap(data))) {
			t.Fatal("full capacity not retained/cleared")
		}
	}
	if !bytes.Equal(s.compare[:], make([]byte, len(s.compare))) {
		t.Fatal("comparison bytes survived")
	}
}
