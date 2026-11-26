package components

import (
	"bytes"
	"sync"
	"testing"
)

func TestManagedRuntimePayloadScratchExclusiveAndCleared(t *testing.T) {
	var joined sync.WaitGroup
	for worker := 1; worker <= 8; worker++ {
		joined.Add(1)
		go func(value byte) {
			defer joined.Done()
			for pass := 0; pass < 16; pass++ {
				s := acquireManagedRuntimePayloadScratch()
				for index := range s.members {
					data, err := s.member(index, int64(4096+pass))
					if err != nil {
						t.Error(err)
						return
					}
					if !bytes.Equal(data, make([]byte, len(data))) {
						t.Error("prior payload survived release")
					}
					for i := range data {
						data[i] = value
					}
				}
				// Keep all six members borrowed concurrently, so neither another
				// member nor another caller can overwrite a first-read image.
				for _, data := range s.members {
					for _, got := range data {
						if got != value {
							t.Error("concurrent caller/member shared payload storage")
							break
						}
					}
				}
				releaseManagedRuntimePayloadScratch(s)
			}
		}(byte(worker))
	}
	joined.Wait()
}

func TestManagedRuntimePayloadScratchBounds(t *testing.T) {
	s := acquireManagedRuntimePayloadScratch()
	defer releaseManagedRuntimePayloadScratch(s)
	for _, pair := range [][2]int64{{-1, 1}, {6, 1}, {0, 0}, {0, 1<<20 + 1}} {
		if _, err := s.member(int(pair[0]), pair[1]); err == nil {
			t.Fatal("invalid storage range accepted", pair)
		}
	}
	data, err := s.member(0, 1<<20)
	if err != nil || len(data) != 1<<20+1 {
		t.Fatal("largest payload lost mandatory trailing EOF byte", len(data), err)
	}
}
