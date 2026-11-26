package routerstats

import (
	"sync"
	"testing"
	"time"
)

func TestReadoutIsCoherentAndDetachedFromSampler(t *testing.T) {
	s := New(Collector{WANDetector: func() string { panic("passive read collected") }})
	first := Snapshot{Timestamp: time.Unix(100, 0), RXBytes: 10}
	s.latest, s.history, s.persisted = first, []Snapshot{first}, []Snapshot{first}
	view := s.Readout(1, false)
	view.History[0].RXBytes, view.TrafficHistory[0].RXBytes = 99, 99
	if s.Readout(1, true).History[0].RXBytes != 10 || s.Readout(1, false).History[0].RXBytes != 10 {
		t.Fatal("returned internal storage")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			next := Snapshot{Timestamp: time.Unix(int64(i)+101, 0), RXBytes: uint64(i)}
			s.mu.Lock()
			s.latest, s.history = next, []Snapshot{next}
			s.mu.Unlock()
		}
	}()
	defer wg.Wait()
	for i := 0; i < 1000; i++ {
		v := s.Readout(1, false)
		if len(v.History) != 1 || v.Latest != v.History[0] {
			t.Fatal("mixed observations")
		}
	}
}
