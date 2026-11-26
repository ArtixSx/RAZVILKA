package telemetry

import (
	"sync"
	"testing"
)

func TestReadoutKeepsRowsCountersAndProducerTogether(t *testing.T) {
	s := NewStore()
	s.Upsert(Connection{ID: "test", Chain: []string{"original"}})
	v := s.Readout(false)
	v.Connections[0].Chain[0] = "changed"
	if s.Readout(false).Connections[0].Chain[0] != "original" {
		t.Fatal("shared chain")
	}
	s.Close("test")
	v = s.Readout(true)
	if v.Active != 0 || v.Closed != 1 || len(v.Connections) != 1 || v.Connections[0].Active {
		t.Fatal("closed rows mixed")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			s.ReplaceActive("populated", []Connection{{ID: "one"}, {ID: "two"}})
			s.ReplaceActive("empty", nil)
		}
	}()
	defer wg.Wait()
	for i := 0; i < 1000; i++ {
		v := s.Readout(false)
		if len(v.Connections) != v.Active || v.Producer == "empty" && v.Active != 0 || v.Producer == "populated" && v.Active != 2 {
			t.Fatal("mixed producer/counters/rows")
		}
	}
}
