package dataplane

import (
	"encoding/json"
	"errors"
	"runtime"
	"sync"
	"testing"
)

// Real original journal descriptors; packet/kernel ownership remains a model.
// Neither snapshot may promote this model into a genuine known footprint.
func TestDomainStandbyConcurrentPendingSnapshotsKeepOriginalCustody(t *testing.T) {
	r, retained, _ := standbyRetirementPublicationModel(t)
	s := retained.scope
	m := s.manager
	s.mu.Lock()
	record := *s.execution
	record.Resources = cloneExecutionResources(record.Resources)
	record.Steps = append([]ExecutionStep(nil), record.Steps...)
	s.mu.Unlock()
	var actors sync.WaitGroup
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writerErr := make(chan error, 1)
	actors.Add(1)
	go func() {
		defer actors.Done()
		for range 50 {
			s.mu.Lock()
			retained.pending = true
			s.mu.Unlock()
			// The actual original writer replaces its global inode while a
			// snapshot that entered before pending=true may still be reading.
			file, err := retained.records.root.WriteAtomicRetained("latest-execution.json", data, 0600)
			if err != nil {
				writerErr <- err
				return
			}
			info, err := file.Stat()
			if err != nil {
				writerErr <- errors.Join(err, file.Close())
				return
			}
			if err := r.owner.replaceGlobalRecord(file, info); err != nil {
				writerErr <- err
				return
			}
			s.mu.Lock()
			retained.pending = false
			s.mu.Unlock()
			runtime.Gosched()
		}
	}()
	for range 500 {
		_ = m.HasPendingManagedXraySelectedTCP()
		// Errors during the rename/install boundary are expected. These
		// reads must retain a synchronized SAME original descriptor.
		_ = r.owner.globalRecordCurrent(m.StateRoot, record)
		if m.checkKnownDomainStandbyRecord(record) == nil {
			t.Error("pending snapshot manufactured original kernel/cleanup proof")
			break
		}
	}
	actors.Wait()
	select {
	case err := <-writerErr:
		t.Fatal(err)
	default:
	}
	if m.retainedXrayOwner() != retained || r.owner.original.standbyOwner != r.owner {
		t.Fatal("readonly snapshots changed original custody")
	}
}
