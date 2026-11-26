package dataplane

import (
	"errors"
	"testing"
)

func TestDomainOriginalPredecessorInventoryRequiresIndependentMatchingClosing(t *testing.T) {
	err := domainSuccessorReadModel(t, func(read *domainTCPSuccessorRead, _ *XrayDomainTCPExecutionResource) error {
		capture := &domainTCPCaptureExecutionResource{}
		old := &DomainTCPOriginalScope{captureResource: capture}
		old.self = old
		entry := &domainTCPStandbyPoolEntry{detached: &DomainTCPDetachedStandby{original: old}}
		pool := read.cursor.pool
		pool.manager.domainPool = pool
		pool.entries = []*domainTCPStandbyPoolEntry{entry}
		pair := &domainTCPPredecessorInventories{root: read, entry: entry, previous: capture, count: 1}
		read.inventories = pair
		pair.samples[0] = backendInventorySnapshot{Rows: []backendInventoryRow{{Family: 4, Table: "filter", Tokens: []string{"-P", "FORWARD", "ACCEPT"}}}}
		assertRefuses := func(reason string) {
			t.Helper()
			view, err := pair.completed(read.rootCtx)
			if !errors.Is(err, ErrPolicyAdditionUnknown) || len(view.Rows) != 0 {
				t.Fatalf("%s returned tentative predecessor rows: %v", reason, err)
			}
		}
		assertRefuses("missing second observation")
		pair.samples[1] = backendInventorySnapshot{Rows: []backendInventoryRow{{Family: 4, Table: "filter", Tokens: []string{"-P", "FORWARD", "DROP"}}}}
		pair.count = 2
		assertRefuses("closing policy changed")
		pair.samples[1] = backendInventorySnapshot{Rows: []backendInventoryRow{{Family: 4, Table: "filter", Tokens: []string{"-P", "FORWARD", "ACCEPT"}}}}
		view, err := pair.completed(read.rootCtx)
		if err != nil || len(view.Rows) != 1 {
			t.Fatalf("matching observations in the original comparison refused: %v", err)
		}
		pool.entries[0] = &domainTCPStandbyPoolEntry{detached: entry.detached}
		assertRefuses("replaced predecessor")
		pool.entries[0] = entry
		old.captureResource = &domainTCPCaptureExecutionResource{}
		assertRefuses("replaced predecessor capture")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
