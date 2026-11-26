package dataplane

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDomainTCPOriginalPublicationPhaseCannotCreateAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	o := &DomainTCPOriginalScope{}
	o.self = o
	// Incomplete original state deliberately has no source, registration,
	// resource, kernel or mapping. Reentrant reads must refuse without opening
	// any of them; the phase bit alone can never construct their authority.
	if o.CurrentSyntheticMapping(ctx, nil) == nil {
		t.Fatal("unopened publication admitted")
	}
	if o.publicationOpen {
		t.Fatal("read opened its own publication phase")
	}
	if o.compareSyntheticMapping(ctx, nil) == nil || o.publicationOpen {
		t.Fatal("failed first producer compare opened phase")
	}
	o.mu.Lock()
	o.publicationOpen = true
	o.mu.Unlock()
	if o.CurrentSyntheticMapping(ctx, nil) == nil {
		t.Fatal("phase bit replaced actual source/kernel comparison")
	}
	o.mu.Lock()
	o.closed = true
	o.mu.Unlock()
	if o.CurrentSyntheticMapping(ctx, nil) == nil {
		t.Fatal("closed original publication admitted")
	}
	cancel()
	if o.CurrentSyntheticMapping(ctx, nil) == nil {
		t.Fatal("canceled original publication admitted")
	}
}

func TestDomainTCPOriginalPublicationPhaseParallelReadsRemainClosed(t *testing.T) {
	o := &DomainTCPOriginalScope{}
	o.self = o
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 50 {
				if o.CurrentSyntheticMapping(ctx, nil) == nil {
					t.Error("reentrant unopened read became ready")
				}
			}
		}()
	}
	workers.Wait()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.publicationOpen || o.closed {
		t.Fatal("readonly reentry mutated producer phase")
	}
}
