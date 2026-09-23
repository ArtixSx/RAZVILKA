package operationgate

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestSnapshotStatesAndAdmissionRemainIndependent(t *testing.T) {
	var g Gate
	if s := g.Snapshot(); s.State != "idle" || s.Active != 0 || s.Fenced {
		t.Fatalf("zero: %+v", s)
	}
	release, err := g.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s := g.Snapshot(); s.State != "shared" || s.Active != 1 || s.Exclusive {
		t.Fatalf("shared: %+v", s)
	}
	release()
	release()
	exclusive, err := g.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s := g.Snapshot(); s.State != "busy" || !s.Exclusive || s.Active != 1 {
		t.Fatalf("exclusive: %+v", s)
	}
	if _, err := g.Enter(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("snapshot changed admission: %v", err)
	}
	g.Fence()
	if s := g.Snapshot(); s.State != "recovery-required" || !s.Fenced {
		t.Fatalf("fenced: %+v", s)
	}
	exclusive()
	if s := g.Snapshot(); s.State != "recovery-required" || s.Active != 0 || s.Exclusive {
		t.Fatalf("released fenced: %+v", s)
	}
	if _, err := g.Enter(context.Background()); !errors.Is(err, ErrRecovery) {
		t.Fatal("snapshot must never clear recovery fence")
	}
}

func TestSnapshotConcurrentReadersAndWorkers(t *testing.T) {
	var g Gate
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := 0; n < 400; n++ {
				if worker%2 == 0 {
					if release, err := g.Enter(context.Background()); err == nil {
						release()
					}
				} else if release, err := g.Exclusive(context.Background()); err == nil {
					release()
				}
				s := g.Snapshot()
				if s.Exclusive && s.Active != 1 {
					t.Errorf("inconsistent snapshot: %+v", s)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if s := g.Snapshot(); s.Active != 0 || s.State != "idle" {
		t.Fatalf("leaked ownership: %+v", s)
	}
}

func TestSnapshotDoesNotAcquireOrReleaseAnOperation(t *testing.T) {
	var g Gate
	release, err := g.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 1000; n++ {
		if g.Snapshot().State != "busy" {
			t.Fatal("worker ownership lost")
		}
	}
	release()
	if g.Snapshot().State != "idle" {
		t.Fatal("worker release did not restore idle state")
	}
}
