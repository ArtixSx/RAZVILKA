package operationgate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// A durable guard runs under the admission mutex. An unrelated blocked read
// must not stop presentation of the already-committed admission and its live
// cleanup progress, nor make the pending admission succeed.
func TestSnapshotDoesNotWaitForDurableAdmissionGuard(t *testing.T) {
	for _, state := range []string{"idle", "shared", "busy"} {
		t.Run(state, func(t *testing.T) {
			var g Gate
			var block atomic.Bool
			var calls atomic.Int32
			entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var resumeOnce sync.Once
			denied := errors.New("modeled durable recovery refusal")
			if err := g.SetGuard(func(context.Context) error {
				calls.Add(1)
				if !block.Load() {
					return nil
				}
				close(entered)
				<-resume
				return denied
			}); err != nil {
				t.Fatal(err)
			}
			ctx, update := WithProgress(WithLabel(context.Background(), "Автопилот"), "autonomy")
			deadline := time.Now().Add(time.Minute)
			ctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			if state != "idle" {
				enter := g.Enter
				if state == "busy" {
					enter = g.Exclusive
				}
				release, err := enter(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				update("checking", "youtube")
			}
			before := g.Snapshot()
			generation, _ := g.IdleGeneration()
			priorCalls := calls.Load()
			block.Store(true)
			var attemptErr error
			var admitted bool
			go func() {
				defer close(done)
				release, err := g.Enter(context.Background())
				attemptErr, admitted = err, release != nil
				if release != nil {
					release()
				}
			}()
			// Unblock before releasing the original holder, including on a
			// regression failure. The pre-fix Snapshot can then also return.
			defer func() {
				resumeOnce.Do(func() { close(resume) })
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("guarded admission did not finish after resuming")
				}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("admission did not reach the guard")
			}
			cancel()
			update("cleanup", "youtube")
			read := make(chan Snapshot, 1)
			go func() { read <- g.snapshotAt(deadline.Add(time.Second)) }()
			select {
			case s := <-read:
				if s.State != state || s.Active != before.Active || s.Exclusive != before.Exclusive || s.Fenced {
					t.Fatalf("blocked guard changed committed admission: %+v", s)
				}
				if state == "idle" {
					if s.Progress != nil || s.Operation != "" {
						t.Fatalf("unadmitted operation leaked progress: %+v", s)
					}
				} else if p := s.Progress; p == nil || p.ID != before.Progress.ID || p.Phase != "cleanup" || p.ServiceID != "youtube" || !p.DeadlineExceeded || p.ElapsedSeconds <= before.Progress.ElapsedSeconds || p.RemainingSeconds == nil || *p.RemainingSeconds != 0 {
					t.Fatalf("blocked guard froze progress or cancellation released its holder: %+v", p)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("memory-only snapshot waited for the durable admission guard")
			}
			if calls.Load() != priorCalls+1 {
				t.Fatal("snapshot consulted the durable guard")
			}
			select {
			case <-done:
				t.Fatal("snapshot bypassed the pending admission guard")
			default:
			}
			resumeOnce.Do(func() { close(resume) })
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("admission did not finish after guard refusal")
			}
			if admitted || !errors.Is(attemptErr, denied) {
				t.Fatalf("guard refusal lost: admitted=%v err=%v", admitted, attemptErr)
			}
			if after, _ := g.IdleGeneration(); after != generation {
				t.Fatal("snapshot or refused admission changed generation")
			}
		})
	}
}
