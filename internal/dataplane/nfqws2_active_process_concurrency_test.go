package dataplane

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNFQWSActiveRetainedPreparedReadCannotSurviveCommit(t *testing.T) {
	for _, method := range []string{"Observe", "VerifyOwnerObservation"} {
		t.Run(method, func(t *testing.T) {
			m := nfqws2ActiveOwnerFixture(t)
			ctx := m.request
			obs := m.lease.observation()
			entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			var blocked atomic.Bool
			if method == "Observe" {
				old := m.owner.admission.Current
				m.owner.admission.Current = func(c context.Context, b NFQWSExecutionBinding) error {
					if blocked.CompareAndSwap(false, true) {
						close(entered)
						<-release
					}
					return old(c, b)
				}
			} else {
				old := m.owner.read
				m.owner.read = func(c context.Context, live bool) (nfqws2ActiveProcessLease, error) {
					if blocked.CompareAndSwap(false, true) {
						close(entered)
						<-release
					}
					return old(c, live)
				}
			}
			go func() {
				if method == "Observe" {
					_, err := m.prepared.Observe(ctx)
					returned <- err
				} else {
					returned <- m.prepared.VerifyOwnerObservation(ctx, obs)
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("prepared operation did not enter")
			}
			c, k := m.guards()
			a, err := m.prepared.CommitPrepared(ctx, c, k)
			close(release)
			if err != nil || a == nil {
				t.Fatal("prepared reader blocked commit through a guard lock", err)
			}
			select {
			case err := <-returned:
				if !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
					t.Fatal("retained prepared read returned authority after D", err)
				}
			case <-time.After(time.Second):
				t.Fatal("prepared reader did not join")
			}
		})
	}
}

// ROOT can run this same regression under Linux -race. It covers field
// revocation between the original self/state check and operation completion.
func TestNFQWSActiveConcurrentPreparedReadsAndCommit(t *testing.T) {
	for iteration := 0; iteration < 16; iteration++ {
		m := nfqws2ActiveOwnerFixture(t)
		ctx := m.request
		obs := m.lease.observation()
		start, stop := make(chan struct{}), make(chan struct{})
		var joined sync.WaitGroup
		for reader := 0; reader < 2; reader++ {
			joined.Add(1)
			go func() {
				defer joined.Done()
				<-start
				for {
					select {
					case <-stop:
						return
					default:
					}
					_, _ = m.prepared.Observe(ctx)
					_ = m.prepared.VerifyOwnerObservation(ctx, obs)
				}
			}()
		}
		close(start)
		c, k := m.guards()
		a, err := m.prepared.CommitPrepared(ctx, c, k)
		close(stop)
		joined.Wait()
		if err != nil || a == nil {
			t.Fatal("concurrent prepared observation invalidated exact commit", err)
		}
		if m.prepared.VerifyOwnerObservation(context.Background(), obs) == nil {
			t.Fatal("revoked prepared handle remained valid")
		}
	}
}
