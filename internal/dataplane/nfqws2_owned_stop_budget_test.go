package dataplane

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

// Exercise the complete real first-start stop/Deactivate path with modeled
// proc/kernel callbacks. A millisecond generic cap demonstrates the regression
// without a real20s/60s delay; it is not native packet/process acceptance.
func TestNFQWSOwnedStopUsesRemainingLifecycleBudget(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	original := f.a.Runner
	f.a.Timeout = time.Millisecond
	ctx, cancel := context.WithTimeout(firstStartContext(t), 500*time.Millisecond)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	stops := 0
	f.a.Runner = nfqws2RunFunc(func(c context.Context, name string, args ...string) ([]byte, error) {
		if name == f.a.InitPath && len(args) == 1 && args[0] == "owned_stop" {
			stops++
			deadline, finite := c.Deadline()
			if !finite || deadline.After(parentDeadline) || time.Until(deadline) <= 50*time.Millisecond {
				t.Fatal("stop used generic cap or extended parent", deadline, parentDeadline)
			}
			select {
			case <-time.After(15 * time.Millisecond):
			case <-c.Done():
				return nil, c.Err()
			}
		}
		return original.Run(c, name, args...)
	})
	if err := f.a.Deactivate(ctx); err != nil || stops != 1 {
		t.Fatal("slow valid stop did not settle once", err, stops)
	}
	f.assertStopped(t)
}

func TestNFQWSOwnedStopCancellationNeverPublishesStoppedReceipt(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, exec.ErrWaitDelay} {
		t.Run(cause.Error(), func(t *testing.T) {
			f := newFirstStartFixture(t)
			f.apply(t)
			before, err := f.a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			original := f.a.Runner
			f.a.Runner = nfqws2RunFunc(func(c context.Context, name string, args ...string) ([]byte, error) {
				if name == f.a.InitPath && len(args) == 1 && args[0] == "owned_stop" {
					// Even physical absence plus misleading legacy output cannot turn a
					// command lifetime failure into a successful receipt in this operation.
					if _, err := original.Run(c, name, args...); err != nil {
						t.Fatal(err)
					}
					return []byte("Service NFQWS2 is not running"), cause
				}
				return original.Run(c, name, args...)
			})
			if err := f.a.Deactivate(firstStartContext(t)); !errors.Is(err, cause) {
				t.Fatal("stop swallowed lifetime error", err)
			}
			after, err := f.a.readLease()
			if err != nil || !reflect.DeepEqual(after, before) || after.FirstStart.Phase != nfqws2FirstRunning {
				t.Fatal("failed command cleared/published ownership", err)
			}
		})
	}
}

func TestNFQWSCommandDeadlineCausePreservedAndGenericCapUnchanged(t *testing.T) {
	a := &NFQWS2Adapter{InitPath: "/unused/init", Timeout: 5 * time.Millisecond}
	calls := 0
	a.Runner = nfqws2RunFunc(func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		calls++
		<-ctx.Done()
		return nil, errors.New("process killed")
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := a.run(ctx, "/unused/read"); !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatal("deadline cause lost", err, calls)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := a.run(canceled, "/unused/read"); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("canceled call executed or cause lost", err, calls)
	}
}
