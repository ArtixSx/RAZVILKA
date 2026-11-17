//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func forwardMeasurementContext(parent context.Context) (context.Context, *domainAcceptedTCP) {
	a := &domainAcceptedTCP{}
	a.self = a
	a.open.Store(true)
	return context.WithValue(parent, domainAcceptedTCPKey{}, a), a
}

func TestDomainNativeForwardMeasurementSeparatesRequestsAndIncomplete(t *testing.T) {
	stop := StartDomainTCPNativeMeasurement()
	defer stop()
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	first, _ := forwardMeasurementContext(parent)
	second, _ := forwardMeasurementContext(context.Background())
	finish := domainTCPMeasureForwardStage(first, "pre-dial", "guard")
	domainTCPMeasureForwardStage(second, "post-dial", "decision")(nil)
	before := DomainTCPNativeForwardMeasurementSnapshot()
	if len(before.Stages) != 2 || before.Dropped != 0 {
		t.Fatal(before)
	}
	a, b := before.Stages[0], before.Stages[1]
	if a.Request != 1 || a.Completed || !a.HasContextDeadline || a.ContextRemainingStart <= 0 || a.ContextRemainingStart > time.Minute || a.ContextCanceledStart {
		t.Fatal("in-flight guard or server deadline misreported", a)
	}
	if b.Request != 2 || !b.Completed || b.ReturnedError || b.HasContextDeadline || b.ContextRemainingStart != 0 || b.ContextRemainingFinish != 0 {
		t.Fatal("separate request/no-deadline confused", b)
	}
	before.Stages[0].Completed = true
	if DomainTCPNativeForwardMeasurementSnapshot().Stages[0].Completed {
		t.Fatal("snapshot mutation changed live row")
	}
	cancel()
	finish(errors.Join(errors.New("private error must never be exported"), context.Canceled))
	finish(nil)
	a = DomainTCPNativeForwardMeasurementSnapshot().Stages[0]
	if !a.Completed || !a.ReturnedError || !a.ErrorCanceled || a.ErrorDeadline || !a.ContextCanceledFinish || a.Elapsed <= 0 || a.FinishedOffset < a.StartedOffset || a.ContextRemainingFinish >= a.ContextRemainingStart {
		t.Fatal("once/outcome/deadline accounting", a)
	}
}

func TestDomainNativeForwardMeasurementClosedBoundedAndGenerationSafe(t *testing.T) {
	stop := StartDomainTCPNativeMeasurement()
	defer stop()
	ctx, a := forwardMeasurementContext(context.Background())
	domainTCPMeasureForwardStage(ctx, "private", "guard")(nil)
	domainTCPMeasureForwardStage(ctx, "pre-dial", "private")(nil)
	domainTCPMeasureForwardStage(context.Background(), "pre-dial", "guard")(nil)
	a.open.Store(false)
	domainTCPMeasureForwardStage(ctx, "pre-dial", "guard")(nil)
	if got := DomainTCPNativeForwardMeasurementSnapshot(); len(got.Stages) != 0 || got.Dropped != 0 {
		t.Fatal("invalid/unmarked observation recorded", got)
	}
	a.open.Store(true)
	late := domainTCPMeasureForwardStage(ctx, "pre-dial", "guard")
	stale := domainTCPMeasureForwardStage(ctx, "post-dial", "guard")
	for i := 2; i < 9; i++ {
		domainTCPMeasureForwardStage(ctx, "pre-dial", "decision")(nil)
	}
	for i := 1; i < 33; i++ {
		next, _ := forwardMeasurementContext(context.Background())
		domainTCPMeasureForwardStage(next, "post-dial", "guard")(nil)
	}
	before := DomainTCPNativeForwardMeasurementSnapshot()
	if len(before.Stages) != 8+31 || before.Dropped != 2 {
		t.Fatal("request/event bounds lost", len(before.Stages), before.Dropped)
	}
	stop()
	late(context.DeadlineExceeded)
	if !reflect.DeepEqual(before, DomainTCPNativeForwardMeasurementSnapshot()) {
		t.Fatal("late completion mutated stopped measurement")
	}
	stopNext := StartDomainTCPNativeMeasurement()
	defer stopNext()
	stale(nil) // First invocation, so generation rather than once must reject it.
	if got := DomainTCPNativeForwardMeasurementSnapshot(); len(got.Stages) != 0 || got.Dropped != 0 {
		t.Fatal("late completion contaminated next generation", got)
	}
	domainTCPMeasureForwardStage(ctx, "post-dial", "compare")(context.DeadlineExceeded)
	row := DomainTCPNativeForwardMeasurementSnapshot().Stages[0]
	if row.Request != 1 || !row.ErrorDeadline || row.ErrorCanceled {
		t.Fatal("new generation/deadline classification", row)
	}
}

type forwardMeasurementReentrantError struct{}

func (forwardMeasurementReentrantError) Error() string { return "not exported" }
func (forwardMeasurementReentrantError) Is(error) bool {
	_ = DomainTCPNativeForwardMeasurementSnapshot()
	return false
}

func TestDomainNativeForwardMeasurementConcurrentSnapshots(t *testing.T) {
	stop := StartDomainTCPNativeMeasurement()
	defer stop()
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		ctx, _ := forwardMeasurementContext(context.Background())
		for _, boundary := range []string{"pre-dial", "post-dial"} {
			for _, stage := range []string{"guard", "decision", "compare"} {
				finish := domainTCPMeasureForwardStage(ctx, boundary, stage)
				workers.Add(1)
				go func() {
					defer workers.Done()
					finish(forwardMeasurementReentrantError{})
					finish(nil)
					_ = DomainTCPNativeForwardMeasurementSnapshot()
				}()
			}
		}
	}
	workers.Wait()
	got := DomainTCPNativeForwardMeasurementSnapshot()
	if len(got.Stages) != 32*6 || got.Dropped != 0 {
		t.Fatal("concurrent stage loss", len(got.Stages), got.Dropped)
	}
	for _, row := range got.Stages {
		if !row.Completed || !row.ReturnedError || row.ErrorCanceled || row.ErrorDeadline {
			t.Fatal("concurrent finish/outcome", row)
		}
	}
}
