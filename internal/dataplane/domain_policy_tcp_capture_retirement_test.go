package dataplane

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Actual listener, original capture and synchronous scope; original backend/
// process/physical registration is the existing explicit synthetic fixture.
// Early handler work below is a joined goroutine model, not native packet proof.
func TestDomainPolicySyntheticTCPCaptureRetirementNeedsWholeScopeJoin(t *testing.T) {
	f, p, spec, owner := syntheticTCPModelFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := f.a.WithDomainPolicyTCPXray(ctx, spec.Xray, owner, func(ctx context.Context, xray *DomainPolicyTCPXray) error {
		capture := syntheticCaptureObjectModel(t, ctx, p, spec, owner, xray)
		retirement, err := capture.Retirement(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(retirement.Joined(ctx), ErrDomainPolicyTCPCaptureRetirementPending) {
			t.Fatal("live carrier became terminal")
		}
		frameStarted, releaseFrame, captureClosed, scopeDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		var scopeErr error
		go func() {
			scopeErr = domainPolicyTCPSynchronousScope(ctx, func(consume func(context.Context) error) error { return consume(ctx) }, func(context.Context) error {
				var frames sync.WaitGroup
				frames.Add(1)
				go func() { defer frames.Done(); close(frameStarted); <-releaseFrame }()
				<-frameStarted
				if err := capture.Close(); err != nil {
					return err
				}
				close(captureClosed)
				frames.Wait() // actual joined early-frame model, before scope return
				return nil
			})
			// Production calls this exact terminal producer in its return defer,
			// after the synchronous scope's real ALL-handler WaitGroup returned.
			capture.completeRetirement()
			close(scopeDone)
		}()
		select {
		case <-captureClosed:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if err := retirement.Joined(ctx); !errors.Is(err, ErrDomainPolicyTCPCaptureRetirementPending) {
			t.Fatal("Close alone granted retirement while early handler was blocked", err)
		}
		if _, err := capture.Retirement(ctx); err == nil {
			t.Fatal("closed capture issued a new carrier")
		}
		close(releaseFrame)
		select {
		case <-scopeDone:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if scopeErr != nil {
			t.Fatal(scopeErr)
		}
		if err := retirement.Joined(ctx); err != nil {
			t.Fatal("original full join did not publish terminal carrier", err)
		}
		endpoint, err := retirement.Endpoint(ctx)
		actual, addrErr := capture.Address()
		if err != nil || addrErr != nil || endpoint != actual || endpoint != capture.spec.Listen {
			t.Fatal("terminal endpoint lost original listener identity", err)
		}
		capture.completeRetirement() // original producer is idempotent
		if err := retirement.Joined(ctx); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDomainPolicySyntheticTCPCaptureRetirementRefusesCopiedOrUnboundedReaders(t *testing.T) {
	f, p, spec, owner := syntheticTCPModelFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := f.a.WithDomainPolicyTCPXray(ctx, spec.Xray, owner, func(ctx context.Context, xray *DomainPolicyTCPXray) error {
		capture := syntheticCaptureObjectModel(t, ctx, p, spec, owner, xray)
		retirement, err := capture.Retirement(ctx)
		if err != nil {
			t.Fatal(err)
		}
		copy := &DomainPolicyTCPCaptureRetirement{self: retirement, capture: capture, endpoint: retirement.endpoint, done: retirement.done}
		if copy.Joined(ctx) == nil {
			t.Fatal("copy became original carrier")
		}
		captureCopy := &DomainPolicyTCPCapture{self: capture, retirement: retirement}
		if _, err := captureCopy.Retirement(ctx); err == nil {
			t.Fatal("copied capture issued original carrier")
		}
		for _, invalid := range []context.Context{nil, context.Background()} {
			if _, err := capture.Retirement(invalid); err == nil {
				t.Fatal("unbounded acquisition accepted")
			}
		}
		capture.completeRetirement() // explicit source-level joined-end model
		canceled, stop := context.WithCancel(ctx)
		stop()
		for _, invalid := range []context.Context{nil, context.Background(), canceled} {
			if retirement.Joined(invalid) == nil {
				t.Fatal("invalid terminal context accepted")
			}
		}
		if err := retirement.Joined(ctx); err != nil {
			t.Fatal("invalid read poisoned original terminal carrier", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
