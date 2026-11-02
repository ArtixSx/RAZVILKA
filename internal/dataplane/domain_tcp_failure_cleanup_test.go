package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestDomainFailureCapsuleKeepsOriginalErrorAndCursor(t *testing.T) {
	cause := errors.New("original action error")
	c := &domainTCPGlobalSuccessor{}
	s := &executionResourceScope{domainSuccessor: c}
	if got := domainTCPFailureWithCustody(s, cause); got != cause {
		t.Fatal("ordinary error wrapped without failed custody")
	}
	c.failedCustody.Store(true)
	err := domainTCPFailureWithCustody(s, cause)
	var failure *DomainTCPCleanupFailure
	if !errors.As(err, &failure) || !errors.Is(err, cause) || failure.self != failure || failure.cursor != c {
		t.Fatal("original failure/custody lost", err)
	}
}

func TestDomainFailureNativeReturnIsNotInferredFromUnlockedResource(t *testing.T) {
	p := &XrayDomainTCPExecutionResource{}
	p.self = p
	if !p.mu.TryLock() {
		t.Fatal("fixture mutex")
	}
	defer p.mu.Unlock()
	if err := p.failureNativeReturnedLocked(); err == nil {
		t.Fatal("missing producer treated as joined")
	}
	p.nativeDone = make(chan struct{})
	if err := p.failureNativeReturnedLocked(); err == nil {
		t.Fatal("unlocked resource treated live callback as joined")
	}
	close(p.nativeDone)
	if err := p.failureNativeReturnedLocked(); err != nil {
		t.Fatal("actual return channel refused", err)
	}
}

// Actual Gate/control/cleanup lifetime, with a deliberately incomplete native
// resource. These are association refusals, never process cleanup evidence.
func TestDomainFailureCleanupIsOriginalFiniteAndRevoked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	root := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(held, root); err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(held, root)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	cleanup, err := control.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	c := &domainTCPGlobalSuccessor{}
	s := &executionResourceScope{domainSuccessor: c}
	p := &XrayDomainTCPExecutionResource{scope: s}
	p.self = p
	m := &XrayDomainTCPOperationMaterial{resource: p, control: control}
	m.self = m
	p.material = m
	r := &domainTCPFailureCleanup{cursor: c, resource: p, control: control, cleanup: cleanup}
	r.self = r
	c.cleanup = r
	c.failedCustody.Store(true)
	r.ctx = context.WithValue(held, domainTCPFailureCleanupKey{}, r)
	r.active.Store(true)
	if err := r.local(r.ctx, p); err != nil {
		t.Fatal("original comparison association", err)
	}
	if !domainTCPFailureCleanupOwner(r.ctx, s) {
		t.Fatal("original scope association refused")
	}
	for _, mode := range []string{"copied", "foreign-context", "foreign-resource", "revoked", "forward-custody", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			check, call, resource := r, r.ctx, p
			switch mode {
			case "copied":
				check = &domainTCPFailureCleanup{self: r, cursor: c, resource: p, control: control, cleanup: cleanup, ctx: r.ctx}
				check.active.Store(true)
			case "foreign-context":
				call = held
			case "foreign-resource":
				resource = &XrayDomainTCPExecutionResource{}
			case "revoked":
				r.active.Store(false)
				defer r.active.Store(true)
			case "forward-custody":
				c.failedCustody.Store(false)
				defer c.failedCustody.Store(true)
			case "canceled":
				var stop context.CancelFunc
				call, stop = context.WithCancel(r.ctx)
				stop()
			}
			if err := check.local(call, resource); err == nil {
				t.Fatal("foreign/late cleanup accepted", mode)
			}
		})
	}
	if _, err := p.cleanupReview(context.WithValue(held, domainTCPFailureCleanupKey{}, "forged")); err == nil {
		t.Fatal("untyped marker fell back to original cleanup")
	}
	r.active.Store(false)
	if _, err := p.cleanupReview(r.ctx); err == nil {
		t.Fatal("expired cleanup returned a review")
	}
}
