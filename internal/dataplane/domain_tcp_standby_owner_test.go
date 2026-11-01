package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDomainTCPStandbyCannotBeIssuedFromMetadataOrCopiedOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, original := range []*DomainTCPOriginalScope{nil, {}, {standbyReady: true, closed: true}} {
		if original != nil {
			original.self = original
		}
		if err := original.standbyCurrent(ctx); err == nil {
			t.Fatal("missing original native/COMMON owner admitted")
		}
		if err := original.RetainStandby(ctx, nil); err == nil {
			t.Fatal("missing original fleet owner admitted")
		}
	}
	original := &DomainTCPOriginalScope{}
	original.self = original
	copy := DomainTCPOriginalScope{self: original}
	if err := copy.standbyCurrent(ctx); err == nil {
		t.Fatal("copied original owner admitted")
	}
	owner := &domainTCPStandbyOwner{original: original}
	owner.self = owner
	if err := owner.current(); err == nil {
		t.Fatal("retained status without actual handoff")
	}
}

func TestDomainTCPStandbyPendingCloseRevokesForwardAndRetainsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := &executionResourceScope{ctx: ctx, cancel: cancel, open: true, retained: true}
	owner := &retainedXrayExecution{scope: scope, standby: &domainTCPStandbyOwner{}, pending: true}
	owner.self = owner
	scope.retainedXrayOwner = owner
	scope.observationOpen.Store(true)
	if err := scope.close(); !errors.Is(err, ErrPolicyAdditionUnknown) || ctx.Err() == nil || scope.observationOpen.Load() {
		t.Fatal("pending handoff retained forward permission or lost its fence", err)
	}
	if scope.retainedXrayOwner != owner || !scope.open || !owner.pending {
		t.Fatal("pending original custody discarded")
	}
}
