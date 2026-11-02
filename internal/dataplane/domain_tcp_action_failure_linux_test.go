//go:build linux

package dataplane

import (
	"context"
	"errors"
	"testing"
)

// Real original directory/journal FD custody, with no native resource/source
// issuer. This proves exceptional return/panic never closes/adopts those FDs.
func TestDomainActionExceptionKeepsOriginalDescriptorsAndError(t *testing.T) {
	for _, mode := range []string{"error", "panic", "nil-entered"} {
		t.Run(mode, func(t *testing.T) {
			k, ctx := domainTCPKeeperFilesFixture(t)
			s, c := k.cursor.scope, k.cursor
			s.observationOpen.Store(true)
			c.actionStarted = true
			failure := errors.New("original callback error")
			func() {
				defer func() {
					got := recover()
					if mode == "panic" {
						if got != failure {
							t.Fatal("panic changed", got)
						}
					} else if got != nil {
						panic(got)
					}
				}()
				err := domainTCPActionWithCustody(s, func(context.Context) error {
					if mode == "panic" {
						panic(failure)
					}
					if mode == "error" {
						return failure
					}
					return nil
				})
				if mode == "error" && !errors.Is(err, failure) {
					t.Fatal("original callback error lost", err)
				}
			}()
			if err := s.close(); !errors.Is(err, ErrPolicyAdditionUnknown) {
				t.Fatal("exceptional scope pretended retired", err)
			}
			if !c.failedCustody.Load() || !s.pending || !s.open || s.ctx.Err() == nil || s.observationOpen.Load() {
				t.Fatal("forward context survived or custody disappeared")
			}
			if _, err := s.owned.RootInfo(); err != nil {
				t.Fatal("original scope root closed", err)
			}
			if err := k.records.current(ctx, true); err != nil {
				t.Fatal("original journal descriptors lost", err)
			}
			if err := s.requestDomainFailureStandby(ctx); err == nil {
				t.Fatal("metadata fixture minted standby without native proof")
			}
		})
	}
}

func TestDomainFailedCloseJoinsOriginalStartBarrier(t *testing.T) {
	k, ctx := domainTCPKeeperFilesFixture(t)
	s, c := k.cursor.scope, k.cursor
	c.actionStarted = true
	c.failedCustody.Store(true)
	s.startMu.RLock()
	done := make(chan error, 1)
	go func() { done <- s.close() }()
	select {
	case <-s.ctx.Done():
	case <-ctx.Done():
		t.Fatal("close did not revoke source", ctx.Err())
	}
	select {
	case err := <-done:
		s.startMu.RUnlock()
		t.Fatal("close escaped original actual Start barrier", err)
	default:
	}
	s.startMu.RUnlock()
	select {
	case err := <-done:
		if !errors.Is(err, ErrPolicyAdditionUnknown) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := k.records.current(ctx, true); err != nil {
		t.Fatal(err)
	}
}
