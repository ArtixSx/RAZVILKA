//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func testMihomoLiveCleanupReadObservationOriginalBookends(t *testing.T, ctx context.Context, p *MihomoLiveProcess, fresh, released, foreign *operationgate.ExclusiveCleanupReview) {
	t.Helper()
	for _, review := range []*operationgate.ExclusiveCleanupReview{nil, released, foreign} {
		called := false
		if err := p.WithCleanupReadObservation(ctx, review, func(context.Context, *MihomoLiveCleanupObservation) error { called = true; return nil }); err == nil || called {
			t.Error("invalid cleanup review issued view")
		}
	}
	if err := p.WithReadObservation(ctx, func(context.Context, *MihomoLiveObservation) error { return nil }); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Error("stopped child issued forward view", err)
	}
	s := p.source
	original := s.origin
	counter := &mihomoObservedOriginCounter{mihomoProbeOriginOwner: original}
	s.origin = counter
	defer func() { s.origin = original }()
	callbackErr := errors.New("actual cleanup read callback error")
	var late *MihomoLiveCleanupObservation
	var lateCtx context.Context
	err := p.WithCleanupReadObservation(ctx, fresh, func(held context.Context, v *MihomoLiveCleanupObservation) error {
		late, lateCtx = v, held
		if !v.BoundTo(p, s, fresh) || v.BoundTo(p, s, released) {
			t.Error("cleanup handle binding")
		}
		for range 4 {
			if err := v.Current(held); err != nil {
				t.Error("original stopped native read", err)
			}
		}
		if counter.reads.Load() != 1 {
			t.Error("nested cleanup source reads", counter.reads.Load())
		}
		if v.Current(ctx) == nil {
			t.Error("foreign context admitted")
		}
		copy := &MihomoLiveCleanupObservation{self: v, inner: v.inner, cleanup: fresh}
		if copy.Current(held) == nil || copy.PID() != 0 {
			t.Error("copied cleanup view admitted")
		}
		canceled, cancel := context.WithCancel(held)
		cancel()
		if !errors.Is(v.Current(canceled), context.Canceled) {
			t.Error("cleanup cancellation lost")
		}
		return callbackErr
	})
	if !errors.Is(err, callbackErr) || counter.reads.Load() != 2 {
		t.Error("full cleanup closing/callback error", err, counter.reads.Load())
	}
	if late.Current(lateCtx) == nil || late.PID() != 0 || late.BoundTo(p, s, fresh) {
		t.Error("late cleanup view revived")
	}
	before := counter.reads.Load()
	func() {
		defer func() {
			if recover() != callbackErr {
				t.Error("cleanup callback panic changed")
			}
		}()
		_ = p.WithCleanupReadObservation(ctx, fresh, func(held context.Context, v *MihomoLiveCleanupObservation) error {
			late, lateCtx = v, held
			panic(callbackErr)
		})
	}()
	if counter.reads.Load() != before+2 || late.Current(lateCtx) == nil {
		t.Error("cleanup panic closing/revocation")
	}
	path := s.session.paths["b_receipt"]
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Error(readErr)
		return
	}
	err = p.WithCleanupReadObservation(ctx, fresh, func(context.Context, *MihomoLiveCleanupObservation) error {
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			return err
		}
		return callbackErr
	})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Error("restore original receipt", err)
	}
	if !errors.Is(err, callbackErr) || !errors.Is(err, ErrMihomoLiveOwner) {
		t.Error("closing cleanup source drift/callback cause", err)
	}
	if err := p.CurrentForCleanup(ctx, fresh); err != nil {
		t.Error("restored receipt cleanup read", err)
	}
}
