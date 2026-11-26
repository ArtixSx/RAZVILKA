//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
)

// Instrumentation delegates every original origin read; it grants no owner.
type mihomoObservedOriginCounter struct {
	mihomoProbeOriginOwner
	reads atomic.Int32
}

func (o *mihomoObservedOriginCounter) current(ctx context.Context) error {
	o.reads.Add(1)
	return o.mihomoProbeOriginOwner.current(ctx)
}

// Invoked only after the official held-FD child has actually started.
func testMihomoLiveReadObservationOriginalBookends(t *testing.T, ctx context.Context, p *MihomoLiveProcess) {
	t.Helper()
	s := p.source
	original := s.origin
	counter := &mihomoObservedOriginCounter{mihomoProbeOriginOwner: original}
	s.origin = counter
	defer func() { s.origin = original }()
	callbackErr := errors.New("actual observation callback error")
	var late *MihomoLiveObservation
	var lateCtx context.Context
	err := p.WithReadObservation(ctx, func(held context.Context, view *MihomoLiveObservation) error {
		late, lateCtx = view, held
		if !view.BoundTo(p, s) || view.BoundTo(new(MihomoLiveProcess), s) {
			t.Error("original pointer binding")
		}
		for range 4 {
			if err := view.Current(held); err != nil {
				t.Error("original native comparison", err)
			}
		}
		if counter.reads.Load() != 1 {
			t.Error("nested source hashing repeated", counter.reads.Load())
		}
		s.mu.Lock()
		delete(s.children, p)
		s.mu.Unlock()
		if view.Current(held) == nil {
			t.Error("revoked child registration admitted")
		}
		s.mu.Lock()
		s.children[p] = true
		delete(s.profiles, p.profile)
		s.mu.Unlock()
		if view.Current(held) == nil {
			t.Error("revoked profile registration admitted")
		}
		s.mu.Lock()
		s.profiles[p.profile] = true
		s.mu.Unlock()
		if view.Current(ctx) == nil {
			t.Error("foreign context admitted")
		}
		copy := &MihomoLiveObservation{self: view, child: view.child, source: view.source, ctx: view.ctx, open: true}
		if copy.Current(held) == nil || copy.PID() != 0 {
			t.Error("copied view admitted")
		}
		canceled, cancel := context.WithCancel(held)
		cancel()
		if !errors.Is(view.Current(canceled), context.Canceled) {
			t.Error("cancellation cause lost")
		}
		return callbackErr
	})
	if !errors.Is(err, callbackErr) || counter.reads.Load() != 2 {
		t.Error("full closing read/callback cause", err, counter.reads.Load())
	}
	if late.Current(lateCtx) == nil || late.PID() != 0 || late.BoundTo(p, s) {
		t.Error("late view revived")
	}
	before := counter.reads.Load()
	func() {
		defer func() {
			if recover() != callbackErr {
				t.Error("callback panic changed")
			}
		}()
		_ = p.WithReadObservation(ctx, func(held context.Context, view *MihomoLiveObservation) error {
			late, lateCtx = view, held
			panic(callbackErr)
		})
	}()
	if counter.reads.Load() != before+2 || late.Current(lateCtx) == nil {
		t.Error("panic skipped closing/revocation")
	}
	// Actual receipt drift is discovered by the full closing source read even
	// when the read-only callback itself returns another error.
	path := s.session.paths["b_receipt"]
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Error(readErr)
		return
	}
	err = p.WithReadObservation(ctx, func(context.Context, *MihomoLiveObservation) error {
		if e := os.WriteFile(path, []byte("{}"), 0600); e != nil {
			return e
		}
		return callbackErr
	})
	restoreErr := os.WriteFile(path, raw, 0600)
	if restoreErr != nil {
		t.Error("restore actual fixture receipt", restoreErr)
	}
	if !errors.Is(err, callbackErr) || !errors.Is(err, ErrMihomoLiveOwner) {
		t.Error("closing source drift/callback cause lost", err)
	}
	if err := p.Current(ctx); err != nil {
		t.Error("restored original receipt", err)
	}
}
