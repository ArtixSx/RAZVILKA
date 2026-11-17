package dataplane

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type wgCleanupToolModel struct {
	*wgKernelLinkSourceModel
	observations atomic.Int32
	afterRead    func()
	closing      error
	childContext func(context.Context) (context.Context, context.CancelFunc)
	inside       atomic.Bool
	checks       atomic.Int32
}

func (m *wgCleanupToolModel) WithWGInactivityCleanupToolObservation(ctx context.Context, _ netidentity.Identity, _ string, read func(context.Context) error) error {
	m.observations.Add(1)
	m.inside.Store(true)
	defer m.inside.Store(false)
	if m.childContext != nil {
		var cancel context.CancelFunc
		ctx, cancel = m.childContext(ctx)
		defer cancel()
	}
	err := read(ctx)
	if m.afterRead != nil {
		m.afterRead()
	}
	return errors.Join(err, m.closing)
}

func (m *wgCleanupToolModel) CheckWG(ctx context.Context, id netidentity.Identity) error {
	if m.inside.Load() {
		m.checks.Add(1)
	}
	return m.wgInactivityProcessModel.CheckWG(ctx, id)
}

func (m *wgCleanupToolModel) ReadWGKernelServiceTable(ctx context.Context, _ netidentity.Identity, _, _ int, _ string) (int, error) {
	if !m.inside.Load() {
		return 0, errors.New("missing original tool observation")
	}
	return 0, ctx.Err()
}

func wgCleanupToolFixture(t *testing.T) (*wgSourceReadFixture, *WGInactivityRead, *wgCleanupToolModel, *operationgate.ExclusiveCleanupReview) {
	t.Helper()
	f, old, kernel := newWGKernelLinkSourceFixture(t)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	m := &wgCleanupToolModel{wgKernelLinkSourceModel: kernel}
	tools := old.tools
	tools.Runner = m
	r, err := ReviewWGInactivityRead(f.ctx, context.Background(), f.manager, f.control, tools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	cleanup, err := f.control.ReviewExclusiveCleanup(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return f, r, m, cleanup
}

func TestWGCleanupToolOriginalLifetimeAndBothLeaves(t *testing.T) {
	f, r, m, cleanup := wgCleanupToolFixture(t)
	f.cancel() // Forward is expired; the original operation is still held.
	if err := f.control.Current(f.ctx); err == nil {
		t.Fatal("expired forward revived")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var saved context.Context
	err := r.WithCurrent(ctx, cleanup, func(c context.Context) error {
		saved = c
		links, err := r.readKernelLinks(c)
		if err != nil || len(links) == 0 {
			return errors.Join(ErrWGOperationOwner, err)
		}
		return r.readKernelEmptyTable(c, 219, 6)
	})
	if err != nil || m.observations.Load() != 2 || m.checks.Load() != 4 || m.calls.Load() != 1 || m.wgInactivityProcessModel.calls.Load() != 0 {
		t.Fatal("same cleanup did not preserve both original read pairs", err, m.observations.Load(), m.checks.Load())
	}
	if _, err := r.readKernelLinks(saved); err == nil {
		t.Fatal("escaped session reused")
	}
	f.release()
	if err := r.WithCurrent(ctx, cleanup, func(c context.Context) error { _, err := r.readKernelLinks(c); return err }); err == nil {
		t.Fatal("released cleanup revived")
	}
}

func TestWGCleanupToolRefusalsAndNoFallback(t *testing.T) {
	for _, cut := range []string{"none", "shorter-child", "extended-child", "foreign-child", "nil-cleanup", "closing-error", "cleanup-swap", "control-swap", "runner-swap", "session-context", "session-copy", "source-copy", "canceled", "foreign-cleanup", "released-cleanup"} {
		t.Run(cut, func(t *testing.T) {
			f, r, m, cleanup := wgCleanupToolFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if cut == "nil-cleanup" {
				ctx = f.ctx
				cleanup = nil
			}
			if cut == "foreign-cleanup" {
				other, _, _, foreign := wgCleanupToolFixture(t)
				_ = other
				cleanup = foreign
			}
			if cut == "released-cleanup" {
				f.release()
			}
			if cut == "closing-error" {
				m.closing = errors.New("closing bytes refused")
			}
			switch cut {
			case "shorter-child":
				m.childContext = func(c context.Context) (context.Context, context.CancelFunc) {
					return context.WithTimeout(c, time.Second)
				}
			case "extended-child":
				m.childContext = func(c context.Context) (context.Context, context.CancelFunc) {
					return context.WithTimeout(context.WithoutCancel(c), time.Hour)
				}
			case "foreign-child":
				m.childContext = func(context.Context) (context.Context, context.CancelFunc) {
					return context.WithTimeout(context.Background(), time.Second)
				}
			}
			err := r.WithCurrent(ctx, cleanup, func(c context.Context) error {
				s := c.Value(wgInactivitySessionKey{}).(*wgInactivityReadSession)
				originalContext, originalCleanup, control, runner := s.ctx, s.cleanup, r.control, r.tools.Runner
				defer func() {
					s.ctx, s.cleanup, r.control, r.tools.Runner = originalContext, originalCleanup, control, runner
				}()
				switch cut {
				case "cleanup-swap":
					m.afterRead = func() { s.cleanup = &operationgate.ExclusiveCleanupReview{} }
				case "control-swap":
					m.afterRead = func() { r.control = &operationgate.ControlEpochReview{} }
				case "runner-swap":
					m.afterRead = func() { r.tools.Runner = m.wgInactivityProcessModel }
				case "session-context":
					m.afterRead = func() { s.ctx = context.WithValue(s.ctx, struct{}{}, true) }
				case "session-copy":
					c = context.WithValue(c, wgInactivitySessionKey{}, &wgInactivityReadSession{self: s, source: r, cleanup: cleanup, ctx: c, open: true})
				case "source-copy":
					copy := &WGInactivityRead{self: r, tools: r.tools}
					_, err := copy.readKernelLinks(c)
					return err
				case "canceled":
					cancel()
				}
				links, err := r.readKernelLinks(c)
				if err != nil && len(links) != 0 {
					t.Error("provisional kernel result escaped")
				}
				return err
			})
			want := cut == "none" || cut == "nil-cleanup" || cut == "shorter-child"
			if (err == nil) != want {
				t.Fatal(cut, err)
			}
			if cut == "nil-cleanup" && m.observations.Load() != 0 {
				t.Fatal("non-cleanup path changed")
			}
			if m.observations.Load() > 1 || m.calls.Load() > 1 || m.wgInactivityProcessModel.calls.Load() != 0 {
				t.Fatal("read retried or CLI reached")
			}
		})
	}
}

func TestWGCleanupToolCloseJoinsOriginalCleanupRead(t *testing.T) {
	f, r, m, cleanup := wgCleanupToolFixture(t)
	m.block, m.started = true, make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- r.WithCurrent(ctx, cleanup, func(c context.Context) error {
			links, err := r.readKernelLinks(c)
			if len(links) != 0 {
				return errors.New("canceled read returned provisional links")
			}
			return err
		})
	}()
	select {
	case <-m.started:
	case <-ctx.Done():
		t.Fatal("kernel read did not enter")
	}
	released := make(chan struct{})
	go func() { f.release(); close(released) }()
	select {
	case <-released:
		t.Fatal("original operation released while reader entered")
	default:
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("source Close failed to join")
	}
	if err := <-done; err == nil || m.inside.Load() || m.observations.Load() != 1 {
		t.Fatal("canceled original read became success", err)
	}
	select {
	case <-released:
	case <-ctx.Done():
		t.Fatal("joined cleanup did not release original operation")
	}
}

func TestWGCleanupToolComparisonSingleJoinedCallback(t *testing.T) {
	for _, cut := range []string{"none", "zero", "double", "swallowed", "closing", "recovered-panic", "late", "async-return", "observer-panic", "observer-goexit"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			bodyFailure := errors.New("actual body refusal")
			var calls atomic.Int32
			var late func(context.Context) error
			started, finished := make(chan struct{}), make(chan struct{})
			async := cut == "async-return" || cut == "observer-panic" || cut == "observer-goexit"
			read := func(c context.Context) error {
				calls.Add(1)
				if async {
					close(started)
					<-c.Done()
					close(finished)
					return c.Err()
				}
				if cut == "recovered-panic" {
					panic("body")
				}
				if cut == "swallowed" {
					return bodyFailure
				}
				return nil
			}
			observer := func(c context.Context, use func(context.Context) error) (result error) {
				switch cut {
				case "zero":
					return nil
				case "late":
					late = use
					return nil
				case "recovered-panic":
					defer func() { _ = recover() }()
				}
				if async {
					go func() { _ = use(c) }()
					<-started
					if cut == "observer-panic" {
						panic("observer")
					}
					if cut == "observer-goexit" {
						runtime.Goexit()
					}
					return nil
				}
				err := use(c)
				if cut == "double" {
					_ = use(c)
				}
				if cut == "swallowed" {
					return nil
				}
				if cut == "closing" {
					return errors.New("closing")
				}
				return err
			}
			done := make(chan struct{})
			var result error
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				result = wgCleanupKernelToolComparison(ctx, observer, func(c context.Context) error { return c.Err() }, read)
			}()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("comparison did not join")
			}
			if async {
				select {
				case <-finished:
				default:
					t.Fatal("reader escaped observer exit")
				}
			}
			if cut != "observer-panic" && cut != "observer-goexit" && (result == nil) != (cut == "none") {
				t.Fatal(cut, result)
			}
			if cut == "swallowed" && !errors.Is(result, bodyFailure) {
				t.Fatal("lost body error")
			}
			if late != nil && late(ctx) == nil {
				t.Fatal("late entry accepted")
			}
			if calls.Load() > 1 {
				t.Fatal("multiple bodies admitted")
			}
		})
	}
}
