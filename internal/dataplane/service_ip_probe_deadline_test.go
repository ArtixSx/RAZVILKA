package dataplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// Actual local TLS and SOCKS exercise net/http's detached dial context. The
// source guard must receive the original finite request, never a fresh budget.
func TestPinnedServiceTransportGuardKeepsRequestDeadline(t *testing.T) {
	backend, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "service reached") })
	socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var calls atomic.Int32
	ctx = WithNodeResourceGuard(ctx, func(c context.Context, _ string, _ netip.Addr) error {
		calls.Add(1)
		actual, finite := c.Deadline()
		if !finite || actual.After(deadline) {
			return errors.New("original finite source observation required")
		}
		return c.Err()
	})
	response, cleanup, err := socksHTTPGetPinnedTLS(ctx, "https://example.com/", socks.address, netip.MustParseAddr("1.1.1.1"), roots)
	if err != nil {
		t.Fatal("real pinned transport lost original deadline", err)
	}
	defer cleanup()
	defer response.Body.Close()
	if calls.Load() < 2 {
		t.Fatal("transport did not execute its actual dial resource check")
	}
}

func TestPinnedServiceDialGuardCancellationCannotReachSOCKS(t *testing.T) {
	backend, roots, _ := newPinnedTLSFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("canceled guard reached service") })
	socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type key struct{}
	ctx = context.WithValue(ctx, key{}, "original request")
	var calls atomic.Int32
	ctx = WithNodeResourceGuard(ctx, func(c context.Context, _ string, _ netip.Addr) error {
		if c.Value(key{}) != "original request" {
			return errors.New("original context values lost")
		}
		if calls.Add(1) == 2 {
			cancel()
		}
		return c.Err()
	})
	_, _, err := socksHTTPGetPinnedTLS(ctx, "https://example.com/", socks.address, netip.MustParseAddr("1.1.1.1"), roots)
	if !errors.Is(err, context.Canceled) || calls.Load() != 2 {
		t.Fatal("original cancellation lost", calls.Load(), err)
	}
	select {
	case request := <-socks.requests:
		t.Fatal("canceled source dialed SOCKS", request)
	default:
	}
}

type pinnedServicePendingTimerContext struct {
	context.Context
	deadline time.Time
}

func (c pinnedServicePendingTimerContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestPinnedServiceElapsedRequestDeadlineKeepsTypedCauseBeforeTimerPublishes(t *testing.T) {
	base := context.Background()
	pending := pinnedServicePendingTimerContext{Context: base, deadline: time.Now().Add(-time.Millisecond)}
	if pending.Err() != nil {
		t.Fatal("pending timer model already canceled")
	}
	if !errors.Is(pinnedServiceContextError(pending, base, base), context.DeadlineExceeded) {
		t.Fatal("elapsed original deadline lost typed cause")
	}
	canceledOriginal, cancelOriginal := context.WithCancel(pending)
	cancelOriginal()
	if err := pinnedServiceContextError(canceledOriginal, base, base); !errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("published original cancellation changed to deadline", err)
	}
	pending.deadline = time.Now().Add(time.Second)
	if pinnedServiceContextError(pending, base, base) != nil {
		t.Fatal("future request deadline classified as expired network timeout")
	}
	canceled, stop := context.WithCancel(base)
	stop()
	if !errors.Is(pinnedServiceContextError(pending, canceled, base), context.Canceled) {
		t.Fatal("transport cancellation cause lost")
	}
}
