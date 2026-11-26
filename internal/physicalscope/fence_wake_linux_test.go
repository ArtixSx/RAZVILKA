//go:build linux

package physicalscope

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFenceWakeFullQueueAndOwnedClose(t *testing.T) {
	w, err := newFenceWake()
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if err := unix.SetsockoptInt(w.fds[1], unix.SOL_SOCKET, unix.SO_SNDBUF, 1024); err != nil {
		t.Fatal(err)
	}
	full := false
	for range 10000 {
		_, err := unix.Write(w.fds[1], []byte{1})
		if err == unix.EAGAIN {
			full = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !full {
		t.Fatal("actual nonblocking socket buffer never filled")
	}
	if err := w.notify(); err != nil {
		t.Fatal("full hint queue must coalesce", err)
	}
	if err := w.wait(w.fds[0]); err != nil {
		t.Fatal(err)
	}
	if err := w.close(); err != nil {
		t.Fatal(err)
	}
	if w.notify() == nil {
		t.Fatal("closed hint owner reused")
	}
	if err := w.close(); err != nil {
		t.Fatal("close acknowledgment changed", err)
	}
}

func TestFenceWakeRefusesReplacementWithoutClosingIt(t *testing.T) {
	w, err := newFenceWake()
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	other, err := newFenceWake()
	if err != nil {
		t.Fatal(err)
	}
	defer other.close()
	if err := unix.Dup3(other.fds[1], w.fds[1], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(w.fds[1]) // This test owns the deliberately installed replacement.
	if w.notify() == nil || w.close() == nil {
		t.Fatal("replacement accepted")
	}
	if cookie, err := unix.GetsockoptUint64(w.fds[1], unix.SOL_SOCKET, unix.SO_COOKIE); err != nil || cookie != other.cookies[1] {
		t.Fatal("foreign replacement closed", err)
	}
}

func TestFenceWakeRejectsMalformedHint(t *testing.T) {
	w, err := newFenceWake()
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if _, err := unix.Write(w.fds[1], []byte{1, 1}); err != nil {
		t.Fatal(err)
	}
	if w.wait(w.fds[0]) == nil {
		t.Fatal("malformed datagram accepted")
	}
}

// Actual owned wake/poll descriptors; netlink data here is explicitly modeled.
// Every request still performs the original descriptor/EAGAIN bookends.
func TestFenceWakeBurstAndCloseJoin(t *testing.T) {
	w, err := newFenceWake()
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	f := newFenceTestTransport()
	source := f.source()
	source.wait = func() error { return w.wait(w.fds[0]) }
	source.wake = w.notify
	r := newOriginalFenceCollector(source)
	defer r.close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var callers sync.WaitGroup
	results := make(chan error, 32)
	for range 32 {
		callers.Go(func() { results <- r.check(ctx, Snapshot{}) })
	}
	callers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, empty := f.counts()
	if empty < 32 {
		t.Fatal("wake hints replaced fresh full drains", empty)
	}
	for range 32 {
		callers.Go(func() { _ = r.check(ctx, Snapshot{}) })
	}
	r.close()
	callers.Wait()
	if err := w.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.done:
	default:
		t.Fatal("descriptors closed before reader joined")
	}
	if !errors.Is(r.check(ctx, Snapshot{}), ErrUnknown) {
		t.Fatal("closed collector revived")
	}
}

func BenchmarkOriginalFenceWakeScheduling(b *testing.B) {
	for _, wake := range []bool{false, true} {
		name := "poll20ms"
		if wake {
			name = "owned-wake"
		}
		b.Run(name, func(b *testing.B) {
			w, err := newFenceWake()
			if err != nil {
				b.Fatal(err)
			}
			defer w.close()
			f := newFenceTestTransport()
			s := f.source()
			s.wait = func() error { return w.wait(w.fds[0]) }
			if wake {
				s.wake = w.notify
			}
			r := newOriginalFenceCollector(s)
			defer r.close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			b.ResetTimer()
			for range b.N {
				if err := r.check(ctx, Snapshot{}); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			_, empty := f.counts()
			b.ReportMetric(float64(empty)/float64(b.N), "fresh-drains/op")
		})
	}
}
