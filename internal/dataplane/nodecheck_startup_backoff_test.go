package dataplane

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The endpoint actively refuses early greetings, rather than holding one
// connection until ready: only the former exercises the retry cadence.
func delayedNodeSOCKSReadiness(t testing.TB, delay time.Duration) (*ExactNodeChecker, exactNodeSession, *atomic.Int64, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var readyAt time.Time
	processStarted := make(chan struct{})
	done := make(chan struct{})
	var attempts atomic.Int64
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadFull(conn, make([]byte, 3)); err == nil {
				<-processStarted
				attempts.Add(1)
				method := byte(255)
				if !time.Now().Before(readyAt) {
					method = 0
				}
				_, _ = conn.Write([]byte{5, method})
			}
			_ = conn.Close()
		}
	}()
	checker := NewExactNodeChecker("")
	checker.Processes = &nodeReadinessProcesses{afterStart: func() {
		readyAt = time.Now().Add(delay)
		close(processStarted)
	}}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = listener.Close()
			<-done
		})
	}
	t.Cleanup(cleanup)
	return checker, exactNodeSession{Address: listener.Addr().String()}, &attempts, cleanup
}

func TestExactNodeStartupWaitsForDelayedSOCKSReadiness(t *testing.T) {
	for _, delay := range []time.Duration{25 * time.Millisecond, 80 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			checker, session, attempts, cleanup := delayedNodeSOCKSReadiness(t, delay)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			started := time.Now()
			err := checker.startSession(ctx, session)
			elapsed := time.Since(started)
			cleanup()
			if err != nil || elapsed < delay || attempts.Load() < 1 {
				t.Fatalf("early rejection became readiness or delayed ready was lost: elapsed=%s attempts=%d err=%v", elapsed, attempts.Load(), err)
			}
		})
	}
}

func TestExactNodeStartupCancellationDuringEarlyRetry(t *testing.T) {
	checker, session, _, cleanup := delayedNodeSOCKSReadiness(t, time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := checker.startSession(ctx, session)
	cleanup()
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("early readiness retry ignored cancellation: %v", err)
	}
}

func BenchmarkExactNodeDelayedSOCKSReadiness(b *testing.B) {
	for _, delay := range []time.Duration{25 * time.Millisecond, 80 * time.Millisecond} {
		b.Run(delay.String(), func(b *testing.B) {
			var totalAttempts int64
			for range b.N {
				b.StopTimer()
				checker, session, attempts, cleanup := delayedNodeSOCKSReadiness(b, delay)
				b.StartTimer()
				err := checker.startSession(b.Context(), session)
				b.StopTimer()
				cleanup()
				if err != nil {
					b.Fatal(err)
				}
				totalAttempts += attempts.Load()
			}
			b.ReportMetric(float64(totalAttempts)/float64(b.N), "greetings/op")
		})
	}
}
