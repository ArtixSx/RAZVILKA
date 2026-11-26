package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type handshakeBudgetRunner func(context.Context, string, ...string) ([]byte, error)

func (r handshakeBudgetRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r(ctx, name, args...)
}
func TestWGHandshakeBudgetBoundsStalledObservation(t *testing.T) {
	for _, engine := range []string{"warp-wg", "wireguard", "amneziawg"} {
		t.Run(engine, func(t *testing.T) {
			a := NewWARPWireGuardAdapter(nil, t.TempDir())
			a.EngineID = engine
			a.WG = "wg"
			a.Timeout = 500 * time.Millisecond
			a.HandshakeTimeout = 30 * time.Millisecond
			var commandDeadline time.Time
			a.Runner = handshakeBudgetRunner(func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
				commandDeadline, _ = ctx.Deadline()
				<-ctx.Done()
				return nil, ctx.Err()
			})
			start := time.Now()
			err := a.confirmHandshake(context.Background(), "owned-test")
			elapsed := time.Since(start)
			t.Logf("model stalled observation elapsed=%s handshake_budget=%s command_budget=%s", elapsed, a.HandshakeTimeout, a.Timeout)
			var timeout WARPHandshakeError
			if !errors.As(err, &timeout) {
				t.Fatalf("missing typed handshake timeout: %v", err)
			}
			// Inspect the admitted deadline instead of asserting scheduler wall
			// time on a loaded CI runner. The old command received 500ms here.
			if commandDeadline.IsZero() || commandDeadline.After(start.Add(a.HandshakeTimeout+50*time.Millisecond)) {
				t.Fatal("wg command was admitted beyond the handshake budget")
			}
		})
	}
}
func TestWGHandshakeCanceledValidOutputCannotPass(t *testing.T) {
	a := NewWARPWireGuardAdapter(nil, t.TempDir())
	a.WG = "wg"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	a.Runner = handshakeBudgetRunner(func(context.Context, string, ...string) ([]byte, error) {
		calls++
		cancel()
		return []byte(fmt.Sprintf("private-peer-marker\t%d\n", time.Now().Unix())), nil
	})
	err := a.confirmHandshake(ctx, "owned-test")
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled handshake accepted: calls=%d err=%v", calls, err)
	}
	if strings.Contains(err.Error(), "private-peer-marker") {
		t.Fatal("peer leaked")
	}
}
func TestWGHandshakeParentDeadlineKeepsItsCause(t *testing.T) {
	a := NewWARPWireGuardAdapter(nil, t.TempDir())
	a.WG = "wg"
	a.HandshakeTimeout = time.Second
	a.Runner = handshakeBudgetRunner(func(ctx context.Context, _ string, _ ...string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := a.confirmHandshake(ctx, "owned-test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent deadline became node failure: %v", err)
	}
}
