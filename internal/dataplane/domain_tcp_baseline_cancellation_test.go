package dataplane

import (
	"context"
	"net"
	"testing"
)

// Lifecycle/race model only: empty native/resource owners deliberately cannot
// acknowledge cleanup. No socket/effect authority is constructed by this test.
func TestDomainTCPBaselinePrecancelledWatcherJoinsClosePublication(t *testing.T) {
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		left, right := net.Pipe()
		c := &domainTCPBaselineConn{ctx: ctx, conn: left}
		c.self = c
		c.watchCancellation()
		if err := c.Close(); err == nil {
			t.Fatal("empty owners acknowledged cleanup")
		}
		_ = left.Close()
		_ = right.Close()
		c.mu.Lock()
		closed := c.closed
		published := c.stop != nil
		c.mu.Unlock()
		if !closed || !published {
			t.Fatal("cancellation escaped producer/close barrier")
		}
	}
}
