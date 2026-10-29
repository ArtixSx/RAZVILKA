package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"testing"
	"time"
)

func TestNFQWSInactiveDuplicateRetryHonorsOriginalDeadline(t *testing.T) {
	stock := nfqwsDirectStockQueueFixture()
	reads := 0
	reader := nfqws2InactiveKernelReader{
		read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
			reads++
			return stock, nil
		},
		queues: func(context.Context) ([]nfqwsScopedQueue, error) { return nil, nil },
		sockets: func(context.Context) (string, error) {
			return nfqws2InactiveTestSockets + "0 12 99 00000000 0 0 0 0 0 992\n", nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	err := reader.check(ctx, stock.Scope.Network)
	if !errors.Is(err, ErrNFQWSManagedKernelOwner) || !errors.Is(err, context.DeadlineExceeded) || reads > 1 {
		t.Fatal("duplicate retry outlived/replaced caller deadline", err, reads)
	}
}
