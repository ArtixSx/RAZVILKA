//go:build !linux

package dataplane

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func CheckTypedNFQWSScopedQueue(context.Context, *netidentity.Provider, netidentity.Identity, uint16, *components.NFQWSRuntimeProcessIdentity) error {
	return ErrNFQWSScopedOwner
}
func nfqwsScopedTypedQueueReadiness(context.Context, *netidentity.Provider, netidentity.Identity, uint16, *components.NFQWSRuntimeProcessIdentity) (bool, error) {
	return false, ErrNFQWSScopedOwner
}

func nfqwsScopedTypedStockQueueObserve(ctx context.Context, proof *nfqwsScopedStockQueueProof, child *components.NFQWSRuntimeProcessIdentity) (bool, error) {
	if err := proof.consume(ctx); err != nil {
		return false, err
	}
	return false, ErrNFQWSScopedOwner
}
