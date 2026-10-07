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
