//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func backendInventorySystemPlatform(provider *netidentity.Provider) backendInventoryPlatform {
	return backendInventoryPlatform{
		withCurrent:      provider.WithCurrent,
		registeredTables: func(context.Context, int) ([]byte, error) { return nil, errBackendInventory },
		openNFT:          func(context.Context) (backendNFTSession, error) { return nil, errBackendInventory },
	}
}
