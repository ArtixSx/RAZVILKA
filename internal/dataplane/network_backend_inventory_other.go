//go:build !linux

package dataplane

import "context"

func backendInventorySystemPlatform() backendInventoryPlatform {
	return backendInventoryPlatform{
		endpoint: func(context.Context) (backendInventoryScope, error) {
			return backendInventoryScope{}, errBackendInventory
		},
		openNFT: func(context.Context) (backendNFTSession, error) { return nil, errBackendInventory },
	}
}
