package dataplane

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Dispatch itself is typed: an original collector cannot carry an alternative
// callback next to an "original" flag. Custom/model callbacks retain their
// existing path and are never selected for the complete NFQ observation loan.
type networkPolicyInventoryReader interface {
	readInventory(context.Context, netidentity.Identity) (BackendInventorySnapshot, error)
}

type networkPolicyOriginalInventoryReader struct{ inventory *BackendInventory }

func (r *networkPolicyOriginalInventoryReader) readInventory(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
	if r == nil || r.inventory == nil {
		return BackendInventorySnapshot{}, ErrNetworkPolicyConsumers
	}
	return r.inventory.Read(ctx, identity)
}

type networkPolicyInventoryCallback func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error)

func (r networkPolicyInventoryCallback) readInventory(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
	if r == nil {
		return BackendInventorySnapshot{}, ErrNetworkPolicyConsumers
	}
	return r(ctx, identity)
}

func (c *NetworkPolicyChecks) read(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
	if c == nil || c.readSource == nil {
		return BackendInventorySnapshot{}, ErrNetworkPolicyConsumers
	}
	return c.readSource.readInventory(ctx, identity)
}
