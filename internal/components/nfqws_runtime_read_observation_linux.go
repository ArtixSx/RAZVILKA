//go:build linux && (amd64 || arm64)

package components

import (
	"context"
	"errors"
	"os"
)

const managedNFQWSRuntimeReadSupported = true

type managedNFQWSHeldReadImage struct {
	manager *Manager
	root    *os.Root
	path    string
	anchor  os.FileInfo
	nodes   []*managedRuntimeImageNode
}

func (r *managedNFQWSHeldReadImage) compare(ctx context.Context) error {
	if r == nil || !managedNFQWSReadFinite(ctx) {
		return ErrManagedNFQWSBundle
	}
	return errors.Join(r.manager.managedRuntimeImageClosing(ctx, r.root, r.path, r.anchor, r.nodes), ctx.Err())
}
