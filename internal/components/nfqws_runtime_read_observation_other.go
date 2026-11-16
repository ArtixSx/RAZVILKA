//go:build !linux || (!amd64 && !arm64)

package components

import "context"

const managedNFQWSRuntimeReadSupported = false

func (m *Manager) withManagedNFQWSRuntimeReadImage(context.Context, string, string, func(managedNFQWSRuntimeReadImage) error) (ManagedNFQWSManifest, error) {
	return ManagedNFQWSManifest{}, ErrManagedNFQWSBundle
}
