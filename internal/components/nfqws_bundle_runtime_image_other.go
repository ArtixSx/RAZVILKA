//go:build !linux || (!amd64 && !arm64)

package components

import "context"

func (m *Manager) verifyManagedNFQWSRuntimeImage(ctx context.Context, path, expected string) (ManagedNFQWSManifest, error) {
	return m.verifyManagedNFQWS(ctx, path, expected)
}
