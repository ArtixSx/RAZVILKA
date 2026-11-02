package components

import "context"

// Only the original runtime owner's Check uses this image reader. It neither
// issues a lease nor changes the installer/recovery's complete verifier.
func (m *Manager) verifyManagedNFQWSRuntimeTerminal(ctx context.Context, receipt ManagedNFQWSBundleReceipt) (ManagedNFQWSManifest, error) {
	path, err := m.managedNFQWSTerminalPath(receipt)
	if err != nil {
		return ManagedNFQWSManifest{}, err
	}
	return m.verifyManagedNFQWSRuntimeImage(ctx, path, receipt.ManifestSHA256)
}
