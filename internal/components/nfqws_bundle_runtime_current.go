package components

import (
	"context"
	"errors"
)

// AcquireCurrentManagedNFQWSRuntime uses this configured Manager's protected
// current receipt. AcquireManagedNFQWSRuntime then re-reads that receipt and
// verifies its accepted terminal journal and immutable generation while holding
// the existing component writer lease. A concurrent install cannot turn the
// initial read into authority for an old generation.
func (m *Manager) AcquireCurrentManagedNFQWSRuntime(ctx context.Context) (*ManagedNFQWSRuntimeLease, error) {
	if m == nil || ctx == nil {
		return nil, ErrManagedNFQWSBundle
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrManagedNFQWSBundle, err)
	}
	root, err := m.managedNFQWSInventory(false)
	if err != nil {
		return nil, err
	}
	receipt, _, readErr := readManagedNFQWSReceipt(root)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil || receipt == nil {
		return nil, errors.Join(ErrManagedNFQWSBundle, readErr, closeErr)
	}
	return m.AcquireManagedNFQWSRuntime(ctx, receipt.TransactionID)
}
