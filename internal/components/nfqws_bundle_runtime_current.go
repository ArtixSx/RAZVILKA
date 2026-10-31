package components

import (
	"context"
	"errors"
	"os"
)

// This is a read observation of an absent receipt, never permission to install.
// Corrupt receipts, missing generations and busy runtime leases stay unknown.
var ErrManagedNFQWSReceiptAbsent = errors.New("managed NFQWS receipt is absent")

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
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(ErrManagedNFQWSBundle, ErrManagedNFQWSReceiptAbsent)
		}
		return nil, err
	}
	receipt, _, readErr := readManagedNFQWSReceipt(root)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(ErrManagedNFQWSBundle, readErr, closeErr)
	}
	if receipt == nil {
		return nil, errors.Join(ErrManagedNFQWSBundle, ErrManagedNFQWSReceiptAbsent)
	}
	return m.AcquireManagedNFQWSRuntime(ctx, receipt.TransactionID)
}
