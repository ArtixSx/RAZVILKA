package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// This is a read observation of an absent receipt, never permission to install.
// Corrupt receipts, missing generations and busy runtime leases stay unknown.
var ErrManagedNFQWSReceiptAbsent = errors.New("managed NFQWS receipt is absent")

// ObserveCurrentManagedNFQWSRuntime verifies the configured Manager's current
// accepted immutable generation without acquiring its writer lease. The
// detached descriptor is read-only evidence; launch/install always requires
// AcquireCurrentManagedNFQWSRuntime and the original operation's admission.
// Opening/closing receipt checks make a concurrent generation change unknown.
func (m *Manager) ObserveCurrentManagedNFQWSRuntime(ctx context.Context) (NFQWSRuntimeDescriptor, error) {
	if m == nil || ctx == nil || ctx.Err() != nil {
		return NFQWSRuntimeDescriptor{}, ErrManagedNFQWSBundle
	}
	root, err := m.managedNFQWSInventory(false)
	if err != nil {
		return NFQWSRuntimeDescriptor{}, err
	}
	receipt, _, readErr := readManagedNFQWSReceipt(root)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil || receipt == nil {
		return NFQWSRuntimeDescriptor{}, errors.Join(ErrManagedNFQWSBundle, readErr, closeErr)
	}
	manifest, err := m.verifyManagedNFQWSRuntimeTerminal(ctx, *receipt)
	if err != nil {
		return NFQWSRuntimeDescriptor{}, err
	}
	closingRoot, err := m.managedNFQWSInventory(false)
	if err != nil {
		return NFQWSRuntimeDescriptor{}, err
	}
	closing, _, readErr := readManagedNFQWSReceipt(closingRoot)
	closeErr = closingRoot.Close()
	if readErr != nil || closeErr != nil || closing == nil || *closing != *receipt || ctx.Err() != nil {
		return NFQWSRuntimeDescriptor{}, errors.Join(ErrManagedNFQWSBundle, readErr, closeErr, ctx.Err())
	}
	d := NFQWSRuntimeDescriptor{ReceiptID: receipt.TransactionID, ManifestSHA256: receipt.ManifestSHA256, Flavor: receipt.Flavor, GenerationPath: receipt.GenerationPath, LuaCompat: manifest.LuaCompat, AllowedFeatures: append([]string(nil), manifest.AllowedFeatures...)}
	for i, member := range manifest.Members {
		asset := NFQWSRuntimeAsset{filepath.Join(receipt.GenerationPath, filepath.FromSlash(member.Destination)), member.RawSHA256}
		if i == 0 {
			d.Executable = asset
		} else if i <= 3 {
			d.Lua = append(d.Lua, asset)
		} else {
			alias := "quic_initial"
			if i == 5 {
				alias = "tls_clienthello"
			}
			d.Blobs = append(d.Blobs, NFQWSRuntimeBlob{alias, asset.Path, asset.SHA256})
		}
	}
	return d, nil
}

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
