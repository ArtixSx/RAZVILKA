package components

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
)

type NFQWSRuntimeAsset struct{ Path, SHA256 string }
type NFQWSRuntimeBlob struct{ Alias, Path, SHA256 string }
type NFQWSRuntimeDescriptor struct {
	ReceiptID, ManifestSHA256, Flavor, GenerationPath string
	Executable                                        NFQWSRuntimeAsset
	Lua                                               []NFQWSRuntimeAsset
	Blobs                                             []NFQWSRuntimeBlob
	LuaCompat                                         int
	AllowedFeatures                                   []string
}

// The existing component writer lease excludes every installer/recovery for
// the whole trusted validation/probe session. It introduces no second owner.
// Complete generations are never modified/pruned by any provider API. These
// invariants do not authorize an arbitrary root-euid writer or runtime launch.
type ManagedNFQWSRuntimeLease struct {
	manager    *Manager
	tx         *updateTransaction
	receipt    ManagedNFQWSBundleReceipt
	descriptor NFQWSRuntimeDescriptor
	mu         sync.Mutex
}

func (m *Manager) AcquireManagedNFQWSRuntime(ctx context.Context, receiptID string) (*ManagedNFQWSRuntimeLease, error) {
	if !bundleHash(receiptID, 32) || ctx.Err() != nil {
		return nil, errors.Join(ErrManagedNFQWSBundle, ctx.Err())
	}
	tx, err := m.lockUpdateJournal()
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			tx.close()
		}
	}()
	if err := tx.requireIdle(); err != nil {
		return nil, err
	}
	root, err := m.managedNFQWSInventory(false)
	if err != nil {
		return nil, err
	}
	receipt, _, err := readManagedNFQWSReceipt(root)
	root.Close()
	if err != nil || receipt == nil || receipt.TransactionID != receiptID {
		return nil, errors.Join(ErrManagedNFQWSBundle, err)
	}
	manifest, err := m.verifyManagedNFQWSTerminal(ctx, *receipt)
	if err != nil {
		return nil, err
	}
	d := NFQWSRuntimeDescriptor{
		ReceiptID: receipt.TransactionID, ManifestSHA256: receipt.ManifestSHA256, Flavor: receipt.Flavor, GenerationPath: receipt.GenerationPath,
		LuaCompat: manifest.LuaCompat, AllowedFeatures: append([]string(nil), manifest.AllowedFeatures...),
	}
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
	keep = true
	return &ManagedNFQWSRuntimeLease{manager: m, tx: tx, receipt: *receipt, descriptor: d}, nil
}

func (l *ManagedNFQWSRuntimeLease) Descriptor() NFQWSRuntimeDescriptor {
	if l == nil {
		return NFQWSRuntimeDescriptor{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tx == nil {
		return NFQWSRuntimeDescriptor{}
	}
	d := l.descriptor
	d.Lua = append([]NFQWSRuntimeAsset(nil), d.Lua...)
	d.Blobs = append([]NFQWSRuntimeBlob(nil), d.Blobs...)
	d.AllowedFeatures = append([]string(nil), d.AllowedFeatures...)
	return d
}

func (l *ManagedNFQWSRuntimeLease) check(ctx context.Context) error {
	if l.tx == nil {
		return ErrManagedNFQWSBundle
	}
	if err := l.tx.requireIdle(); err != nil {
		return err
	}
	root, err := l.manager.managedNFQWSInventory(false)
	if err != nil {
		return err
	}
	r, _, err := readManagedNFQWSReceipt(root)
	root.Close()
	if err != nil || r == nil || *r != l.receipt {
		return errors.Join(ErrManagedNFQWSBundle, err)
	}
	_, err = l.manager.verifyManagedNFQWSTerminal(ctx, l.receipt)
	return err
}

func (l *ManagedNFQWSRuntimeLease) Check(ctx context.Context) error {
	if l == nil {
		return ErrManagedNFQWSBundle
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.check(ctx)
}

func (l *ManagedNFQWSRuntimeLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tx == nil {
		return nil
	}
	err := l.check(context.Background())
	l.tx.close()
	l.tx = nil
	return err
}
