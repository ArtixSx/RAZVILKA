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
	self   *ManagedNFQWSRuntimeLease
	owner  *managedNFQWSRuntimeOwner
	closed bool // Protected by owner.mu.
}

// One original exclusive writer, never a second Acquire or a shared flock.
// Only registered lifecycle leases may use or release its immutable runtime.
type managedNFQWSRuntimeOwner struct {
	manager    *Manager
	tx         *updateTransaction
	receipt    ManagedNFQWSBundleReceipt
	descriptor NFQWSRuntimeDescriptor
	mu         sync.Mutex
	source     *ManagedNFQWSRuntimeLease
	validation *ManagedNFQWSRuntimeLease
}

var ErrManagedNFQWSValidationPending = errors.New("managed NFQWS validation lease remains open")

func (m *Manager) AcquireManagedNFQWSRuntime(ctx context.Context, receiptID string) (*ManagedNFQWSRuntimeLease, error) {
	if m == nil || ctx == nil {
		return nil, ErrManagedNFQWSBundle
	}
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
	owner := &managedNFQWSRuntimeOwner{manager: m, tx: tx, receipt: *receipt, descriptor: d}
	lease := &ManagedNFQWSRuntimeLease{owner: owner}
	lease.self = lease
	owner.source = lease
	return lease, nil
}

func (l *ManagedNFQWSRuntimeLease) Descriptor() NFQWSRuntimeDescriptor {
	if l == nil || l.self != l || l.owner == nil {
		return NFQWSRuntimeDescriptor{}
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.current(l) {
		return NFQWSRuntimeDescriptor{}
	}
	d := o.descriptor
	d.Lua = append([]NFQWSRuntimeAsset(nil), d.Lua...)
	d.Blobs = append([]NFQWSRuntimeBlob(nil), d.Blobs...)
	d.AllowedFeatures = append([]string(nil), d.AllowedFeatures...)
	return d
}

// Caller holds o.mu. Membership, rather than copied descriptor/receipt fields,
// binds every lifecycle action to the actual owner-issued lease.
func (o *managedNFQWSRuntimeOwner) current(l *ManagedNFQWSRuntimeLease) bool {
	return o != nil && o.tx != nil && l != nil && l.self == l && l.owner == o && !l.closed &&
		(o.source == l || o.validation == l)
}

func (o *managedNFQWSRuntimeOwner) check(ctx context.Context) error {
	if o.tx == nil || ctx == nil || ctx.Err() != nil {
		if ctx != nil {
			return errors.Join(ErrManagedNFQWSBundle, ctx.Err())
		}
		return ErrManagedNFQWSBundle
	}
	if err := o.tx.requireIdle(); err != nil {
		return err
	}
	root, err := o.manager.managedNFQWSInventory(false)
	if err != nil {
		return err
	}
	r, _, err := readManagedNFQWSReceipt(root)
	root.Close()
	if err != nil || r == nil || *r != o.receipt {
		return errors.Join(ErrManagedNFQWSBundle, err)
	}
	_, err = o.manager.verifyManagedNFQWSTerminal(ctx, o.receipt)
	return err
}

func (l *ManagedNFQWSRuntimeLease) Check(ctx context.Context) error {
	if l == nil || l.self != l || l.owner == nil || ctx == nil {
		return ErrManagedNFQWSBundle
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.current(l) {
		return ErrManagedNFQWSBundle
	}
	return o.check(ctx)
}

// ForkValidation issues one distinct compatibility lifecycle under this exact
// original component writer. It conveys immutable runtime access only; native
// invocation, packet/effect and installation authority remain separate.
func (l *ManagedNFQWSRuntimeLease) ForkValidation(ctx context.Context) (*ManagedNFQWSRuntimeLease, error) {
	if l == nil || l.self != l || l.owner == nil || ctx == nil {
		return nil, ErrManagedNFQWSBundle
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.current(l) || o.source != l {
		return nil, ErrManagedNFQWSBundle
	}
	if o.validation != nil {
		return nil, errors.Join(ErrManagedNFQWSBundle, ErrManagedNFQWSValidationPending)
	}
	if err := o.check(ctx); err != nil {
		return nil, err
	}
	child := &ManagedNFQWSRuntimeLease{owner: o}
	child.self = child
	o.validation = child
	return child, nil
}

func (l *ManagedNFQWSRuntimeLease) Close() error {
	if l == nil {
		return nil
	}
	if l.self != l || l.owner == nil {
		return ErrManagedNFQWSBundle
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if l.closed {
		return nil
	}
	if !o.current(l) {
		return ErrManagedNFQWSBundle
	}
	if o.source == l && o.validation != nil {
		return errors.Join(ErrManagedNFQWSBundle, ErrManagedNFQWSValidationPending)
	}
	err := o.check(context.Background())
	l.closed = true
	if o.validation == l {
		o.validation = nil
	} else {
		o.tx.close()
		o.tx = nil
	}
	return err
}
