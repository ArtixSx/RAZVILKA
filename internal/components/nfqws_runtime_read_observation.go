package components

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
)

// ManagedNFQWSRuntimeRead is a provisional byte comparison inside one known
// pure reader. It has no Check/Descriptor/Start interface and changes neither
// the public lease Check nor any launch admission. Only the outer successful
// return includes the complete second byte read and original cleanup.
type ManagedNFQWSRuntimeRead struct {
	mu                 sync.Mutex
	self               *ManagedNFQWSRuntimeRead
	owner              *managedNFQWSRuntimeOwner
	lease              *ManagedNFQWSRuntimeLease
	manager            *Manager
	tx                 *updateTransaction
	receipt            ManagedNFQWSBundleReceipt
	descriptor         NFQWSRuntimeDescriptor
	source, validation *ManagedNFQWSRuntimeLease
	parent, ctx        context.Context
	open               bool
	image              managedNFQWSRuntimeReadImage
}

type managedNFQWSRuntimeReadImage interface{ compare(context.Context) error }

// WithReadObservation returns unavailable only before acquiring a read token:
// unsupported platforms or an already busy original owner keep the old full
// Check path. Once begun, every failure is a refusal, never a fallback.
func (l *ManagedNFQWSRuntimeLease) WithReadObservation(ctx context.Context, read func(context.Context, *ManagedNFQWSRuntimeRead) error) (began bool, result error) {
	if !managedNFQWSRuntimeReadSupported {
		return false, nil
	}
	if l == nil || l.self != l || l.owner == nil || read == nil || !managedNFQWSReadFinite(ctx) {
		return true, ErrManagedNFQWSBundle
	}
	o := l.owner
	o.mu.Lock()
	if !o.current(l) || o.manager == nil || o.tx == nil {
		o.mu.Unlock()
		return true, ErrManagedNFQWSBundle
	}
	if o.readFrame != nil {
		o.mu.Unlock()
		return false, nil
	}
	v := &ManagedNFQWSRuntimeRead{owner: o, lease: l, manager: o.manager, tx: o.tx, receipt: o.receipt, descriptor: o.descriptor, source: o.source, validation: o.validation, parent: ctx}
	v.descriptor.Lua = slices.Clone(o.descriptor.Lua)
	v.descriptor.Blobs = slices.Clone(o.descriptor.Blobs)
	v.descriptor.AllowedFeatures = slices.Clone(o.descriptor.AllowedFeatures)
	v.self = v
	o.readFrame = v
	o.mu.Unlock()
	noteManagedNFQWSRuntimeFrame(v.manager, 0)
	finished := false
	measuredManager := v.manager
	child, cancel := context.WithCancel(ctx)
	v.ctx = child
	defer func() {
		cancel()
		// The platform reader has already closed every descriptor and cleared
		// its bytes, including on panic/Goexit, before this token is released.
		o.mu.Lock()
		if o.readFrame == v {
			o.readFrame = nil
		} else {
			result = errors.Join(result, ErrManagedNFQWSBundle)
		}
		o.mu.Unlock()
		v.mu.Lock()
		v.open = false
		v.image = nil
		v.lease = nil
		v.owner = nil
		v.manager = nil
		v.tx = nil
		v.source = nil
		v.validation = nil
		v.parent = nil
		v.ctx = nil
		v.receipt = ManagedNFQWSBundleReceipt{}
		v.descriptor = NFQWSRuntimeDescriptor{}
		v.mu.Unlock()
		if finished && result == nil {
			noteManagedNFQWSRuntimeFrame(measuredManager, 1)
		} else {
			noteManagedNFQWSRuntimeFrame(measuredManager, 2)
		}
	}()
	o.mu.Lock()
	err := v.ownerCurrentLocked(ctx)
	o.mu.Unlock()
	if err != nil {
		return true, err
	}
	_, result = v.manager.withManagedNFQWSRuntimeReadImage(ctx, v.receipt.GenerationPath, v.receipt.ManifestSHA256, func(image managedNFQWSRuntimeReadImage) (err error) {
		v.mu.Lock()
		v.image = image
		v.open = true
		v.mu.Unlock()
		defer func() {
			// Lock acquisition joins every already admitted CompareCurrent.
			// Revoke before the original second full byte/EOF read starts.
			v.mu.Lock()
			v.open = false
			v.mu.Unlock()
			cancel()
		}()
		if err := v.CompareCurrent(child); err != nil {
			return err
		}
		return read(child, v)
	})
	// Do not short-circuit byte closing on association drift or callback error.
	o.mu.Lock()
	closing := error(ErrManagedNFQWSBundle)
	if v.owner == o {
		closing = v.ownerCurrentLocked(ctx)
	}
	o.mu.Unlock()
	finished = true
	return true, errors.Join(result, closing, ctx.Err())
}

func managedNFQWSReadFinite(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	_, finite := ctx.Deadline()
	return finite
}

// Caller holds the SAME original owner's mutex. This preserves the ordinary
// Check's writer/receipt/accepted-journal checks at every comparison point.
func (v *ManagedNFQWSRuntimeRead) ownerCurrentLocked(ctx context.Context) error {
	o := v.owner
	if v.self != v || o == nil || !o.current(v.lease) || o.readFrame != v || o.manager != v.manager || o.tx != v.tx || o.receipt != v.receipt || o.source != v.source || o.validation != v.validation || !reflect.DeepEqual(o.descriptor, v.descriptor) || !managedNFQWSReadFinite(ctx) {
		return ErrManagedNFQWSBundle
	}
	if err := o.tx.requireIdle(); err != nil {
		return err
	}
	root, err := o.manager.managedNFQWSInventory(false)
	if err != nil {
		return err
	}
	receipt, _, readErr := readManagedNFQWSReceipt(root)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil || receipt == nil || *receipt != v.receipt {
		return errors.Join(ErrManagedNFQWSBundle, readErr, closeErr)
	}
	path, err := o.manager.managedNFQWSTerminalPath(v.receipt)
	if err != nil || path != v.receipt.GenerationPath {
		return errors.Join(ErrManagedNFQWSBundle, err)
	}
	return ctx.Err()
}

func (v *ManagedNFQWSRuntimeRead) BoundTo(lease *ManagedNFQWSRuntimeLease) bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.self == v && v.open && v.lease == lease
}

func (v *ManagedNFQWSRuntimeRead) CompareCurrent(ctx context.Context) error {
	if v == nil {
		return ErrManagedNFQWSBundle
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.self != v || !v.open || v.ctx == nil || ctx != v.ctx || !managedNFQWSReadFinite(ctx) || !managedNFQWSReadFinite(v.parent) || v.owner == nil || v.image == nil {
		return ErrManagedNFQWSBundle
	}
	v.owner.mu.Lock()
	defer v.owner.mu.Unlock()
	if err := v.ownerCurrentLocked(ctx); err != nil {
		return err
	}
	return errors.Join(v.image.compare(ctx), ctx.Err())
}
