package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// The original empty Snapshot already holds the manager directory. A fresh
// manual Apply must prepare its fixed private runtime child without depending
// on an earlier finite probe. This is metadata custody, never Start authority.
// Keep both directory identities until the same material is actually retired.
type nfqwsActiveProcessDirectory struct {
	mu                sync.Mutex
	self              *nfqwsActiveProcessDirectory
	execution         *nfqws2ActiveExecution
	review            *nfqwsPreEffectLANReview
	root              *ownedfs.Root
	info, runtimeInfo os.FileInfo
	closed            bool
	closeErr          error
}

func (e *nfqws2ActiveExecution) prepareOriginalProcessDirectory(ctx context.Context) error {
	if e == nil || e.self != e || e.resource == nil || e.material == nil || e.material.self != e.material {
		return ErrNFQWSScopedOwner
	}
	if err := e.current(ctx, e.resource.Plan()); err != nil {
		return err
	}
	e.mu.Lock()
	review, existing := e.preEffectLAN, e.processDirectory
	original := e.started && !e.launchInvoked && e.activationSeal != nil && e.resource.scope != nil && e.resource.scope.manager == e.material.manager && e.resource.scope.managerRoot == e.material.managerRoot && e.material.adapter.StateRoot == filepath.Join(e.material.managerRoot, "runtime", "nfqws2")
	e.mu.Unlock()
	if !original || existing != nil {
		return ErrNFQWSScopedOwner
	}
	if review == nil {
		return nil
	} // Prior-owner path keeps its original existing-directory admission.
	d, err := holdNFQWSActiveProcessDirectory(ctx, e, review)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.processDirectory = d
	e.mu.Unlock()
	// A closing refusal retains the original descriptor for known retirement.
	return e.current(ctx, e.resource.Plan())
}

func holdNFQWSActiveProcessDirectory(ctx context.Context, e *nfqws2ActiveExecution, review *nfqwsPreEffectLANReview) (_ *nfqwsActiveProcessDirectory, resultErr error) {
	if ctx == nil || ctx.Err() != nil || e == nil || e.self != e || e.material == nil || review == nil || review.self != review || review.execution != e || e.preEffectLAN != review {
		return nil, ErrNFQWSScopedOwner
	}
	review.mu.Lock()
	defer review.mu.Unlock()
	if err := nfqwsActiveDirectoryManagerCurrent(ctx, e, review); err != nil {
		return nil, err
	}
	if err := prepareNFQWSProbePrivateDirectories(review.manager); err != nil {
		return nil, err
	}
	d := &nfqwsActiveProcessDirectory{execution: e, review: review}
	d.self = d
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, d.close())
		}
	}()
	var err error
	d.runtimeInfo, err = review.manager.Stat("runtime")
	if err != nil {
		return nil, err
	}
	d.root, d.info, err = openNetworkPolicyObservationRoot(e.material.adapter.StateRoot)
	if err != nil {
		return nil, err
	}
	if err := d.currentUnderReview(ctx); err != nil {
		return nil, err
	}
	keep = true
	return d, nil
}

// Caller holds the original Snapshot review mutex, never its obsolete
// empty-snapshot observation. Active metadata may legitimately have changed.
func nfqwsActiveDirectoryManagerCurrent(ctx context.Context, e *nfqws2ActiveExecution, r *nfqwsPreEffectLANReview) error {
	if ctx == nil || ctx.Err() != nil || e == nil || e.self != e || e.material == nil || e.material.manager == nil || e.material.adapter == nil || r == nil || r.self != r || r.closed || r.execution != e || e.preEffectLAN != r || r.manager == nil || r.managerInfo == nil || r.dir == nil || r.dirInfo == nil || e.material.manager.StateRoot != e.material.managerRoot || e.material.adapter.StateRoot != filepath.Join(e.material.managerRoot, "runtime", "nfqws2") {
		return ErrNFQWSScopedOwner
	}
	for _, read := range []func() (os.FileInfo, error){func() (os.FileInfo, error) { return os.Lstat(e.material.managerRoot) }, r.manager.RootInfo} {
		info, err := read()
		if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(info, r.managerInfo) {
			return ErrNFQWSScopedOwner
		}
	}
	actual, err := r.manager.Stat(r.relative)
	if err != nil || !os.SameFile(actual, r.dirInfo) || !networkPolicyPrivateDirectory(actual) {
		return ErrNFQWSScopedOwner
	}
	held, err := r.dir.RootInfo()
	if err != nil || !os.SameFile(held, r.dirInfo) {
		return ErrNFQWSScopedOwner
	}
	return ctx.Err()
}

func (d *nfqwsActiveProcessDirectory) current(ctx context.Context) error {
	if d == nil || d.self != d || d.review == nil {
		return ErrNFQWSScopedOwner
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.review.mu.Lock()
	defer d.review.mu.Unlock()
	return d.currentUnderReview(ctx)
}
func (d *nfqwsActiveProcessDirectory) currentUnderReview(ctx context.Context) error {
	if d.closed || d.root == nil || d.info == nil || d.runtimeInfo == nil {
		return ErrNFQWSScopedOwner
	}
	if err := nfqwsActiveDirectoryManagerCurrent(ctx, d.execution, d.review); err != nil {
		return err
	}
	parent, err := d.review.manager.Stat("runtime")
	if err != nil || !networkPolicyPrivateDirectory(parent) || !os.SameFile(parent, d.runtimeInfo) {
		return ErrNFQWSScopedOwner
	}
	for _, read := range []func() (os.FileInfo, error){func() (os.FileInfo, error) { return d.review.manager.Stat(filepath.Join("runtime", "nfqws2")) }, func() (os.FileInfo, error) { return os.Lstat(d.execution.material.adapter.StateRoot) }, d.root.RootInfo} {
		info, err := read()
		if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(info, d.info) {
			return ErrNFQWSScopedOwner
		}
	}
	return nfqwsActiveDirectoryManagerCurrent(ctx, d.execution, d.review)
}
func (d *nfqwsActiveProcessDirectory) matchesTarget(ctx context.Context, target *restorejournal.FileTarget) error {
	if target == nil {
		return ErrNFQWSScopedOwner
	}
	if err := d.current(ctx); err != nil {
		return err
	}
	info, err := target.ParentIdentity()
	if err != nil || !os.SameFile(info, d.info) {
		return ErrNFQWSScopedOwner
	}
	return d.current(ctx)
}
func (d *nfqwsActiveProcessDirectory) close() error {
	if d == nil || d.self != d {
		return ErrNFQWSScopedOwner
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		if d.root != nil {
			d.closeErr = d.root.Close()
		}
	}
	return d.closeErr
}
func (e *nfqws2ActiveExecution) originalProcessDirectory() *nfqwsActiveProcessDirectory {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.processDirectory
}
