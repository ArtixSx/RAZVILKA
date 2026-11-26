package dataplane

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Inert directory preparation uses the SAME manager-root descriptor retained
// by the COMMON reservation. It never writes/adopts a process receipt, changes
// a foreign mode, issues a Start, or makes unknown prior state clean.
func (e *nfqwsProbeExecution) prepareProcessDirectory(ctx context.Context) error {
	if e == nil || e.self != e || e.consumer == nil || e.resource == nil || e.records == nil || e.records.scope != e.resource.scope || e.resource.scope.manager != e.consumer.manager || e.consumer.adapter.StateRoot != filepath.Join(e.resource.scope.managerRoot, "runtime", "nfqws2") {
		return ErrNFQWSScopedOwner
	}
	if err := errors.Join(e.current(ctx), e.resource.Current(ctx, e.resource.binding)); err != nil {
		return err
	}
	d := e.records
	d.mu.Lock()
	var err error
	if d.closed || d.root == nil {
		err = ErrNFQWSScopedOwner
	} else {
		err = prepareNFQWSProbePrivateDirectories(d.root)
	}
	d.mu.Unlock()
	return errors.Join(err, e.resource.Current(ctx, e.resource.binding), e.current(ctx))
}

func prepareNFQWSProbePrivateDirectories(root *ownedfs.Root) error {
	if root == nil {
		return ErrNFQWSScopedOwner
	}
	for _, name := range []string{"runtime", filepath.Join("runtime", "nfqws2")} {
		if err := root.MkdirAll(name, 0700); err != nil {
			return err
		}
		info, err := root.Stat(name)
		if err != nil || !proxyInactivePrivateDirectory(info) {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
	}
	return nil
}
