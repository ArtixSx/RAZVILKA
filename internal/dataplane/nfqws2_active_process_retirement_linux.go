//go:build linux

package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func nfqws2ActiveRetireFile(ctx context.Context, o *nfqws2ActiveOwner, settled nfqws2ActiveProcessLease, common func() error) (err error) {
	if o == nil || common == nil || nfqws2ActiveOperation(ctx) != nil || !o.known(settled) || !nfqws2ActiveProcessSettled(settled) || o.admission.Provider == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	path := filepath.Join(o.command.StateRoot, nfqws2LeaseFile)
	if nfqws2ManagedProtected(path, true) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, target.Close()) }()
	before, err := target.Read(ctx)
	image, decodeErr := nfqws2DecodeActiveLease(before, o.command.StateRoot, o.command.Owner)
	if err != nil || decodeErr != nil || !reflect.DeepEqual(image, settled) {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err, decodeErr)
	}
	empty := func() error {
		return CheckTypedNFQWSScopedQueue(ctx, o.admission.Provider, o.command.NetworkIdentity, o.admission.Spec.Queue, nil)
	}
	if err = empty(); err != nil {
		return err
	}
	if err = common(); err != nil {
		return err // COMMON failure never deletes the process receipt or clears association.
	}
	after, err := target.Read(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || nfqws2ManagedProtected(path, true) != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	if err = empty(); err != nil {
		return err
	}
	if err = target.CompareAndSwap(ctx, before, restorejournal.Image{}); err != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	absent, err := target.Read(ctx)
	if err != nil || absent.Exists || nfqws2ManagedProtected(path, true) != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	if err = empty(); err != nil {
		return err // An ambiguous post-unlink result retains the original adapter fence.
	}
	return ctx.Err()
}
