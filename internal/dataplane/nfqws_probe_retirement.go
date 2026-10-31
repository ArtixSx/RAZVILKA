package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func (e *nfqwsProbeExecution) retireProcessReceipt(ctx context.Context, settled nfqws2ManagedProcessLease) (err error) {
	if e == nil || e.self != e || e.processResult == nil || !reflect.DeepEqual(*e.processResult, settled) || e.binding == nil || e.resource == nil {
		return ErrNFQWSScopedOwner
	}
	path := filepath.Join(e.command.StateRoot, nfqws2LeaseFile)
	if err := nfqws2ManagedObservationPath(path); err != nil {
		return err
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, target.Close()) }()
	before, err := target.Read(ctx)
	if err != nil {
		return err
	}
	if e.receiptUnlinked.Load() {
		if before.Exists {
			return ErrNFQWSScopedOwner
		}
		return e.binding.checkQueue(ctx, e.resource.plan, nil)
	}
	actual, err := nfqws2DecodeManagedLease(before, e.command.StateRoot, e.command.Owner)
	if err != nil || !reflect.DeepEqual(actual, settled) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := e.binding.checkQueue(ctx, e.resource.plan, nil); err != nil {
		return err
	}
	if err := e.cleanupCurrent(ctx); err != nil {
		return err
	}
	if err := target.CompareAndSwap(ctx, before, restorejournal.Image{}); err != nil {
		return err
	}
	e.receiptUnlinked.Store(true)
	after, err := target.Read(ctx)
	if err != nil || after.Exists {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return e.binding.checkQueue(ctx, e.resource.plan, nil)
}
