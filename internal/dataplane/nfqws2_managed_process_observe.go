package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// This process-only observation performs fresh readback and no writes/cleanup.
// ECHILD + exact parent ACK are its evidence; /proc absence alone never passes.
func (a *NFQWS2Adapter) observeManagedNFQWSProcessInactive(ctx context.Context) (nfqws2ManagedProcessLease, error) {
	var zero nfqws2ManagedProcessLease
	if a == nil || ctx == nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	owner, err := a.owner()
	if err != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	path := filepath.Join(a.StateRoot, nfqws2LeaseFile)
	if nfqws2ManagedObservationPath(path) != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	image, err := restorejournal.ReadFileImage(ctx, path)
	if err != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	lease, err := nfqws2DecodeManagedLease(image, a.StateRoot, owner)
	if err != nil || !nfqws2ManagedProcessSettled(lease) {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	boot, err := components.ReadNFQWSSupervisionIdentity()
	if err != nil || boot.BootID != lease.Receipt.BootID {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	for _, pid := range []int{lease.Receipt.PID, lease.Receipt.ChildPID} {
		if pid == 0 {
			continue // Exact not-started terminal receipt has no child.
		}
		_, err := components.ReadNFQWSRuntimeProcessIdentity(pid)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
		}
	}
	after, err := restorejournal.ReadFileImage(ctx, path)
	current, bootErr := components.ReadNFQWSSupervisionIdentity()
	if err != nil || bootErr != nil || current.BootID != boot.BootID || !reflect.DeepEqual(image, after) || ctx.Err() != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err, bootErr, ctx.Err())
	}
	return lease, nil
}

// VerifyRuntimeInactive requires the startup owner's original concrete source.
// Process settlement, successful Stop or an absent lease never grants this
// independent full process/files/kernel/queue observation on its own.
func (a *NFQWS2Adapter) VerifyRuntimeInactive(ctx context.Context) error {
	if ctx == nil || a == nil {
		return nfqws2InactiveAt("source", nil)
	}
	if err := ctx.Err(); err != nil {
		return nfqws2InactiveAt("context", err)
	}
	nfqws2ActiveAdapterMu.Lock()
	source := a.inactivity
	nfqws2ActiveAdapterMu.Unlock()
	if source == nil || source.adapter != a {
		return nfqws2InactiveAt("source", nil)
	}
	return source.verify(ctx, source.platform)
}
