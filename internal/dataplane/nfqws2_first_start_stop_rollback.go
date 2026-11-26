package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
)

// A retirement may have stopped the original process before a later absence
// observation refused. Its prior transaction and running lease then remain
// unchanged. Equality of those files alone is not evidence of restored runtime.
func (a *NFQWS2Adapter) rollbackInterruptedFirstStartStop(ctx context.Context, plan Plan, root string, snapshot nfqws2Snapshot, expected *nfqws2Lease, originalFirstStart bool) (bool, error) {
	if !snapshot.FirstStart || !snapshot.WasRunning || expected == nil || expected.FirstStart == nil ||
		expected.FirstStart.Phase != nfqws2FirstRunning || expected.FirstStart.Process == nil ||
		!reflect.DeepEqual(expected, snapshot.Lease) || !slices.Contains(plan.RetiringAdapters, a.ID()) || slices.Contains(plan.Adapters, a.ID()) {
		return false, nil
	}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) == a.ID() {
			return false, nil
		}
	}
	if !nfqws2InactiveFinite(ctx) {
		return true, ErrReviewChanged
	}
	unlock, err := a.lockResources()
	if err != nil {
		return true, err
	}
	defer unlock()
	current, err := a.readLease()
	if err != nil || !reflect.DeepEqual(current, expected) {
		return true, ErrReviewChanged
	}
	identity, err := a.readFirstStartProcess(expected.FirstStart.Process.PID)
	if err == nil {
		if identity != *expected.FirstStart.Process {
			return true, ErrNFQWSManagedProcessUnknown
		}
		return false, nil // Still the original live incarnation; ordinary rollback checks remain.
	}
	if !errors.Is(err, os.ErrNotExist) {
		return true, ErrNFQWSManagedProcessUnknown
	}
	// Admit only the exact original main/init/lists. No foreign edit or newer
	// transaction may become content or authority for this compensation.
	currentImages := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		lease, err := a.readLease()
		if err != nil || !reflect.DeepEqual(lease, expected) {
			return ErrReviewChanged
		}
		data, existed := nfqws2SnapshotResources(snapshot)
		for i, path := range append(a.globalResources(), a.InitPath) {
			before, present := snapshot.Init, true
			if i < len(data) {
				before, present = data[i], existed[i]
			}
			actual, exists, err := nfqws2Read(path)
			if err != nil || exists != present || !bytes.Equal(actual, before) {
				return ErrReviewChanged
			}
		}
		if _, exists, err := nfqws2Read(a.firstStartPIDPath()); err != nil || exists {
			return ErrReviewChanged
		}
		running, exists, err := nfqws2Read(a.ConfigPath + ".run")
		if err != nil || exists && (!snapshot.RunningConfigExisted || !bytes.Equal(running, snapshot.RunningConfig)) {
			return ErrReviewChanged
		}
		return ctx.Err()
	}
	if err := currentImages(); err != nil {
		return true, err
	}
	if originalFirstStart {
		// Only Manager's original legacy compensation supplies this intent.
		// The exact saved images and lease under the same resource locks above
		// replace the rejected forward App owner's guard, not any native,
		// process, kernel, context or cleanup ownership check.
		ctx = WithReviewGuard(ctx, nil)
	}
	if err := checkFirstStartReviewGuard(ctx); err != nil {
		return true, err
	}
	// A fresh complete independent observation is mandatory. Persistent
	// unknown kernel/process state returns a rollback failure, never a no-op PASS.
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return true, err
	}
	if err := checkFirstStartReviewGuard(ctx); err != nil {
		return true, err
	}
	if err := currentImages(); err != nil {
		return true, err
	}
	if err := a.recordFirstStartStopped(expected); err != nil {
		return true, err
	}
	return true, a.restartFirstStartSnapshot(ctx, root, snapshot, expected)
}
