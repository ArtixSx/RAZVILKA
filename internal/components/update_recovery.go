package components

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func updateModeMatches(actual, expected os.FileMode) bool {
	return runtime.GOOS == "windows" || actual == expected
}

// ManagedRecoveryRequest identifies the exact transaction reviewed by the
// caller. SafeMode/Stopped are a fail-closed snapshot, and the required guard
// must re-read current authority before each mutation and after live checks.
type ManagedRecoveryRequest struct {
	TransactionID        string
	Component            string
	Action               string // rollback, accept-live, abandon-prepared, verify-rollback
	AllowUnknownRollback bool   // explicit one-time compensation, never upgrade replay
	SafeMode             bool
	Stopped              bool
}

// RecoverManagedUpdate runs in a new Manager/process using only durable
// journal state. It never retries the upgrade or an interrupted rollback
// command. verify-rollback only observes a manually repaired runtime; it does
// not run opkg or write configuration. The caller owns actual live evidence.
func (m *Manager) RecoverManagedUpdate(ctx context.Context, request ManagedRecoveryRequest, guard, liveCheck func(context.Context) error) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := Result{Component: request.Component, Action: "recover"}
	if request.SafeMode || request.Stopped || guard == nil {
		return result, ErrRecoveryAuthority
	}
	tx, err := m.lockUpdateJournal()
	if err != nil {
		return result, err
	}
	defer tx.close()
	doc, exists, err := readUpdateJournal(tx.root)
	if err != nil {
		return result, errors.Join(ErrUpdatePending, err)
	}
	if !exists || doc.TransactionID != request.TransactionID || doc.Component != request.Component || request.TransactionID == "" {
		return result, errors.New("component recovery does not match the pending transaction")
	}
	tx.doc = doc
	if err := tx.authority(ctx, guard); err != nil {
		return result, err
	}
	if updateTerminal(doc.Phase) {
		return result, errors.New("component transaction is already settled")
	}
	if _, _, err := tx.loadSnapshot(); err != nil {
		return result, err
	}
	switch request.Action {
	case "abandon-prepared":
		if doc.Phase != UpdatePrepared {
			return result, ErrUpdateUnknown
		}
		if err := tx.phase(UpdateAbandoned); err != nil {
			return result, err
		}
		result.OK = true
		return result, nil
	case "accept-live":
		if doc.Phase != UpdateAwaitingLive || doc.AfterVersion == "" || liveCheck == nil {
			return result, ErrUpdatePending
		}
		if err := tx.verifyVersion(ctx, doc.AfterVersion); err != nil {
			return result, err
		}
		if err := liveCheck(ctx); err != nil {
			return result, err
		}
		if err := tx.authority(ctx, guard); err != nil {
			return result, err
		}
		if err := tx.verifyVersion(ctx, doc.AfterVersion); err != nil {
			return result, err
		}
		if err := tx.finish("update", UpdateAccepted, doc.AfterVersion); err != nil {
			return result, err
		}
		result.OK = true
		return result, nil
	case "rollback":
		if liveCheck == nil {
			return result, ErrRecoveryAuthority
		}
		if doc.Phase == UpdateStarted && !request.AllowUnknownRollback {
			return result, ErrUpdateUnknown
		}
		if doc.Phase == UpdateRollbackStarted {
			return result, ErrUpdateUnknown
		}
		if doc.Phase == UpdatePrepared {
			return result, errors.New("prepared update has no package mutation to roll back")
		}
		return tx.rollback(ctx, guard, liveCheck)
	case "verify-rollback":
		// A command may have exited between the side effect and journal fsync.
		// Fresh observation can settle it without reissuing that command. This
		// action is explicit matching repair, never startup/automatic recovery.
		if (doc.Phase != UpdateRollbackStarted && doc.Phase != UpdateAwaitingRollback) || liveCheck == nil {
			return result, ErrUpdatePending
		}
		if err := tx.verifyRollback(ctx); err != nil {
			return result, err
		}
		if err := liveCheck(ctx); err != nil {
			return result, err
		}
		if err := tx.authority(ctx, guard); err != nil {
			return result, err
		}
		if err := tx.verifyRollback(ctx); err != nil {
			return result, err
		}
		if err := tx.finish("rollback", UpdateRolledBack, doc.BeforeVersion); err != nil {
			return result, err
		}
		result.OK = true
		return result, nil
	default:
		return result, errors.New("unknown component recovery action")
	}
}

func (tx *updateTransaction) restore(ctx context.Context, images []conffileImage, stage string, guard func(context.Context) error) error {
	for i, image := range images {
		if err := tx.authority(ctx, guard); err != nil {
			return err
		}
		point := fmt.Sprintf("restore-%s:%d", stage, i)
		if err := tx.fault("before:" + point); err != nil {
			return err
		}
		if err := restoreConffiles([]conffileImage{image}); err != nil {
			return err
		}
		if err := tx.fault("after:" + point); err != nil {
			return err
		}
	}
	return nil
}

func (tx *updateTransaction) rollback(ctx context.Context, guard, check func(context.Context) error) (Result, error) {
	result := Result{Component: tx.doc.Component, Action: "rollback"}
	rollback, images, err := tx.loadSnapshot()
	if err != nil {
		return result, err
	}
	switch tx.doc.Phase {
	case UpdateStarted, UpdateInstalled, UpdateAwaitingLive, UpdateRestoreBefore:
		if err := tx.authority(ctx, guard); err != nil {
			return result, err
		}
		if err := tx.phase(UpdateRestoreBefore); err != nil {
			return result, err
		}
		if err := tx.restore(ctx, images, "before", guard); err != nil {
			return result, err
		}
		if err := tx.phase(UpdateRollbackReady); err != nil {
			return result, err
		}
	case UpdateRollbackReady, UpdateRollbackInstalled, UpdateRestoreAfter, UpdateAwaitingRollback:
	default:
		return result, ErrUpdateUnknown
	}
	if tx.doc.Phase == UpdateRollbackReady {
		if err := tx.authority(ctx, guard); err != nil {
			return result, err
		}
		if err := tx.phase(UpdateRollbackStarted); err != nil {
			return result, err
		}
		if err := tx.fault("before:rollback-command"); err != nil {
			return result, err
		}
		out, err := tx.manager.run(ctx, "install", "--force-downgrade", "--force-reinstall", rollback)
		result.Output = boundedOutput(out)
		if faultErr := tx.fault("after:rollback-command"); faultErr != nil {
			return result, faultErr
		}
		if err != nil {
			return result, errors.Join(ErrUpdateUnknown, err)
		}
		if err := tx.phase(UpdateRollbackInstalled); err != nil {
			return result, err
		}
	}
	if tx.doc.Phase == UpdateRollbackInstalled || tx.doc.Phase == UpdateRestoreAfter {
		if err := tx.authority(ctx, guard); err != nil {
			return result, err
		}
		if err := tx.phase(UpdateRestoreAfter); err != nil {
			return result, err
		}
		// Package scripts may migrate defaults even during a downgrade.
		if err := tx.restore(ctx, images, "after", guard); err != nil {
			return result, err
		}
		if err := tx.phase(UpdateAwaitingRollback); err != nil {
			return result, err
		}
	}
	if err := tx.authority(ctx, guard); err != nil {
		return result, err
	}
	if err := tx.verifyRollback(ctx); err != nil {
		return result, err
	}
	if err := check(ctx); err != nil {
		return result, err
	}
	if err := tx.authority(ctx, guard); err != nil {
		return result, err
	}
	if err := tx.verifyRollback(ctx); err != nil {
		return result, err
	}
	if err := tx.finish("rollback", UpdateRolledBack, tx.doc.BeforeVersion); err != nil {
		return result, err
	}
	result.OK = true
	return result, nil
}

func (tx *updateTransaction) verifyVersion(ctx context.Context, expected string) error {
	installed, err := tx.manager.installedPackageVersions(ctx)
	if err != nil {
		return err
	}
	if installed[tx.doc.Package] != expected {
		return fmt.Errorf("installed %s version %q does not match recovery version %q", tx.doc.Package, installed[tx.doc.Package], expected)
	}
	return nil
}

func (tx *updateTransaction) verifyRollback(ctx context.Context) error {
	if err := tx.verifyVersion(ctx, tx.doc.BeforeVersion); err != nil {
		return err
	}
	_, images, err := tx.loadSnapshot()
	if err != nil {
		return err
	}
	for _, image := range images {
		root, err := ownedfs.Open(filepath.Dir(image.path))
		if err != nil {
			return err
		}
		info, err := root.Stat(filepath.Base(image.path))
		if !image.exists {
			_ = root.Close()
			if !errors.Is(err, os.ErrNotExist) {
				return errors.New("previously absent configuration exists after rollback")
			}
			continue
		}
		if err != nil {
			_ = root.Close()
			return err
		}
		data, err := root.ReadLimited(filepath.Base(image.path), maxConffileBytes)
		_ = root.Close()
		if err != nil || !bytes.Equal(data, image.data) || !updateModeMatches(info.Mode().Perm(), image.mode) {
			return errors.New("configuration does not match rollback snapshot")
		}
	}
	return nil
}

func (tx *updateTransaction) finish(action, phase, version string) error {
	if err := tx.fault("before:receipt"); err != nil {
		return err
	}
	spec, _ := lookup(tx.doc.Component)
	if err := tx.manager.writeLifecycleReceipt(lifecycleReceipt{SchemaVersion: 1, Component: spec.ID, Package: spec.Package, Provider: spec.Provider, Action: action, BeforeVersion: tx.doc.BeforeVersion, AfterVersion: version, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), TransactionID: tx.doc.TransactionID, Acceptance: phase}); err != nil {
		return err
	}
	if err := tx.fault("after:receipt"); err != nil {
		return err
	}
	return tx.phase(phase)
}
