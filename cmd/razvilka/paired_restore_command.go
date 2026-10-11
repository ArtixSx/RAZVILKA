package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// CORE's dispatcher calls this before ordinary startup. Roots remain fixed;
// only the matching transaction ID is input. This command cannot Start, clear
// Stop, initialize an epoch, adopt a legacy helper, or accept restored runtime.
func runPairedRestoreCommand(args []string, roots selfUpdateJournalRoots) (bool, int) {
	if len(args) == 0 || args[0] != "self-update-paired-restore" {
		return false, 0
	}
	if len(args) != 2 {
		return true, 2
	}
	decoded, err := hex.DecodeString(args[1])
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != args[1] {
		return true, 2
	}
	if runtime.GOOS != "linux" || roots != productionSelfUpdateJournalRoots() {
		return true, 3
	}
	parent, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	var gate operationgate.Gate
	ctx, release, err := gate.ExclusiveContext(parent)
	if err != nil {
		return true, 3
	}
	defer release() // All synchronous restore work finishes before owner release.
	owner, err := openPairedRestoreOwner(ctx, &gate, selfUpdateDefaultPath(installpath.State+"/self-update-stop"), args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "paired offline restore requires matching current durable Stop; preserve all evidence")
		return true, 3
	}
	defer owner.close()
	if checkSelfUpdateJournalState(ctx, roots, updatecheck.SelfUpdateReadVersion) != nil {
		fmt.Fprintln(os.Stderr, "paired offline restore requires readable matching retained evidence")
		return true, 3
	}
	adapter := updatecheck.NewSelfUpdateFileAdapterWithAuthority(selfUpdateStopCheck, selfUpdateEffectAdmission, selfUpdateRuntimeInactive)
	result, err := adapter.RestorePairedPriorState(ctx, args[1], owner.current, owner.admit)
	if err != nil {
		fmt.Fprintln(os.Stderr, "paired offline restore requires review; retain archive, guarded init and displaced files")
		return true, 3
	}
	return true, writeCommandJSON(result)
}

// This private handle is constructed only from the original live exclusive
// CLI owner and the existing protected control directory/permanent marker.
// The observed Stop value alone is never an effect capability.
type pairedRestoreOwner struct {
	ctx        context.Context
	gate       *operationgate.Gate
	root       *ownedfs.Root
	path, id   string
	info       os.FileInfo
	marker     *os.File
	markerInfo os.FileInfo
	stop       operationgate.SelfUpdateStop
}

func openPairedRestoreOwner(ctx context.Context, gate *operationgate.Gate, path, id string) (*pairedRestoreOwner, error) {
	if gate == nil || ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, updatecheck.ErrPairedOfflineRestore
	}
	var owner *pairedRestoreOwner
	err := gate.WithExclusiveContext(ctx, func() error {
		root, err := ownedfs.Open(path)
		if err != nil {
			return err
		}
		candidate := &pairedRestoreOwner{ctx: ctx, gate: gate, root: root, path: path, id: id}
		keep := false
		defer func() {
			if !keep {
				candidate.close()
			}
		}()
		candidate.info, err = root.RootInfo()
		if err != nil {
			return err
		}
		candidate.marker, err = root.OpenFile(".control.lock", os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		candidate.markerInfo, err = candidate.marker.Stat()
		if err != nil || !candidate.markerInfo.Mode().IsRegular() {
			return updatecheck.ErrPairedOfflineRestore
		}
		stop, present, err := operationgate.ReadSelfUpdateStop(ctx, path)
		if err != nil || !present || !stop.Stopped || stop.TransactionID != id || stop.Sequence < 2 {
			return updatecheck.ErrPairedOfflineRestore
		}
		candidate.stop = stop
		if err := candidate.current(ctx, id); err != nil {
			return err
		}
		owner, keep = candidate, true
		return nil
	})
	return owner, err
}

func (o *pairedRestoreOwner) close() {
	if o == nil {
		return
	}
	if o.marker != nil {
		o.marker.Close()
		o.marker = nil
	}
	if o.root != nil {
		o.root.Close()
		o.root = nil
	}
}

// Leaf metadata only; called under the existing control lock immediately
// around a single bounded rename. Never reopen a Store or wait a process here.
func (o *pairedRestoreOwner) pinned() error {
	if o == nil || o.root == nil || o.marker == nil {
		return updatecheck.ErrPairedOfflineRestore
	}
	root, err := os.Lstat(o.path)
	held, heldErr := o.root.RootInfo()
	marker, markerErr := o.root.Stat(".control.lock")
	opened, openedErr := o.marker.Stat()
	if err != nil || heldErr != nil || markerErr != nil || openedErr != nil || !os.SameFile(o.info, root) || !os.SameFile(o.info, held) || !os.SameFile(o.markerInfo, marker) || !os.SameFile(o.markerInfo, opened) || root.Mode() != o.info.Mode() || marker.Mode() != o.markerInfo.Mode() || marker.Size() != o.markerInfo.Size() || !marker.ModTime().Equal(o.markerInfo.ModTime()) || root.Mode()&os.ModeSymlink != 0 || !root.IsDir() || !marker.Mode().IsRegular() {
		return updatecheck.ErrPairedOfflineRestore
	}
	return nil
}

func (o *pairedRestoreOwner) current(ctx context.Context, id string) error {
	if o == nil || ctx != o.ctx || id != o.id {
		return updatecheck.ErrPairedOfflineRestore
	}
	return o.gate.WithExclusiveContext(ctx, func() error {
		if err := o.pinned(); err != nil {
			return err
		}
		stop, present, err := operationgate.ReadSelfUpdateStop(ctx, o.path)
		if err != nil || !present || stop != o.stop {
			return operationgate.ErrSelfUpdateStopChanged
		}
		return ctx.Err()
	})
}

func (o *pairedRestoreOwner) admit(ctx context.Context, id, effect string, begin func() error) error {
	index := strings.TrimPrefix(effect, "paired-offline-file-")
	n, err := strconv.Atoi(index)
	if begin == nil || !strings.HasPrefix(effect, "paired-offline-file-") || err != nil || n < 0 || n >= 40000 || strconv.Itoa(n) != index || o.current(ctx, id) != nil {
		return updatecheck.ErrPairedOfflineRestore
	}
	return o.gate.WithExclusiveContext(ctx, func() error {
		// This exact fixed-plan effect is compensation only. The actual Stop
		// revision is retained even when the offline config gets a new revision.
		return operationgate.WithSelfUpdateStoppedEffectAdmission(ctx, o.path, id, o.stop.InstallationID, o.stop.Sequence-1, o.stop.ConfigRevision, "replace-to-rollback", "rollback-private-"+effect, func() error {
			if err := o.pinned(); err != nil {
				return err
			}
			return begin()
		})
	})
}
