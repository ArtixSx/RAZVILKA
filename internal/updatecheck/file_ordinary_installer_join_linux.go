//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func (a *SelfUpdateFileAdapter) withOriginalOrdinaryInstallerJoin(ctx context.Context, id string, use func(context.Context) error) error {
	// The file journal may not yet exist before Prepare. No pending owner
	// grants a role; the actual producer and every reader check owned roots.
	if a.installation != "/opt" || a.directory != productionUpdateRoot || a.fileJournal != productionFileJournal || a.processInactive != nil || a.bootstrapCommandWait != nil ||
		a.admission == nil || a.runtimeInactive == nil || a.stopCheck == nil || os.Geteuid() != 0 {
		return ErrOrdinaryInstallerControllerRole
	}
	return runOrdinaryInstallerJoinScope(a, ctx, id, use)
}

func (a *SelfUpdateFileAdapter) prepareOriginalOrdinaryInstallerWait(ctx context.Context, id string, worker *exec.Cmd, parent fileProcess, record updateRecord, review fileReview, identity fileHelperIdentity) (func(fileProcess) (*ordinaryInstallerWait, error), error) {
	o, err := ordinaryInstallerOwner(ctx, a, id)
	if err != nil {
		return nil, err
	}
	if !productionOrdinaryRoleAdapter(a) || review.ID != id || identity.Process != parent || worker == nil || worker.Process != nil || len(worker.Args) != 4 || worker.Args[1] != "self-update-command-helper" || worker.Args[2] != id || worker.Args[3] != "quiesce-old-runtime" ||
		worker.Path != filepath.Join(a.directory, id, "control.bin") {
		return nil, o.poison(nil)
	}
	fact, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil || ordinaryInstallerIdentityRole(review, record, identity, fact) != "ordinary-installer" {
		return nil, o.poison(err)
	}
	// Authenticate H before Start; hashing H after Start could let a fast S
	// finish before its parent/birth bookend. S is then captured before Wait.
	return func(supervisor fileProcess) (*ordinaryInstallerWait, error) {
		birth, ppid, err := fileBirth(supervisor.PID)
		if err != nil || birth != supervisor.Start || ppid != parent.PID {
			return nil, o.poison(err)
		}
		return beginOrdinaryInstallerWait(ctx, a, id, worker, parent, supervisor)
	}, nil
}

func originalJoinedOrdinaryInstallerAdapter(ctx context.Context, id string) (*SelfUpdateFileAdapter, error) {
	o, ok := ctx.Value(ordinaryInstallerJoinKey{}).(*ordinaryInstallerJoin)
	if !ok || o == nil || !productionOrdinaryRoleAdapter(o.adapter) {
		return nil, ErrOrdinaryInstallerControllerRole
	}
	if _, err := o.joined(ctx, o.adapter, id, os.Getpid()); err != nil {
		return nil, err
	}
	return o.adapter, nil
}

// Reject any live or reused S/C PID. Birth mismatch, a different boot or an
// empty process title cannot stand in for the original actual join.
func ordinaryJoinedProcessesAbsent(ctx context.Context, command fileCommandReceipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := fileBoot()
	if err != nil || boot != command.Parent.Boot || !completedOrdinaryQuiesce(command) {
		return errors.Join(ErrOrdinaryInstallerControllerRole, err)
	}
	for _, pid := range []int{command.Supervisor.PID, command.DirectPID} {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrOrdinaryInstallerControllerRole, err)
		}
	}
	return ctx.Err()
}

func (a *SelfUpdateFileAdapter) withJoinedOrdinaryInstallerObservation(ctx context.Context, id string, use func(context.Context, *OrdinaryInstallerControllerObservation) error) (result error) {
	refuse := ordinaryInstallerRoleAt
	if !productionOrdinaryRoleAdapter(a) {
		return refuse("source", ErrFileProtocol)
	}
	o, err := ordinaryInstallerOwner(ctx, a, id)
	if err != nil {
		return refuse("join-opening", err)
	}
	command, err := o.joined(ctx, a, id, os.Getpid())
	if err != nil {
		return refuse("join-opening", err)
	}
	if err := a.checkStop(ctx, id, "read/observe"); err != nil {
		return refuse("control-opening", err)
	}
	record, review, err := a.load(ctx, id)
	if err != nil || review.ID != id || review.Bootstrap != nil {
		return refuse("review-opening", err)
	}
	identity, err := a.helperIdentity(id, review)
	if err != nil || identity.Process != command.Parent {
		return refuse("helper-identity-opening", err)
	}
	if err := a.oldPanelInactive(ctx, id); err != nil {
		return refuse("old-panel-opening", err)
	}
	if err := a.filePanelAbsent(ctx); err != nil {
		return refuse("panel-absent-opening", err)
	}
	if err := ordinaryJoinedProcessesAbsent(ctx, command); err != nil {
		return refuse("facts-closing", err)
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return refuse("command-root", err)
	}
	var image *ordinaryExecutableImage
	transferred := false
	defer func() {
		if !transferred {
			if image != nil {
				image.clear()
			}
			root.Close()
			result = errors.Join(result, ctx.Err())
		}
	}()
	if actual, err := readFileCommand(root, id, command.Command); err != nil || actual != command {
		return refuse("command-opening", err)
	}
	readReceipt := func() (selfupdatejournal.Receipt, error) {
		store, err := a.OpenFileJournal()
		if err != nil {
			return selfupdatejournal.Receipt{}, err
		}
		defer store.Close()
		current, present, err := store.Current()
		if err != nil || !present || !ordinaryJoinedInstallReceipt(current, id) {
			return current, errors.Join(ErrOrdinaryInstallerControllerRole, err)
		}
		return current, nil
	}
	opening, err := readReceipt()
	if err != nil {
		return refuse("receipt-opening", err)
	}
	image, err = newOrdinaryExecutableImage(ctx, review.OldExecutableSHA256)
	if err != nil {
		return refuse("helper-opening", err)
	}
	check := func(c context.Context, artifacts bool) error {
		if !productionOrdinaryRoleAdapter(a) {
			return refuse("source", ErrFileProtocol)
		}
		if err := a.checkStop(c, id, "read/observe"); err != nil {
			return refuse("control-closing", err)
		}
		var freshRecord updateRecord
		var freshReview fileReview
		var err error
		if artifacts {
			freshRecord, freshReview, err = a.load(c, id)
		} else {
			freshRecord, freshReview, err = a.loadHeader(c, id)
		}
		freshIdentity, identityErr := a.helperIdentity(id, review)
		if err != nil || identityErr != nil || freshIdentity != identity || !reflect.DeepEqual(freshRecord, record) || !reflect.DeepEqual(freshReview, review) {
			return refuse("header-closing", errors.Join(err, identityErr))
		}
		if err := a.oldPanelInactive(c, id); err != nil {
			return refuse("old-panel-closing", err)
		}
		if err := a.filePanelAbsent(c); err != nil {
			return refuse("panel-absent-closing", err)
		}
		if err := ordinaryJoinedProcessesAbsent(c, command); err != nil {
			return refuse("facts-closing", err)
		}
		closing, receiptErr := readReceipt()
		freshCommand, commandErr := readFileCommand(root, id, command.Command)
		joinedCommand, joinErr := o.joined(c, a, id, os.Getpid())
		if receiptErr != nil || commandErr != nil || joinErr != nil || freshCommand != command || joinedCommand != command || !reflect.DeepEqual(closing, opening) {
			return refuse("receipt-closing", errors.Join(receiptErr, commandErr, joinErr))
		}
		return c.Err()
	}
	source := ordinaryObservationSource{review: review, record: record, identity: identity, command: command, caller: os.Getpid(), installerJoin: o,
		read: image.controllerAt, check: check, clear: func() { image.clear(); root.Close() }}
	transferred = true
	return runOrdinaryControllerObservation(ctx, source, use)
}
