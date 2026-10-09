//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func bootstrapControllerAt(ctx context.Context, pid int) (bootstrapControllerFact, error) {
	var fact bootstrapControllerFact
	if err := ctx.Err(); err != nil {
		return fact, err
	}
	process, err := fileProcessAt(pid)
	if err != nil {
		return fact, err
	}
	start, parent, err := fileBirth(pid)
	if err != nil || start != process.Start {
		return fact, ErrInstallerControllerRole
	}
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return fact, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > 64<<10 || data[len(data)-1] != 0 {
		return fact, ErrInstallerControllerRole
	}
	defer clear(data)
	args := strings.Split(string(data[:len(data)-1]), "\x00")
	if len(args) > 256 || args[0] == "" {
		return fact, ErrInstallerControllerRole
	}
	after, err := fileProcessAt(pid)
	_, afterParent, birthErr := fileBirth(pid)
	if err != nil || birthErr != nil || after != process || afterParent != parent || ctx.Err() != nil {
		return fact, ErrInstallerControllerRole
	}
	return bootstrapControllerFact{process, parent, args}, nil
}

func (a *SelfUpdateFileAdapter) verifyInstallerControllerRole(ctx context.Context, id string, pid int) error {
	refuse := func(err error) error { return errors.Join(ErrInstallerControllerRole, err) }
	if a.checkStop(ctx, id, "read/observe") != nil {
		return refuse(ErrFileProtocol)
	}
	record, review, err := a.load(ctx, id)
	if err != nil || !validFileReviewOwner(review, record) || review.Bootstrap == nil {
		return refuse(err)
	}
	identity, err := a.helperIdentity(id, review)
	if err != nil || a.oldPanelInactive(ctx, id) != nil || a.filePanelAbsent(ctx) != nil {
		return refuse(err)
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return refuse(err)
	}
	defer root.Close()
	command, err := readFileCommand(root, id, "quiesce-old-runtime")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return refuse(err)
	}
	var openingFileReceipt selfupdatejournal.Receipt
	if command.State == "running" {
		store, err := a.OpenFileJournal()
		if err != nil {
			return refuse(err)
		}
		current, present, readErr := store.Current()
		store.Close()
		if readErr != nil || !present || current.ID != id || current.Schema != selfupdatejournal.Schema || current.Phase != "command-started" || !current.BeforeFiles || current.Command != "quiesce-old-runtime" {
			return refuse(readErr)
		}
		openingFileReceipt = current
	}
	// Prove all live roles as a closed group. In particular an arbitrary
	// outer caller cannot classify a recorded helper by borrowing its ID.
	helper, err := bootstrapControllerAt(ctx, identity.Process.PID)
	if err != nil || bootstrapControllerRole(review, record, identity, command, helper) != externalOld193InstallerRole {
		return refuse(err)
	}
	caller, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil || bootstrapControllerRole(review, record, identity, command, caller) == "" {
		return refuse(err)
	}
	peer, err := bootstrapControllerAt(ctx, pid)
	if err != nil || pid == caller.Process.PID || bootstrapControllerRole(review, record, identity, command, peer) == "" {
		return refuse(err)
	}
	if command.State == "running" {
		supervisor, err := bootstrapControllerAt(ctx, command.Supervisor.PID)
		if err != nil || bootstrapControllerRole(review, record, identity, command, supervisor) != "quiesce-supervisor" {
			return refuse(err)
		}
		child, err := bootstrapControllerAt(ctx, command.DirectPID)
		if err != nil || bootstrapControllerRole(review, record, identity, command, child) != "quiesce-child" {
			return refuse(err)
		}
		fresh, err := readFileCommand(root, id, "quiesce-old-runtime")
		if err != nil || fresh != command {
			return refuse(err)
		}
	}
	freshRecord, freshReview, err := a.loadHeader(ctx, id)
	freshIdentity, identityErr := a.helperIdentity(id, review)
	if err != nil || identityErr != nil || freshIdentity != identity || !reflect.DeepEqual(freshRecord, record) || !reflect.DeepEqual(freshReview, review) ||
		a.oldPanelInactive(ctx, id) != nil || a.filePanelAbsent(ctx) != nil || a.checkStop(ctx, id, "read/observe") != nil {
		return refuse(err)
	}
	for _, fact := range []bootstrapControllerFact{helper, caller, peer} {
		after, err := bootstrapControllerAt(ctx, fact.Process.PID)
		if err != nil || !reflect.DeepEqual(after, fact) {
			return refuse(err)
		}
	}
	if command.State == "running" {
		store, err := a.OpenFileJournal()
		if err != nil {
			return refuse(err)
		}
		closing, present, readErr := store.Current()
		store.Close()
		fresh, commandErr := readFileCommand(root, id, "quiesce-old-runtime")
		if readErr != nil || commandErr != nil || !present || !reflect.DeepEqual(closing, openingFileReceipt) || fresh != command {
			return refuse(errors.Join(readErr, commandErr))
		}
	}
	return ctx.Err()
}
