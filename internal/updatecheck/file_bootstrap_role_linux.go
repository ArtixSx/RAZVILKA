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
	"time"

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

func (a *SelfUpdateFileAdapter) verifyInstallerControllerRole(ctx context.Context, id string, pid int) (result error) {
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
	joined, err := bootstrapQuiesceJoinFor(ctx, a, command, os.Getpid())
	if err != nil {
		return refuse(err)
	}
	if joined != nil {
		if err := bootstrapJoinedChildAbsent(ctx, command); err != nil {
			return refuse(err)
		}
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
	// One role call owns one fresh authenticated executable image. Every
	// occurrence still reads all actual bytes+EOF and all process bookends;
	// only repeated SHA work over identical bytes becomes exact comparison.
	image, err := bootstrapExecutableImage(ctx, review)
	if err != nil {
		return refuse(err)
	}
	defer func() { result = finishBootstrapExecutableImage(ctx, image, result) }()
	// Prove all live roles as a closed group. In particular an arbitrary
	// outer caller cannot classify a recorded helper by borrowing its ID.
	helper, err := image.controllerAt(identity.Process.PID)
	if err != nil || bootstrapControllerRole(review, record, identity, command, helper) != externalOld193InstallerRole {
		return refuse(err)
	}
	caller, err := image.controllerAt(os.Getpid())
	callerRole := bootstrapControllerRole(review, record, identity, command, caller)
	if err != nil || callerRole == "" || joined != nil && callerRole != "quiesce-supervisor" {
		return refuse(err)
	}
	peer, err := image.controllerAt(pid)
	peerRole := bootstrapControllerRole(review, record, identity, command, peer)
	if err != nil || pid == caller.Process.PID || peerRole == "" || joined != nil && peerRole == "quiesce-child" {
		return refuse(err)
	}
	if command.State == "running" {
		supervisor, err := image.controllerAt(command.Supervisor.PID)
		if err != nil || bootstrapControllerRole(review, record, identity, command, supervisor) != "quiesce-supervisor" {
			return refuse(err)
		}
		if joined == nil {
			child, err := image.controllerAt(command.DirectPID)
			if err != nil || bootstrapControllerRole(review, record, identity, command, child) != "quiesce-child" {
				return refuse(err)
			}
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
		after, err := image.controllerAt(fact.Process.PID)
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
		freshJoin, joinErr := bootstrapQuiesceJoinFor(ctx, a, fresh, os.Getpid())
		if readErr != nil || commandErr != nil || joinErr != nil || freshJoin != joined || !present || !reflect.DeepEqual(closing, openingFileReceipt) || fresh != command {
			return refuse(errors.Join(readErr, commandErr, joinErr))
		}
		if joined != nil {
			if err := bootstrapJoinedChildAbsent(ctx, command); err != nil {
				return refuse(err)
			}
		}
	}
	return ctx.Err()
}

func bootstrapExecutableImage(ctx context.Context, review fileReview) (*ordinaryExecutableImage, error) {
	if review.Bootstrap == nil {
		return nil, ErrInstallerControllerRole
	}
	// The original old193 panel is a different binary. Never authenticate these
	// actual candidate/helper occurrences against its old executable digest.
	return newOrdinaryExecutableImage(ctx, review.Bootstrap.HelperSHA256)
}

func finishBootstrapExecutableImage(ctx context.Context, image *ordinaryExecutableImage, result error) error {
	deadline := image.deadline
	image.clear()
	// Clearing the privately retained image is part of this synchronous call.
	// A successful body must not escape cancellation/deadline during cleanup.
	closing := ctx.Err()
	if !deadline.After(time.Now()) {
		closing = errors.Join(closing, context.DeadlineExceeded)
	}
	if closing != nil {
		return errors.Join(result, ErrInstallerControllerRole, closing)
	}
	return result
}
