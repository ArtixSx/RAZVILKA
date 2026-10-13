//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func (a *SelfUpdateFileAdapter) withOrdinaryInstallerControllerObservation(ctx context.Context, id string, use func(context.Context, *OrdinaryInstallerControllerObservation) error) (result error) {
	if ctx.Value(ordinaryInstallerJoinKey{}) != nil {
		return a.withJoinedOrdinaryInstallerObservation(ctx, id, use)
	}
	refuse := ordinaryInstallerRoleAt
	if !productionOrdinaryRoleAdapter(a) {
		return refuse("source", ErrFileProtocol)
	}
	if err := a.checkStop(ctx, id, "read/observe"); err != nil {
		return refuse("control-opening", err)
	}
	// Each observation authenticates its own release artifacts and migrated
	// config. This never borrows a load, group or byte image from Bind/current.
	record, review, err := a.load(ctx, id)
	if err != nil || review.Schema != selfUpdateProtocolSchema || review.Bootstrap != nil {
		return refuse("review-opening", err)
	}
	identity, err := a.helperIdentity(id, review)
	if err != nil {
		return refuse("helper-identity-opening", err)
	}
	if err := a.oldPanelInactive(ctx, id); err != nil {
		return refuse("old-panel-opening", err)
	}
	if err := a.filePanelAbsent(ctx); err != nil {
		return refuse("panel-absent-opening", err)
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
	command, err := readFileCommand(root, id, "quiesce-old-runtime")
	if err != nil || command.State != "running" {
		return refuse("command-opening", err)
	}
	readReceipt := func() (selfupdatejournal.Receipt, error) {
		store, err := a.OpenFileJournal()
		if err != nil {
			return selfupdatejournal.Receipt{}, err
		}
		defer store.Close()
		current, present, err := store.Current()
		if err != nil || !present || current.ID != id || current.Schema != selfupdatejournal.Schema || current.Phase != "command-started" || !current.BeforeFiles || current.Command != command.Command {
			return current, errors.Join(ErrOrdinaryInstallerControllerRole, err)
		}
		return current, nil
	}
	opening, err := readReceipt()
	if err != nil {
		return refuse("receipt-opening", err)
	}
	joined, err := ordinaryQuiesceJoinFor(ctx, a, command, os.Getpid())
	if err != nil {
		return refuse("join-opening", err)
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
			// A persistent artifact/config change during the callback must also
			// fail closing. This slow boundary precedes the full group bookend.
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
		if err := a.checkStop(c, id, "read/observe"); err != nil {
			return refuse("control-closing", err)
		}
		closing, receiptErr := readReceipt()
		freshCommand, commandErr := readFileCommand(root, id, command.Command)
		freshJoin, joinErr := ordinaryQuiesceJoinFor(c, a, freshCommand, os.Getpid())
		if receiptErr != nil || commandErr != nil || joinErr != nil || freshCommand != command || freshJoin != joined || !reflect.DeepEqual(closing, opening) {
			return refuse("receipt-closing", errors.Join(receiptErr, commandErr, joinErr))
		}
		if err := c.Err(); err != nil {
			return refuse("context-closing", err)
		}
		return nil
	}
	source := ordinaryObservationSource{review: review, record: record, identity: identity, command: command,
		caller: os.Getpid(), joined: joined != nil, read: image.controllerAt, check: check,
		clear: func() { image.clear(); root.Close() }}
	transferred = true
	return runOrdinaryControllerObservation(ctx, source, use)
}
