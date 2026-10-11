//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func originalOrdinaryInstallerControllerAdapter(ctx context.Context, id string) (*SelfUpdateFileAdapter, error) {
	c, ok := ctx.Value(ordinaryQuiesceJoinKey{}).(*ordinaryQuiesceJoin)
	if !ok || c == nil || c.adapter == nil || c.command.ID != id || !productionOrdinaryRoleAdapter(c.adapter) {
		return nil, ErrOrdinaryInstallerControllerRole
	}
	if current, err := ordinaryQuiesceJoinFor(ctx, c.adapter, c.command, os.Getpid()); err != nil || current != c {
		return nil, errors.Join(ErrOrdinaryInstallerControllerRole, err)
	}
	return c.adapter, nil
}

func productionOrdinaryRoleAdapter(a *SelfUpdateFileAdapter) bool {
	return a != nil && a.installation == "/opt" && a.directory == productionUpdateRoot && a.fileJournal == productionFileJournal && a.processInactive == nil && a.bootstrapCommandWait == nil &&
		os.Geteuid() == 0 && checkRootOwnedPath(a.directory) == nil && checkRootOwnedPath(a.fileJournal) == nil
}

func (a *SelfUpdateFileAdapter) verifyOrdinaryInstallerControllerRole(ctx context.Context, id string, pid int) error {
	return a.verifyOrdinaryInstallerControllerGroup(ctx, id, pid, false)
}

func (a *SelfUpdateFileAdapter) verifyCurrentOrdinaryInstallerControllerRole(ctx context.Context, id string) error {
	return a.verifyOrdinaryInstallerControllerGroup(ctx, id, os.Getpid(), true)
}

func (a *SelfUpdateFileAdapter) verifyOrdinaryInstallerControllerGroup(ctx context.Context, id string, pid int, current bool) error {
	refuse := func(err error) error { return errors.Join(ErrOrdinaryInstallerControllerRole, err) }
	if !productionOrdinaryRoleAdapter(a) || a.checkStop(ctx, id, "read/observe") != nil {
		return refuse(ErrFileProtocol)
	}
	record, review, err := a.load(ctx, id)
	if err != nil || review.Schema != selfUpdateProtocolSchema || review.Bootstrap != nil {
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
	if err != nil || command.State != "running" {
		return refuse(err)
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
		return refuse(err)
	}
	joined, err := ordinaryQuiesceJoinFor(ctx, a, command, os.Getpid())
	if err != nil {
		return refuse(err)
	}
	helper, err := bootstrapControllerAt(ctx, identity.Process.PID)
	if err != nil || ordinaryControllerRole(review, record, identity, command, helper) != "ordinary-installer" {
		return refuse(err)
	}
	supervisor, err := bootstrapControllerAt(ctx, command.Supervisor.PID)
	if err != nil || ordinaryControllerRole(review, record, identity, command, supervisor) != "quiesce-supervisor" {
		return refuse(err)
	}
	facts := []bootstrapControllerFact{helper, supervisor}
	if joined == nil {
		child, err := bootstrapControllerAt(ctx, command.DirectPID)
		if err != nil || ordinaryControllerRole(review, record, identity, command, child) != "quiesce-child" {
			return refuse(err)
		}
		facts = append(facts, child)
	}
	caller, err := bootstrapControllerAt(ctx, os.Getpid())
	callerRole := ordinaryControllerRole(review, record, identity, command, caller)
	if err != nil || callerRole == "" {
		return refuse(err)
	}
	facts = append(facts, caller)
	if current {
		if !ordinaryControllerReadRole(callerRole, pid, caller.Process.PID, joined != nil, true) {
			return refuse(ErrOrdinaryInstallerControllerRole)
		}
	} else {
		peer, err := bootstrapControllerAt(ctx, pid)
		peerRole := ordinaryControllerRole(review, record, identity, command, peer)
		if err != nil || !ordinaryControllerReadRole(peerRole, pid, caller.Process.PID, joined != nil, false) {
			return refuse(err)
		}
		facts = append(facts, peer)
	}
	freshRecord, freshReview, err := a.loadHeader(ctx, id)
	freshIdentity, identityErr := a.helperIdentity(id, review)
	if err != nil || identityErr != nil || freshIdentity != identity || !reflect.DeepEqual(freshRecord, record) || !reflect.DeepEqual(freshReview, review) ||
		a.oldPanelInactive(ctx, id) != nil || a.filePanelAbsent(ctx) != nil || a.checkStop(ctx, id, "read/observe") != nil {
		return refuse(err)
	}
	for _, fact := range facts {
		after, err := bootstrapControllerAt(ctx, fact.Process.PID)
		if err != nil || !reflect.DeepEqual(after, fact) {
			return refuse(err)
		}
	}
	closing, err := readReceipt()
	freshCommand, commandErr := readFileCommand(root, id, command.Command)
	freshJoin, joinErr := ordinaryQuiesceJoinFor(ctx, a, freshCommand, os.Getpid())
	if err != nil || commandErr != nil || joinErr != nil || freshCommand != command || freshJoin != joined || !reflect.DeepEqual(closing, opening) {
		return refuse(errors.Join(err, commandErr, joinErr))
	}
	return ctx.Err()
}
