package updatecheck

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

type ordinaryInstallerJoinKey struct{}

// This owner exists only around the original H callback. A completed receipt
// cannot create it or attach the exec-created child and its sole actual Wait.
type ordinaryInstallerJoin struct {
	self      *ordinaryInstallerJoin
	adapter   *SelfUpdateFileAdapter
	id        string
	original  context.Context
	held      context.Context
	deadline  time.Time
	active    atomic.Bool
	failed    atomic.Bool
	mu        sync.Mutex
	wait      *ordinaryInstallerWait
	candidate *candidateStartWait
}

type ordinaryInstallerWait struct {
	self       *ordinaryInstallerWait
	owner      *ordinaryInstallerJoin
	worker     *exec.Cmd
	process    *os.Process
	parent     fileProcess
	supervisor fileProcess
	waited     atomic.Bool
	command    fileCommandReceipt // published under owner.mu only after actual Wait
}

// WithOriginalOrdinaryInstallerJoin scopes provenance around the original
// helper execution. The callback receives no role before its own quiesce child
// is joined. The platform refuses cold, copied or non-production construction.
func (a *SelfUpdateFileAdapter) WithOriginalOrdinaryInstallerJoin(ctx context.Context, id string, use func(context.Context) error) error {
	if a == nil || ctx == nil || use == nil || !jobIDPattern.MatchString(id) {
		return ErrOrdinaryInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if !finite || ctx.Err() != nil || !deadline.After(time.Now()) || ctx.Value(ordinaryInstallerJoinKey{}) != nil || ctx.Value(ordinaryQuiesceJoinKey{}) != nil {
		return errors.Join(ErrOrdinaryInstallerControllerRole, ctx.Err())
	}
	return a.withOriginalOrdinaryInstallerJoin(ctx, id, use)
}

func runOrdinaryInstallerJoinScope(a *SelfUpdateFileAdapter, ctx context.Context, id string, use func(context.Context) error) (result error) {
	deadline, _ := ctx.Deadline()
	o := &ordinaryInstallerJoin{adapter: a, id: id, original: ctx, deadline: deadline}
	o.self = o
	o.active.Store(true)
	o.held = context.WithValue(ctx, ordinaryInstallerJoinKey{}, o)
	defer func() {
		o.active.Store(false)
		o.mu.Lock()
		candidate := o.candidate
		o.mu.Unlock()
		if candidate != nil {
			candidate.close()
		}
		if o.failed.Load() {
			result = errors.Join(result, ErrOrdinaryInstallerControllerRole)
		}
		result = errors.Join(result, ctx.Err())
	}()
	return use(o.held)
}

func (o *ordinaryInstallerJoin) poison(err error) error {
	if o != nil && o.self != nil && o.self.self == o.self {
		o.self.failed.Store(true)
	}
	return errors.Join(ErrOrdinaryInstallerControllerRole, err)
}

func (o *ordinaryInstallerJoin) current(ctx context.Context, a *SelfUpdateFileAdapter, id string) error {
	if o == nil || o.self != o || o.adapter != a || o.id != id || o.original == nil || ctx == nil || ctx.Value(ordinaryInstallerJoinKey{}) != o || ctx.Value(ordinaryQuiesceJoinKey{}) != nil {
		return o.poison(nil)
	}
	deadline, finite := ctx.Deadline()
	if !o.active.Load() || o.failed.Load() || !finite || deadline.After(o.deadline) || !o.deadline.After(time.Now()) || ctx.Err() != nil || o.original.Err() != nil {
		return o.poison(errors.Join(ctx.Err(), o.original.Err()))
	}
	return nil
}

func ordinaryInstallerOwner(ctx context.Context, a *SelfUpdateFileAdapter, id string) (*ordinaryInstallerJoin, error) {
	if ctx == nil {
		return nil, ErrOrdinaryInstallerControllerRole
	}
	o, ok := ctx.Value(ordinaryInstallerJoinKey{}).(*ordinaryInstallerJoin)
	if !ok || o == nil {
		return nil, ErrOrdinaryInstallerControllerRole
	}
	if err := o.current(ctx, a, id); err != nil {
		return nil, err
	}
	return o, nil
}

// Called before the sole Wait, with the actual exec-created process handle.
// Platform code supplies kernel identities and verifies the actual H/S caller.
func beginOrdinaryInstallerWait(ctx context.Context, a *SelfUpdateFileAdapter, id string, worker *exec.Cmd, parent, supervisor fileProcess) (*ordinaryInstallerWait, error) {
	o, err := ordinaryInstallerOwner(ctx, a, id)
	if err != nil {
		return nil, err
	}
	if ctx != o.held || worker == nil || worker.Process == nil || worker.ProcessState != nil || worker.Path == "" || !validFileProcess(parent) || !validFileProcess(supervisor) ||
		parent.PID != os.Getpid() || worker.Process.Pid != supervisor.PID || supervisor.PID == parent.PID || supervisor.Boot != parent.Boot || supervisor.ExecutableSHA256 != parent.ExecutableSHA256 {
		return nil, o.poison(nil)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.wait != nil || o.current(ctx, a, id) != nil {
		return nil, o.poison(nil)
	}
	w := &ordinaryInstallerWait{owner: o, worker: worker, process: worker.Process, parent: parent, supervisor: supervisor}
	w.self = w
	o.wait = w
	return w, nil
}

// Invoked by the existing sole worker.Wait goroutine, before publishing done.
func (w *ordinaryInstallerWait) observeWait(err error) {
	if w == nil || w.self != w || w.owner == nil {
		return
	}
	state := w.worker.ProcessState
	if w.waited.Load() || err != nil || w.worker.Process != w.process || state == nil || state.Pid() != w.supervisor.PID || !state.Exited() || !state.Success() || state.ExitCode() != 0 {
		w.owner.poison(err)
		return
	}
	w.waited.Store(true)
}

func completedOrdinaryQuiesce(command fileCommandReceipt) bool {
	return validFileCommandReceipt(command) && command.Command == "quiesce-old-runtime" && command.State == "reaped" && command.WaitECHILD && !command.Cancelled && command.ExitCode == 0 &&
		command.Reaped > 0 && command.Runtime == (fileProcess{}) && command.Supervisor.PID != command.Parent.PID && command.DirectPID != command.Parent.PID && command.DirectPID != command.Supervisor.PID &&
		command.Supervisor.ExecutableSHA256 == command.Parent.ExecutableSHA256
}

func (w *ordinaryInstallerWait) complete(ctx context.Context, command fileCommandReceipt) error {
	if w == nil || w.self != w || w.owner == nil {
		return ErrOrdinaryInstallerControllerRole
	}
	o := w.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.current(ctx, o.adapter, o.id); err != nil {
		return err
	}
	if ctx != o.held || o.wait != w || !w.waited.Load() || w.command != (fileCommandReceipt{}) || !completedOrdinaryQuiesce(command) || command.ID != o.id || command.Parent != w.parent || command.Supervisor != w.supervisor {
		return o.poison(nil)
	}
	w.command = command
	return nil
}

func (o *ordinaryInstallerJoin) joined(ctx context.Context, a *SelfUpdateFileAdapter, id string, caller int) (fileCommandReceipt, error) {
	if err := o.current(ctx, a, id); err != nil {
		return fileCommandReceipt{}, err
	}
	if !o.mu.TryLock() {
		return fileCommandReceipt{}, o.poison(nil)
	}
	defer o.mu.Unlock()
	w := o.wait
	if w == nil || w.self != w || w.owner != o || !w.waited.Load() || !completedOrdinaryQuiesce(w.command) || w.command.Parent != w.parent || w.command.Supervisor != w.supervisor || caller != w.parent.PID {
		return fileCommandReceipt{}, o.poison(nil)
	}
	return w.command, o.current(ctx, a, id)
}

func ordinaryJoinedInstallerRole(review fileReview, record updateRecord, identity fileHelperIdentity, command fileCommandReceipt, fact bootstrapControllerFact) string {
	if !completedOrdinaryQuiesce(command) || command.ID != review.ID || command.Parent != identity.Process {
		return ""
	}
	return ordinaryInstallerIdentityRole(review, record, identity, fact)
}

func ordinaryInstallerIdentityRole(review fileReview, record updateRecord, identity fileHelperIdentity, fact bootstrapControllerFact) string {
	if review.Schema != selfUpdateProtocolSchema || review.Bootstrap != nil || !validJournalReaderProof(review.JournalReaders) || review.JournalReaders.RequiredReader != selfupdatejournal.PairedSchema ||
		!ordinaryFutureVersions(review.OldVersion, review.NewVersion) ||
		record.CurrentVersion != review.OldVersion || record.Job.Release == nil || record.Job.Release.Version != review.NewVersion || record.Job.Release.ID != review.ReleaseID ||
		record.Owner != updaterOwner || record.Job.ID != review.ID || record.Job.ConfigRevision != review.Revision || record.ExecutableHash != review.OldExecutableSHA256 ||
		record.Job.State != "restarting" || record.Job.Stage != "file-protocol" || record.Job.ReviewToken != "" || record.Job.CanApply || record.Job.CanCancel ||
		identity.Schema != selfUpdateProtocolSchema || identity.ID != review.ID || !validFileProcess(identity.Process) || !validFileProcess(identity.OldPanel) ||
		identity.Process.Boot != identity.OldPanel.Boot || identity.Process.PID == identity.OldPanel.PID || identity.Process.ExecutableSHA256 != review.OldExecutableSHA256 ||
		identity.OldPanel.ExecutableSHA256 != review.OldExecutableSHA256 || record.Job.HelperPID != identity.Process.PID || record.ParentPID != identity.OldPanel.PID ||
		!validFileProcess(fact.Process) || fact.Process != identity.Process || len(fact.Args) != 3 || fact.Args[0] == "" || fact.Args[1] != "self-update-helper" || fact.Args[2] != review.ID {
		return ""
	}
	return "ordinary-installer"
}

func ordinaryJoinedInstallReceipt(receipt selfupdatejournal.Receipt, id string) bool {
	return receipt.Schema == selfupdatejournal.Schema && receipt.ID == id && !receipt.Rollback && !receipt.BeforeFiles && receipt.Command == "" &&
		(receipt.Phase == "prepared" && receipt.Index == 0 || receipt.Phase == "installing" && receipt.Index >= 0 && receipt.Index <= 6) && len(receipt.Commands) == 3 &&
		receipt.Commands[0] == "stop-old-panel" && receipt.Commands[1] == "prepare-private-state" && receipt.Commands[2] == "quiesce-old-runtime"
}
