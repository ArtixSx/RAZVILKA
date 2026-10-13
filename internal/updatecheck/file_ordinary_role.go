package updatecheck

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var ErrOrdinaryInstallerControllerRole = errors.New("self update controller has no current verified ordinary installer role")

// OriginalOrdinaryInstallerControllerAdapter returns the actual command
// worker's or joined original helper's adapter in its finite owner scope. (nil, nil)
// means this finite context has no ordinary join: a live child uses its local
// adapter and still has to prove the entire live group. A present invalid join
// returns an error, never permission to fall back to a bootstrap role.
func OriginalOrdinaryInstallerControllerAdapter(ctx context.Context, id string) (*SelfUpdateFileAdapter, error) {
	if ctx == nil || !jobIDPattern.MatchString(id) {
		return nil, ErrOrdinaryInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if !finite || !deadline.After(time.Now()) || ctx.Err() != nil {
		return nil, errors.Join(ErrOrdinaryInstallerControllerRole, ctx.Err())
	}
	if ctx.Value(ordinaryQuiesceJoinKey{}) == nil && ctx.Value(ordinaryInstallerJoinKey{}) == nil {
		return nil, nil
	}
	return originalOrdinaryInstallerControllerAdapter(ctx, id)
}

// VerifyOrdinaryInstallerControllerRole classifies a different process in the
// sealed ordinary helper group. It never classifies the caller itself and
// grants no effect, inactivity, health or retirement result.
// The existing bootstrap role API remains distinct and unchanged.
func (a *SelfUpdateFileAdapter) VerifyOrdinaryInstallerControllerRole(ctx context.Context, id string, pid int) error {
	if a == nil || ctx == nil || pid <= 1 || !jobIDPattern.MatchString(id) {
		return ErrOrdinaryInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if !finite || !deadline.After(time.Now()) || ctx.Err() != nil {
		return errors.Join(ErrOrdinaryInstallerControllerRole, ctx.Err())
	}
	return a.verifyOrdinaryInstallerControllerRole(ctx, id, pid)
}

// VerifyCurrentOrdinaryInstallerControllerRole verifies the actual calling
// quiescer, joined command worker or original joined helper against its sealed
// ordinary group. No supplied PID, persisted receipt or role label selects
// that caller. Peer classification remains a separate read.
func (a *SelfUpdateFileAdapter) VerifyCurrentOrdinaryInstallerControllerRole(ctx context.Context, id string) error {
	if a == nil || ctx == nil || !jobIDPattern.MatchString(id) {
		return ErrOrdinaryInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if !finite || !deadline.After(time.Now()) || ctx.Err() != nil {
		return errors.Join(ErrOrdinaryInstallerControllerRole, ctx.Err())
	}
	return a.verifyCurrentOrdinaryInstallerControllerRole(ctx, id)
}

func ordinaryControllerReadRole(role string, pid, caller int, joined, current bool) bool {
	if current {
		return pid == caller && ((!joined && role == "quiesce-child") || (joined && role == "quiesce-supervisor"))
	}
	return pid != caller && role != "" && (!joined || role != "quiesce-child")
}

func ordinaryControllerRole(review fileReview, record updateRecord, identity fileHelperIdentity, command fileCommandReceipt, fact bootstrapControllerFact) string {
	_, _, oldValid := parseComparableVersion(review.OldVersion)
	_, _, newValid := parseComparableVersion(review.NewVersion)
	if review.Schema != selfUpdateProtocolSchema || review.Bootstrap != nil || !validJournalReaderProof(review.JournalReaders) || review.JournalReaders.RequiredReader != selfupdatejournal.PairedSchema ||
		!oldValid || !newValid || compareVersions(review.OldVersion, "0.20.0") < 0 || compareVersions(review.NewVersion, review.OldVersion) <= 0 ||
		record.CurrentVersion != review.OldVersion || record.Job.Release == nil || record.Job.Release.Version != review.NewVersion || record.Job.Release.ID != review.ReleaseID ||
		record.Owner != updaterOwner || record.Job.ID != review.ID || record.Job.ConfigRevision != review.Revision || record.ExecutableHash != review.OldExecutableSHA256 ||
		record.Job.State != "restarting" || record.Job.Stage != "file-protocol" || record.Job.ReviewToken != "" || record.Job.CanApply || record.Job.CanCancel ||
		identity.Schema != selfUpdateProtocolSchema || identity.ID != review.ID || !validFileProcess(identity.Process) || !validFileProcess(identity.OldPanel) ||
		identity.Process.Boot != identity.OldPanel.Boot || identity.Process.PID == identity.OldPanel.PID || identity.Process.ExecutableSHA256 != review.OldExecutableSHA256 ||
		identity.OldPanel.ExecutableSHA256 != review.OldExecutableSHA256 || record.Job.HelperPID != identity.Process.PID || record.ParentPID != identity.OldPanel.PID ||
		!validFileCommandReceipt(command) || command.ID != review.ID || command.Command != "quiesce-old-runtime" || command.Parent != identity.Process || command.State != "running" ||
		command.Supervisor.ExecutableSHA256 != review.OldExecutableSHA256 || command.Supervisor.PID == identity.Process.PID || command.DirectPID == identity.Process.PID || command.DirectPID == command.Supervisor.PID ||
		!validFileProcess(fact.Process) || len(fact.Args) == 0 || fact.Args[0] == "" {
		return ""
	}
	args := fact.Args[1:]
	if fact.Process == identity.Process && len(args) == 2 && args[0] == "self-update-helper" && args[1] == review.ID {
		return "ordinary-installer"
	}
	if fact.Process == command.Supervisor && fact.Parent == identity.Process.PID && len(args) == 3 && args[0] == "self-update-command-helper" && args[1] == review.ID && args[2] == command.Command {
		return "quiesce-supervisor"
	}
	if fact.Process.PID == command.DirectPID && fact.Process.Boot == command.Supervisor.Boot && fact.Process.ExecutableSHA256 == review.OldExecutableSHA256 && fact.Parent == command.Supervisor.PID &&
		len(args) == 4 && args[0] == "self-update-runtime-quiesce" && args[1] == review.ID && args[2] == bootstrapDecimal(review.Revision) && args[3] == bootstrapDecimal(uint64(command.Supervisor.PID)) {
		return "quiesce-child"
	}
	return ""
}

type ordinaryQuiesceJoinKey struct{}

// Only the actual command worker mints this private, short-lived capability,
// after wait4 observed the direct child exit 0 and then ECHILD. No persisted
// receipt can reconstruct it. Derived observer contexts inherit cancellation
// and the original deadline; copying the capability invalidates its self seal.
type ordinaryQuiesceJoin struct {
	self     *ordinaryQuiesceJoin
	adapter  *SelfUpdateFileAdapter
	original context.Context
	deadline time.Time
	command  fileCommandReceipt
	reaped   int
	active   atomic.Bool
}

func ordinaryJoinedQuiesceContext(a *SelfUpdateFileAdapter, ctx context.Context, launched fileCommandReceipt, reaped int) (context.Context, func()) {
	if ctx == nil {
		return nil, func() {}
	}
	deadline, finite := ctx.Deadline()
	if a == nil || !finite || ctx.Err() != nil || !deadline.After(time.Now()) || reaped <= 0 || !validFileCommandReceipt(launched) || launched.Command != "quiesce-old-runtime" || launched.State != "running" {
		return ctx, func() {}
	}
	c := &ordinaryQuiesceJoin{adapter: a, original: ctx, deadline: deadline, command: launched, reaped: reaped}
	c.self = c
	c.active.Store(true)
	return context.WithValue(ctx, ordinaryQuiesceJoinKey{}, c), func() { c.active.Store(false) }
}

func ordinaryQuiesceJoinFor(ctx context.Context, a *SelfUpdateFileAdapter, command fileCommandReceipt, caller int) (*ordinaryQuiesceJoin, error) {
	value := ctx.Value(ordinaryQuiesceJoinKey{})
	if value == nil {
		return nil, nil
	}
	c, present := value.(*ordinaryQuiesceJoin)
	if !present {
		return nil, ErrOrdinaryInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if c == nil || c.self != c || c.adapter != a || !c.active.Load() || c.reaped <= 0 || c.original == nil || c.original.Err() != nil || ctx.Err() != nil ||
		!finite || deadline.After(c.deadline) || !c.deadline.After(time.Now()) || command != c.command || caller != command.Supervisor.PID {
		return nil, ErrOrdinaryInstallerControllerRole
	}
	return c, nil
}
