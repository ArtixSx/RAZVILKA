package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var ErrPairedRetirementOwner = errors.New("paired retirement requires the original completed live App owner")

// RetireCompletedPairedState is the App consumer, not a recovery command. The
// original finite App operation supplies owner; physical process evidence must
// independently identify this process as the candidate actually handed off by
// the completed command. A cold App, helper or reader cannot acquire the role.
func (a *SelfUpdateFileAdapter) RetireCompletedPairedState(ctx context.Context, id string, startupWorkerPID int, owner SelfUpdateRuntimeObservation) error {
	if runtime.GOOS != "linux" || a == nil || ctx == nil || owner == nil || ctx.Err() != nil || startupWorkerPID <= 1 || !jobIDPattern.MatchString(id) ||
		a.installation != "/opt" || a.directory != productionUpdateRoot || a.fileJournal != productionFileJournal || a.owned == nil || a.admission == nil || a.processInactive != nil {
		return ErrPairedRetirementOwner
	}
	if deadline, finite := ctx.Deadline(); !finite || !deadline.After(time.Now()) {
		return ErrPairedRetirementOwner
	}
	if err := owner(ctx, id); err != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	record, review, err := a.loadBoundReview(ctx, id, true, true)
	if err != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	receipt, err := store.RetainedReceipt(ctx, id)
	store.Close()
	if err != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	job, err := a.commandRoot(id)
	if err != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	command, err := readFileCommand(job, id, "start-candidate-panel")
	job.Close()
	if err != nil || validatePairedRetirementSource(record, review, receipt, command, startupWorkerPID) != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	p := &completedPairedRetirement{adapter: a, original: ctx, owner: owner, record: record, review: review, receipt: receipt, command: command, workerPID: startupWorkerPID}
	for i, path := range []string{a.directory, filepath.Join(a.directory, id), a.fileJournal} {
		p.roots[i], err = os.Lstat(path)
		if err != nil {
			return errors.Join(ErrPairedRetirementOwner, err)
		}
	}
	p.self = p
	if err := p.current(ctx, id); err != nil {
		return err
	}
	if err := a.RetirePairedPriorState(ctx, id, p.current); err != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	return p.current(ctx, id)
}

type completedPairedRetirement struct {
	self      *completedPairedRetirement
	adapter   *SelfUpdateFileAdapter
	original  context.Context
	owner     SelfUpdateRuntimeObservation
	record    updateRecord
	review    fileReview
	receipt   selfupdatejournal.Receipt
	command   fileCommandReceipt
	workerPID int
	roots     [3]os.FileInfo
}

func validatePairedRetirementSource(record updateRecord, review fileReview, receipt selfupdatejournal.Receipt, command fileCommandReceipt, workerPID int) error {
	if record.Owner != updaterOwner || record.Job.State != "completed" || record.Job.Stage != "completed" || record.Job.CanApply || record.Job.CanCancel || record.Job.ReviewToken != "" ||
		receipt.ID != record.Job.ID || receipt.Schema != selfupdatejournal.PairedSchema || receipt.Paired == nil || receipt.Rollback ||
		(receipt.Phase != "accepted" && receipt.Phase != "archived") || review.ID != record.Job.ID || !validFileReviewOwner(review, record) ||
		review.Bootstrap != nil && review.Bootstrap.Mode != "live" || record.FileReviewSHA256 != receipt.Paired.ReviewSHA256 ||
		review.AuthorityInstallationID != receipt.Paired.InstallationID || review.AuthoritySequence != receipt.Paired.Sequence || review.Revision != receipt.Paired.Revision ||
		command.ID != receipt.ID || command.Command != "start-candidate-panel" || command.State != "runtime-handed-off" || command.Cancelled || command.ExitCode != 0 ||
		command.Supervisor.PID != workerPID || command.Parent.PID != record.Job.HelperPID || !validFileCommandReceipt(command) || command.Runtime == (fileProcess{}) {
		return ErrPairedRetirementOwner
	}
	candidate := ""
	for _, file := range receipt.Files {
		if file.Target == "bin/razvilka" {
			candidate = file.NewHash
		}
	}
	if candidate != command.Runtime.ExecutableSHA256 || !validDigest("sha256:"+candidate) {
		return ErrPairedRetirementOwner
	}
	return nil
}

// Retirement changes only accepted -> archived. Every other byte of the
// accepted receipt and the retained helper stays bound to the original owner.
func samePairedRetirementReceipt(opening, current selfupdatejournal.Receipt, helperSHA string) bool {
	accepted := opening
	accepted.Phase, accepted.Retired = "accepted", nil
	if current.Phase == "archived" {
		data, _ := json.Marshal(accepted)
		if current.Retired == nil || current.Retired.AcceptedSHA256 != digestBytes(data) || current.Retired.HelperSHA256 != helperSHA {
			return false
		}
	} else if current.Phase != "accepted" || current.Retired != nil {
		return false
	}
	current.Phase, current.Retired = "accepted", nil
	return reflect.DeepEqual(accepted, current)
}

func (p *completedPairedRetirement) current(ctx context.Context, id string) error {
	if p == nil || p.self != p || p.adapter == nil || p.original == nil || p.owner == nil || ctx == nil || ctx != p.original || id != p.record.Job.ID ||
		p.original.Err() != nil || ctx.Err() != nil {
		return ErrPairedRetirementOwner
	}
	if deadline, finite := p.original.Deadline(); !finite || !deadline.After(time.Now()) {
		return ErrPairedRetirementOwner
	}
	if err := p.owner(ctx, id); err != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	a := p.adapter
	if runtime.GOOS != "linux" || a.installation != "/opt" || a.directory != productionUpdateRoot || a.fileJournal != productionFileJournal || a.processInactive != nil || a.owned == nil || a.admission == nil {
		return ErrPairedRetirementOwner
	}
	for i, path := range []string{a.directory, filepath.Join(a.directory, id), a.fileJournal} {
		current, err := os.Lstat(path)
		if err != nil || p.roots[i] == nil || !os.SameFile(current, p.roots[i]) || a.owned(path) != nil {
			return errors.Join(ErrPairedRetirementOwner, err)
		}
	}
	record, review, err := a.loadBoundReview(ctx, id, true, true)
	current, currentErr := readAdapterRecord(a.directory, id)
	if err != nil || currentErr != nil || !reflect.DeepEqual(p.record, record) || !reflect.DeepEqual(record, current) || !reflect.DeepEqual(p.review, review) {
		return errors.Join(ErrPairedRetirementOwner, err, currentErr)
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	receipt, err := store.RetainedReceipt(ctx, id)
	store.Close()
	header, _ := json.Marshal(record)
	if err != nil || !samePairedRetirementReceipt(p.receipt, receipt, digestBytes(header)) || a.pairedSettledFormats(ctx, record, review, receipt) != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	job, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	command, err := readFileCommand(job, id, "start-candidate-panel")
	job.Close()
	if err != nil || command != p.command || validatePairedRetirementSource(record, review, receipt, command, p.workerPID) != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	if err := pairedRetirementExecutingApp(ctx, command.Runtime); err != nil {
		return err
	}
	return p.owner(ctx, id)
}

func pairedRetirementExecutingApp(ctx context.Context, expected fileProcess) error {
	if runtime.GOOS != "linux" || ctx == nil || ctx.Err() != nil || expected.PID != os.Getpid() {
		return ErrPairedRetirementOwner
	}
	path, err := os.Executable()
	if err != nil || path != "/opt/bin/razvilka" || checkRootOwnedPath(path) != nil {
		return ErrPairedRetirementOwner
	}
	if _, err := externalBootstrapProgramInfo(); err != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	actual, err := fileProcessAt(os.Getpid())
	if err != nil || actual != expected || checkProductionPID(actual.PID, path) != nil {
		return errors.Join(ErrPairedRetirementOwner, err)
	}
	root, err := ownedfs.Open(filepath.Dir(installpath.Run + "/razvilka.pid"))
	if err != nil {
		return err
	}
	data, err := root.ReadLimited("razvilka.pid", 32)
	root.Close()
	pid, pidErr := externalBootstrapPID(data)
	if err != nil || pidErr != nil || pid != actual.PID {
		return errors.Join(ErrPairedRetirementOwner, err, pidErr)
	}
	return ctx.Err()
}
