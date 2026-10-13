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
	"syscall"
	"time"
)

func (a *SelfUpdateFileAdapter) prepareCandidateStartWait(ctx context.Context, id string, worker *exec.Cmd, parent fileProcess, record updateRecord, review fileReview, identity fileHelperIdentity) (func(fileProcess) (*candidateStartWait, error), error) {
	o, err := ordinaryInstallerOwner(ctx, a, id)
	if err != nil {
		return nil, err
	}
	if ctx != o.held || !productionOrdinaryRoleAdapter(a) || review.Bootstrap != nil || review.ID != id || identity.Process != parent || worker == nil || worker.Process != nil || worker.Path != filepath.Join(a.directory, id, "control.bin") || len(worker.Args) != 4 || worker.Args[1] != "self-update-command-helper" || worker.Args[2] != id || worker.Args[3] != "start-candidate-panel" {
		return nil, o.poison(nil)
	}
	fact, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil || ordinaryInstallerIdentityRole(review, record, identity, fact) != "ordinary-installer" {
		return nil, o.poison(err)
	}
	return func(supervisor fileProcess) (*candidateStartWait, error) {
		birth, ppid, err := fileBirth(supervisor.PID)
		if err != nil || birth != supervisor.Start || ppid != parent.PID {
			return nil, o.poison(err)
		}
		w, err := beginCandidateStartWait(ctx, a, id, worker, parent, supervisor)
		if err == nil {
			w.mu.Lock()
			w.record, w.review, w.identity = record, review, identity
			w.mu.Unlock()
		}
		return w, err
	}, nil
}

func candidatePIDMetadata(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return ErrFileProtocol
	}
	return nil
}

func (w *candidateStartWait) captureReady(ctx context.Context, ready fileCommandReceipt) error {
	w.mu.Lock()
	err := w.current(ctx)
	expectedRecord, expectedReview := w.record, w.review
	w.mu.Unlock()
	if err != nil {
		return err
	}
	a := w.owner.adapter
	if err := a.owned(filepath.Join(a.installation, "razvilka/run")); err != nil {
		return err
	}
	p, err := captureCandidatePID(filepath.Join(a.installation, "razvilka/run"), ready.Runtime.PID, syscall.O_NOFOLLOW)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			p.close()
		}
	}()
	if err := candidatePIDMetadata(p.info); err != nil {
		return err
	}
	record, review, err := a.load(ctx, w.owner.id)
	if err != nil || !reflect.DeepEqual(record, expectedRecord) || !reflect.DeepEqual(review, expectedReview) {
		return errors.Join(ErrFileProtocol, err)
	}
	actual, err := a.ownedFileRuntime(w.owner.id, w.supervisor.PID, review, false)
	if err != nil || actual != ready.Runtime {
		return errors.Join(ErrFileProtocol, err)
	}
	root, err := a.commandRoot(w.owner.id)
	if err != nil {
		return err
	}
	defer root.Close()
	current, err := readFileCommand(root, w.owner.id, "start-candidate-panel")
	if err != nil || current != ready || fileProcessMatches(w.supervisor) != nil {
		return errors.Join(ErrFileProtocol, err)
	}
	if err := w.rememberReady(ctx, ready, p); err != nil {
		return err
	}
	keep = true
	return nil
}

func candidateProcessesAbsent(ctx context.Context, ready fileCommandReceipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := fileBoot()
	if err != nil || boot != ready.Parent.Boot || ready.Supervisor.Boot != boot || ready.Runtime.Boot != boot {
		return errors.Join(ErrFileProtocol, err)
	}
	for _, pid := range []int{ready.Supervisor.PID, ready.DirectPID, ready.Runtime.PID} {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrFileProtocol, err)
		}
	}
	return ctx.Err()
}

func candidatePIDOwnership(pid *candidatePIDImage) error {
	exists, err := pid.observe()
	if err != nil {
		return err
	}
	info, err := pid.file.Stat()
	if err != nil {
		return err
	}
	actual, ok := info.Sys().(*syscall.Stat_t)
	original, originalOK := pid.info.Sys().(*syscall.Stat_t)
	links := uint64(0)
	if exists {
		links = 1
	}
	if !ok || !originalOK || actual.Uid != original.Uid || actual.Gid != original.Gid || actual.Uid != 0 || uint64(actual.Nlink) != links {
		return ErrFileProtocol
	}
	return nil
}

func removeCandidatePID(pid *candidatePIDImage) error {
	if err := pid.root.Remove("razvilka.pid"); err != nil {
		return err
	}
	directory, err := pid.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (a *SelfUpdateFileAdapter) cleanupAbsentCandidate(ctx context.Context, id string, record updateRecord, review fileReview, identity fileHelperIdentity) (bool, error) {
	if ctx.Value(ordinaryInstallerJoinKey{}) == nil || review.Bootstrap != nil {
		return false, nil
	}
	o, err := ordinaryInstallerOwner(ctx, a, id)
	if err != nil {
		return true, err
	}
	o.mu.Lock()
	w := o.candidate
	o.mu.Unlock()
	if w == nil {
		return false, nil
	}
	w.mu.Lock()
	sourceErr := w.current(ctx)
	expectedRecord, expectedReview, expectedIdentity := w.record, w.review, w.identity
	w.mu.Unlock()
	if sourceErr != nil {
		return true, sourceErr
	}
	if !productionOrdinaryRoleAdapter(a) || !reflect.DeepEqual(record, expectedRecord) || !reflect.DeepEqual(review, expectedReview) || identity != expectedIdentity {
		return true, ErrFileProtocol
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return true, err
	}
	defer root.Close()
	start, err := readFileCommand(root, id, "start-candidate-panel")
	if err != nil {
		return true, err
	}
	if start.State == "runtime-ready" {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(start.Runtime.PID))); err == nil {
			return false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return true, err
		}
	} else if start.State != "reaped" {
		return true, ErrFileCommandUnsettled
	}
	// Join through the original Wait channel, not by polling a dead PID.
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case <-w.joined:
	case <-ctx.Done():
		return true, errors.Join(ErrFileCommandUnsettled, ctx.Err())
	case <-timer.C:
		return true, ErrFileCommandUnsettled
	}
	final, err := readFileCommand(root, id, "start-candidate-panel")
	if err != nil {
		return true, err
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return true, err
	}
	defer store.Close()
	intent, present, err := store.Current()
	if err != nil || !present || !candidateStopIntent(intent, id) {
		return true, errors.Join(ErrFileProtocol, err)
	}
	check := func() error {
		if err := w.current(ctx); err != nil {
			return err
		}
		if !productionOrdinaryRoleAdapter(a) {
			return ErrFileProtocol
		}
		if err := a.AuthorityAction(ctx, id, review.Revision, "stop-owned"); err != nil {
			return err
		}
		freshRecord, freshReview, err := a.load(ctx, id)
		if err != nil || !reflect.DeepEqual(freshRecord, record) || !reflect.DeepEqual(freshReview, review) {
			return errors.Join(ErrFileProtocol, err)
		}
		freshIdentity, err := a.helperIdentity(id, review)
		if err != nil || freshIdentity != identity {
			return errors.Join(ErrFileProtocol, err)
		}
		fact, err := bootstrapControllerAt(ctx, os.Getpid())
		if err != nil || ordinaryInstallerIdentityRole(review, record, identity, fact) != "ordinary-installer" {
			return errors.Join(ErrFileProtocol, err)
		}
		current, present, err := store.Current()
		if err != nil || !present || !reflect.DeepEqual(current, intent) {
			return errors.Join(ErrFileProtocol, err)
		}
		actual, err := readFileCommand(root, id, "start-candidate-panel")
		if err != nil || actual != final {
			return errors.Join(ErrFileProtocol, err)
		}
		if err := a.owned(w.pid.directory); err != nil {
			return err
		}
		if err := candidatePIDMetadata(w.pid.info); err != nil {
			return err
		}
		if err := candidatePIDOwnership(w.pid); err != nil {
			return err
		}
		return candidateProcessesAbsent(ctx, w.ready)
	}
	err = executeCandidateCleanup(ctx, w, final, check, func(begin func() error) error {
		return a.EffectAdmission(ctx, id, "stop-owned", candidateKnownAbsentPIDEffect, begin)
	}, removeCandidatePID)
	if err == nil {
		err = a.filePanelAbsent(ctx)
	}
	if err == nil {
		err = sealCandidateAbsenceCompletion(ctx, w, final, intent, a.candidateStoppedCompletionFresh, a.candidateStoppedCompletionObservation)
	}
	return true, err
}

// Called with the original source's mutex held. The terminal helper record
// may change only through the existing data-only publication; its immutable
// identity/review/release fields remain exactly those authenticated by H.
func (a *SelfUpdateFileAdapter) candidateStoppedCompletionFresh(ctx context.Context, c *candidateAbsenceCompletion) error {
	if !productionOrdinaryRoleAdapter(a) {
		return ErrFileProtocol
	}
	return a.candidateStoppedCompletionFacts(ctx, c)
}

// Intrinsic facts are separately exercised by the bounded native fixture.
// Production always enters through the fixed-root check above.
func (a *SelfUpdateFileAdapter) candidateStoppedCompletionFacts(ctx context.Context, c *candidateAbsenceCompletion) error {
	w := c.wait
	if a.stopCheck == nil {
		return ErrFileProtocol
	}
	stopped, err := a.stopCheck(ctx, w.owner.id)
	if err != nil || !stopped {
		return errors.Join(ErrFileProtocol, err)
	}
	if err := a.AuthorityAction(ctx, w.owner.id, w.review.Revision, "replace-to-rollback"); err != nil {
		return err
	}
	record, review, err := a.load(ctx, w.owner.id)
	if err != nil || !reflect.DeepEqual(review, w.review) {
		return errors.Join(ErrFileProtocol, err)
	}
	if record.Job.State == stoppedRollbackState {
		if record.Job.Stage != stoppedRollbackState || record.Job.Code != "" || record.Job.Message != "Данные приложения восстановлены. Приложение остановлено." || record.Job.UpdatedAt.Before(w.record.Job.UpdatedAt) {
			return ErrFileProtocol
		}
		record.Job.State, record.Job.Stage, record.Job.Code, record.Job.Message, record.Job.UpdatedAt = w.record.Job.State, w.record.Job.Stage, w.record.Job.Code, w.record.Job.Message, w.record.Job.UpdatedAt
	}
	if !reflect.DeepEqual(record, w.record) {
		return ErrFileProtocol
	}
	identity, err := a.helperIdentity(w.owner.id, review)
	if err != nil || identity != w.identity {
		return errors.Join(ErrFileProtocol, err)
	}
	fact, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil || ordinaryInstallerIdentityRole(w.review, w.record, w.identity, fact) != "ordinary-installer" {
		return errors.Join(ErrFileProtocol, err)
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	current, present, err := store.Current()
	store.Close()
	if err != nil || !present {
		return errors.Join(ErrFileProtocol, err)
	}
	if err := c.receipt(current); err != nil {
		return err
	}
	root, err := a.commandRoot(w.owner.id)
	if err != nil {
		return err
	}
	actual, err := readFileCommand(root, w.owner.id, "start-candidate-panel")
	root.Close()
	if err != nil || actual != c.final {
		return errors.Join(ErrFileProtocol, err)
	}
	quiesce, err := w.owner.joined(ctx, a, w.owner.id, os.Getpid())
	if err != nil {
		return err
	}
	if err := ordinaryJoinedProcessesAbsent(ctx, quiesce); err != nil {
		return err
	}
	if err := a.oldPanelInactive(ctx, w.owner.id); err != nil {
		return err
	}
	if err := a.filePanelAbsent(ctx); err != nil {
		return err
	}
	if err := candidatePIDOwnership(w.pid); err != nil {
		return err
	}
	return candidateProcessesAbsent(ctx, w.ready)
}

func (a *SelfUpdateFileAdapter) candidateStoppedCompletionObservation(ctx context.Context, c *candidateAbsenceCompletion, use func(context.Context, *OrdinaryInstallerControllerObservation) error) (result error) {
	if err := c.current(ctx, a, c.wait.owner.id); err != nil {
		return err
	}
	w := c.wait
	command, err := w.owner.joined(ctx, a, w.owner.id, os.Getpid())
	if err != nil {
		return err
	}
	image, err := newOrdinaryExecutableImage(ctx, w.review.OldExecutableSHA256)
	if err != nil {
		return err
	}
	// Classification uses the original authenticated H snapshot. Fresh checks
	// below validate the actual Stop/restored/terminal state on every bookend.
	source := ordinaryObservationSource{review: w.review, record: w.record, identity: w.identity, command: command, caller: os.Getpid(), installerJoin: w.owner,
		read: image.controllerAt, check: func(cctx context.Context, _ bool) error {
			s, err := candidateStoppedReadFor(cctx, a, w.owner.id)
			if err != nil || s.completion != c {
				return errors.Join(ErrFileCommandUnsettled, err)
			}
			return nil
		}, clear: image.clear}
	return runOrdinaryControllerObservation(ctx, source, use)
}
