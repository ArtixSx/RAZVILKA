//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
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

func candidateStopIntent(r selfupdatejournal.Receipt, id string) bool {
	return r.Schema == selfupdatejournal.Schema && r.ID == id && r.Phase == "command-started" && r.Command == "stop-candidate-panel" && r.Index == 6 && !r.Rollback && !r.BeforeFiles &&
		slices.Equal(r.Commands, []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel"})
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
	return true, err
}
