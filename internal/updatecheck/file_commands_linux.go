//go:build linux

package updatecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func fileBoot() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(data))
	if err != nil || !fileBootPattern.MatchString(boot) {
		return "", ErrFileProtocol
	}
	return boot, nil
}

func fileBirth(pid int) (string, int, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return "", 0, ErrFileProtocol
	}
	end := strings.LastIndex(string(data), ")")
	if end < 0 {
		return "", 0, ErrFileProtocol
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 20 {
		return "", 0, ErrFileProtocol
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, err
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", 0, err
	}
	return fields[19], parent, nil
}

func fileProcessOf(pid int) (fileProcess, error) {
	var process fileProcess
	if pid <= 1 {
		return process, ErrFileProtocol
	}
	boot, err := fileBoot()
	if err != nil {
		return process, err
	}
	start, _, err := fileBirth(pid)
	if err != nil {
		return process, err
	}
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return process, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaximumBinaryBytes {
		return process, ErrFileProtocol
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return process, ErrFileProtocol
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, MaximumBinaryBytes+1))
	if err != nil || n > MaximumBinaryBytes {
		return process, ErrFileProtocol
	}
	after, _, err := fileBirth(pid)
	if err != nil || after != start {
		return process, ErrFileProtocol
	}
	return fileProcess{Boot: boot, PID: pid, Start: start, ExecutableSHA256: hex.EncodeToString(hash.Sum(nil)), Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func fileProcessMatches(process fileProcess) error {
	boot, err := fileBoot()
	if err != nil || boot != process.Boot {
		return ErrFileProtocol
	}
	start, _, err := fileBirth(process.PID)
	if err != nil || start != process.Start {
		return ErrFileProtocol
	}
	info, err := os.Stat("/proc/" + strconv.Itoa(process.PID) + "/exe")
	if err != nil {
		return ErrFileProtocol
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || process.Inode == 0 || uint64(stat.Dev) != process.Device || stat.Ino != process.Inode {
		return ErrFileProtocol
	}
	return nil
}
func fileHelperProcess() (fileProcess, error)    { return fileProcessOf(os.Getpid()) }
func fileProcessAt(pid int) (fileProcess, error) { return fileProcessOf(pid) }

func fileProcessInactive(ctx context.Context, process fileProcess) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validFileProcess(process) {
		return ErrFileProtocol
	}
	boot, err := fileBoot()
	if err != nil {
		return err
	}
	if boot != process.Boot {
		return ctx.Err()
	}
	birth, _, err := fileBirth(process.PID)
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if birth != process.Start {
		return ctx.Err()
	}
	return ErrFileProtocol
}

func fileCommandInactive(ctx context.Context, receipt fileCommandReceipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := fileBoot()
	if err != nil {
		return err
	}
	if !validFileProcess(receipt.Parent) {
		return ErrFileProtocol
	}
	if boot != receipt.Parent.Boot {
		return nil
	} // Inactivity only, never effect success.
	if (receipt.State == "reaped" || receipt.State == "not-started") && receipt.WaitECHILD {
		return nil
	}
	return ErrFileProtocol // Dead helper/empty proc/PGID cannot establish completion.
}

func (a *SelfUpdateFileAdapter) filePanelAbsent(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := os.Lstat(filepath.Join(a.installation, "razvilka/run/razvilka.pid"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return ErrFileProtocol
}

// The old panel predates the worker and cannot be its wait4 child. Its sealed
// boot/birth identity is checked independently of the stop hook's child tree.
// A missing PID file alone does not show that this exact prior panel stopped.
func (a *SelfUpdateFileAdapter) oldPanelInactive(ctx context.Context, id string) error {
	_, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return err
	}
	identity, err := a.helperIdentity(id, review)
	if err != nil {
		return err
	}
	boot, err := fileBoot()
	if err != nil {
		return err
	}
	if boot != identity.OldPanel.Boot {
		return ctx.Err()
	}
	start, _, err := fileBirth(identity.OldPanel.PID)
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if start != identity.OldPanel.Start {
		return ctx.Err()
	}
	return ErrFileProtocol
}

func fileCommandLease(root *ownedfs.Root, command string) (func(), error) {
	if !validFileCommand(command) {
		return nil, ErrFileProtocol
	}
	name := "." + command + ".lock"
	marker := "RAZVILKA self update command writer v2\n"
	file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = root.OpenFile(name, os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	}
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, ErrFileProtocol
	}
	keep := false
	defer func() {
		if !keep {
			file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrFileProtocol
	}
	current, err := root.Stat(name)
	if err != nil || !os.SameFile(info, current) {
		return nil, ErrFileProtocol
	}
	if created {
		if _, err := file.WriteString(marker); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
		if err := syncSelfUpdateDirectory(root); err != nil {
			return nil, err
		}
	} else {
		data, err := io.ReadAll(io.LimitReader(file, int64(len(marker))+1))
		if err != nil || string(data) != marker {
			return nil, ErrFileProtocol
		}
	}
	keep = true
	return func() { file.Close() }, nil
}

func (a *SelfUpdateFileAdapter) runFileCommand(ctx context.Context, id, command string) error {
	if !validFileCommand(command) {
		return ErrFileProtocol
	}
	record, review, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	helperIdentity, err := a.helperIdentity(id, review)
	if err != nil {
		return err
	}
	if err := a.AuthorityAction(ctx, id, review.Revision, fileCommandAuthorityForReview(review, command)); err != nil {
		return err
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Stat(command + ".process.json"); !errors.Is(err, os.ErrNotExist) {
		return ErrFileProtocol
	}
	if command == "quiesce-old-runtime" {
		if _, err := root.Stat(runtimeQuiesceDiagnosticFile); !errors.Is(err, os.ErrNotExist) {
			return ErrFileProtocol
		}
	}
	controller := filepath.Join(a.directory, id, "control.bin")
	hash, err := hashRegularFile(controller, MaximumBinaryBytes)
	if err != nil || hash != reviewedHelperSHA(review) {
		return ErrFileProtocol
	}
	parent, err := fileProcessOf(os.Getpid())
	if err != nil {
		return err
	}
	if parent.ExecutableSHA256 != reviewedHelperSHA(review) && parent.ExecutableSHA256 != strings.TrimPrefix(record.Job.Release.Binary.Digest, "sha256:") {
		return ErrFileProtocol
	}
	receipt := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: id, Command: command, State: "intent", Parent: parent}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(command+".process.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := syncSelfUpdateDirectory(root); err != nil {
		return err
	}
	worker := exec.Command(controller, "self-update-command-helper", id, command)
	worker.Env = commandEnvironment()
	worker.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.AuthorityAction(ctx, id, review.Revision, fileCommandAuthorityForReview(review, command)); err != nil {
		return err
	}
	var originalInstallerStarted func(fileProcess) (*ordinaryInstallerWait, error)
	if command == "quiesce-old-runtime" && ctx.Value(ordinaryInstallerJoinKey{}) != nil {
		originalInstallerStarted, err = a.prepareOriginalOrdinaryInstallerWait(ctx, id, worker, parent, record, review, helperIdentity)
		if err != nil {
			return err
		}
	}
	admissionErr := a.EffectAdmission(ctx, id, fileCommandAuthorityForReview(review, command), "command-worker-"+command, worker.Start)
	if worker.Process == nil {
		if admissionErr != nil {
			return admissionErr
		}
		return ErrFileProtocol
	}
	// Capture the exact kernel/executable identity before starting the sole
	// parent Wait. A receipt alone cannot establish which process we joined.
	supervisor, identityErr := fileProcessOf(worker.Process.Pid)
	if identityErr == nil && (supervisor.Boot != parent.Boot || supervisor.ExecutableSHA256 != reviewedHelperSHA(review)) {
		identityErr = ErrFileProtocol
	}
	var installerWait *ordinaryInstallerWait
	if originalInstallerStarted != nil && identityErr == nil {
		installerWait, identityErr = originalInstallerStarted(supervisor)
	}
	done := make(chan error, 1)
	joined := make(chan struct{})
	var supervisorWaitErr error
	go func() {
		supervisorWaitErr = worker.Wait()
		if installerWait != nil {
			installerWait.observeWait(supervisorWaitErr)
		}
		done <- supervisorWaitErr
		close(joined)
	}()
	if a.bootstrapCommandWait != nil {
		a.bootstrapCommandWait(command, func(c context.Context) error {
			select {
			case <-joined:
			case <-c.Done():
				return errors.Join(ErrFileCommandUnsettled, c.Err())
			}
			if supervisorWaitErr != nil {
				return errors.Join(ErrFileCommandUnsettled, supervisorWaitErr)
			}
			if identityErr != nil || !validFileProcess(supervisor) {
				return errors.Join(ErrFileCommandUnsettled, identityErr)
			}
			currentRoot, err := a.commandRoot(id)
			if err != nil {
				return errors.Join(ErrFileCommandUnsettled, err)
			}
			defer currentRoot.Close()
			r, err := readFileCommand(currentRoot, id, command)
			if err != nil || r.Parent != parent || r.Supervisor != supervisor {
				return errors.Join(ErrFileCommandUnsettled, err)
			}
			if r.State == "runtime-handed-off" && command == "start-candidate-panel" {
				return c.Err() // Actual supervisor Wait; live runtime deliberately handed off.
			}
			if (r.State != "reaped" && r.State != "not-started") || !r.WaitECHILD {
				return ErrFileCommandUnsettled
			}
			return c.Err()
		})
	}
	cleanup := func(cause error) error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return errors.Join(cause, settleFileCommandWorker(cleanupCtx, root, id, command, worker.Process, done, parent, supervisor, identityErr))
	}
	if admissionErr != nil || identityErr != nil {
		return cleanup(errors.Join(admissionErr, identityErr))
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return cleanup(ctx.Err())
		case waitErr := <-done:
			r, err := readFileCommand(root, id, command)
			if err != nil || r.Parent != parent || r.Supervisor != supervisor || !r.WaitECHILD || (r.State != "reaped" && r.State != "not-started") {
				return errors.Join(ctx.Err(), ErrFileProtocol, ErrFileCommandUnsettled, err)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if waitErr != nil || r.State != "reaped" || r.Cancelled || r.ExitCode != 0 {
				if command == "quiesce-old-runtime" && r.State == "reaped" && !r.Cancelled && r.ExitCode != 0 {
					return runtimeQuiesceCommandFailure(root, errors.Join(ErrFileProtocol, waitErr))
				}
				return ErrFileProtocol
			}
			if installerWait != nil {
				return installerWait.complete(ctx, r)
			}
			return nil
		case <-tick.C:
			r, err := readFileCommand(root, id, command)
			if err != nil {
				return cleanup(err)
			}
			if r.Parent != parent || (r.State != "intent" && r.Supervisor != supervisor) {
				return cleanup(ErrFileProtocol)
			}
			if r.State == "runtime-ready" {
				if fileProcessMatches(r.Supervisor) != nil || fileProcessMatches(r.Runtime) != nil {
					return cleanup(ErrFileProtocol)
				}
				if err := ctx.Err(); err != nil {
					return cleanup(err)
				}
				return nil
			}
		}
	}
}

// Process.Signal uses the exec-created process handle, never a receipt PID or
// process group. Keep the worker alive to reap its own adopted descendants;
// killing it on timeout would destroy that proof. The independent cleanup
// context bounds the join even when the caller's context has already expired.
func settleFileCommandWorker(ctx context.Context, root *ownedfs.Root, id, command string, process *os.Process, done <-chan error, parent, supervisor fileProcess, identityErr error) error {
	_ = process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-ctx.Done():
		return errors.Join(ErrFileCommandUnsettled, ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrFileCommandUnsettled, err)
	}
	r, err := readFileCommand(root, id, command)
	if deadlineErr := ctx.Err(); deadlineErr != nil {
		return errors.Join(ErrFileCommandUnsettled, deadlineErr, err)
	}
	if identityErr != nil || err != nil || !validFileProcess(supervisor) || r.Parent != parent || r.Supervisor != supervisor || !r.WaitECHILD || (r.State != "reaped" && r.State != "not-started") {
		return errors.Join(ErrFileCommandUnsettled, identityErr, err)
	}
	return nil
}

// Separate process only. The current/retained trusted controller dispatches
// this before server startup, with fixed roots and command enumeration.
func RunFileCommandHelper(id, command string) int {
	return RunFileCommandHelperWithStopGuard(id, command, nil)
}

func RunFileCommandHelperWithStopGuard(id, command string, stop SelfUpdateStopCheck) int {
	return RunFileCommandHelperWithAuthority(id, command, stop, nil)
}

func RunFileCommandHelperWithAuthority(id, command string, stop SelfUpdateStopCheck, admission SelfUpdateEffectAdmission, runtime ...SelfUpdateRuntimeObservation) int {
	if err := runFileCommandWorker(NewSelfUpdateFileAdapterWithAuthority(stop, admission, runtime...), id, command); err != nil {
		return 3
	}
	return 0
}

func runFileCommandWorker(a *SelfUpdateFileAdapter, id, command string) error {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	if a == nil || a.stopCheck == nil || a.admission == nil || a.runtimeInactive == nil || !validFileCommand(command) {
		return ErrFileProtocol
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	// Cancellation is armed before filesystem reads/fsync. A lost transient
	// signal or a durable Stop must not permit a delayed launch on slow flash.
	go func() {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-signals:
				cancel()
				return
			case <-tick.C:
				if a.checkFileCommandStop(ctx, id, command) != nil {
					cancel()
					return
				}
			}
		}
	}()
	record, review, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	if err := a.AuthorityAction(ctx, id, review.Revision, fileCommandAuthorityForReview(review, command)); err != nil {
		return err
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	release, err := fileCommandLease(root, command)
	if err != nil {
		return err
	}
	defer release()
	r, err := readFileCommand(root, id, command)
	if err != nil || r.State != "intent" || fileProcessMatches(r.Parent) != nil {
		return ErrFileProtocol
	}
	if err := components.ProbePackageSupervision(); err != nil {
		return err
	}
	r.Supervisor, err = fileProcessOf(os.Getpid())
	if err != nil || r.Supervisor.ExecutableSHA256 != reviewedHelperSHA(review) {
		return ErrFileProtocol
	}
	r.State = "armed"
	if err := writeFileCommand(root, r); err != nil {
		return err
	}
	spawned, settled := false, false
	defer func() {
		if spawned || settled {
			return
		}
		var status syscall.WaitStatus
		if _, e := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil); e != syscall.ECHILD {
			return
		}
		r.State = "not-started"
		r.WaitECHILD = true
		r.Cancelled = true
		r.ExitCode = 125
		_ = writeFileCommand(root, r)
	}()
	select {
	case <-signals:
		return ErrFileProtocol
	default:
	}
	if command == "prepare-private-state" || command == "restore-private-state" {
		if err := a.fileQuiescenceExcept(ctx, id, command); err != nil {
			return err
		}
		if err := a.filePanelAbsent(ctx); err != nil {
			return err
		}
		if err := a.oldPanelInactive(ctx, id); err != nil {
			return err
		}
		if command == "prepare-private-state" {
			err = a.preparePrivateSnapshot(ctx, id)
		} else {
			err = a.restorePrivateSnapshot(ctx, id)
		}
		operationErr := err
		var status syscall.WaitStatus
		if _, err := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil); err != syscall.ECHILD {
			return ErrFileProtocol
		}
		r.State = "reaped"
		r.WaitECHILD = true
		if operationErr != nil || ctx.Err() != nil {
			r.ExitCode = 125
			r.Cancelled = true
		}
		settled = true
		return errors.Join(operationErr, writeFileCommand(root, r))
	}
	init := filepath.Join(a.installation, "etc/init.d/S99razvilka")
	actual, err := hashRegularFile(init, 256<<10)
	if err != nil || (actual != review.OldInitSHA256 && actual != record.Files["scripts/S99razvilka"]) {
		return ErrFileProtocol
	}
	if command == "stop-old-panel" || command == "stop-candidate-panel" {
		if err := a.ownedPanelBeforeStop(id, review, command); err != nil {
			return err
		}
	}
	start := command == "start-candidate-panel" || command == "start-rollback-panel"
	if start {
		store, err := a.OpenFileJournal()
		if err != nil {
			return err
		}
		err = store.VerifyInstallation(ctx, id, command == "start-rollback-panel")
		store.Close()
		if err != nil {
			return err
		}
		if err := a.fileQuiescenceExcept(ctx, id, command); err != nil {
			return err
		}
		if err := a.filePanelAbsent(ctx); err != nil {
			return err
		}
		if command == "start-candidate-panel" {
			if err := a.verifyPrivateSnapshot(ctx, id); err != nil {
				return err
			}
		} else {
			if err := a.verifyPrivateRestore(ctx, id); err != nil {
				return err
			}
		}
	}
	args := []string{init, "stop"}
	if start {
		args[1] = "start"
	}
	program := "/bin/sh"
	if command == "quiesce-old-runtime" {
		program = filepath.Join(a.directory, id, "control.bin")
		args = []string{"self-update-runtime-quiesce", id, strconv.FormatUint(review.Revision, 10), strconv.Itoa(os.Getpid())}
	}
	cmd := exec.Command(program, args...)
	cmd.Env = commandEnvironment()
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	var diagnostic *fileQuiesceDiagnosticPipe
	if command == "quiesce-old-runtime" {
		diagnostic, err = newFileQuiesceDiagnosticPipe(cmd)
		if err != nil {
			return err
		}
		defer diagnostic.Close()
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if start {
		cmd.Env = append(cmd.Env, "RAZVILKA_SELF_UPDATE_JOB="+id, "RAZVILKA_SELF_UPDATE_HELPER_PID="+strconv.Itoa(os.Getpid()))
	}
	if err := a.AuthorityAction(ctx, id, review.Revision, fileCommandAuthorityForReview(review, command)); err != nil {
		return err
	}
	if err := a.EffectAdmission(ctx, id, fileCommandAuthorityForReview(review, command), "command-child-"+command, cmd.Start); err != nil {
		if cmd.Process == nil {
			return err
		}
		cancel()
	}
	spawned = true
	if diagnostic != nil {
		if err := diagnostic.started(); err != nil {
			cancel()
		}
	}
	r.DirectPID = cmd.Process.Pid
	r.State = "running"
	writeErr := writeFileCommand(root, r)
	launched := r
	code, seen, ready := 1, false, false
	nextStopCheck := time.Time{}
	cleanup := writeErr != nil
	for {
		select {
		case <-signals:
			cleanup = true
		default:
		}
		if ctx.Err() != nil {
			cleanup = true
		}
		if !cleanup && time.Now().After(nextStopCheck) {
			nextStopCheck = time.Now().Add(250 * time.Millisecond)
			if err := a.checkFileCommandStop(ctx, id, command); err != nil {
				cleanup = true
				cancel()
			}
		}
		if cleanup {
			killFileChildren(os.Getpid())
		}
		var status syscall.WaitStatus
		pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil)
		if e == syscall.EINTR {
			continue
		}
		if e == syscall.ECHILD {
			if !seen {
				return ErrFileProtocol
			}
			break
		}
		if e != nil {
			return e
		}
		if pid > 0 {
			r.Reaped++
			if pid == r.DirectPID {
				seen = true
				if status.Exited() {
					code = status.ExitStatus()
				} else {
					code = 128 + int(status.Signal())
				}
			}
			continue
		}
		if start && seen && !ready && !cleanup && (code == 0 || code == 75) {
			r.Runtime, err = a.ownedFileRuntime(id, r.Supervisor.PID, review, command == "start-rollback-panel")
			if err == nil {
				_, parent, e := fileBirth(r.Runtime.PID)
				if e != nil || parent != os.Getpid() {
					cleanup = true
					continue
				}
				if onlyFileRuntimeChild(os.Getpid(), r.Runtime) != nil {
					continue
				}
				r.State = "runtime-ready"
				if err := writeFileCommand(root, r); err != nil {
					cleanup = true
					continue
				}
				ready = true
			}
		}
		if ready && !cleanup {
			store, e := a.OpenFileJournal()
			if e != nil {
				cleanup = true
				continue
			}
			receipt, present, e := store.Current()
			store.Close()
			if e != nil {
				cleanup = true
				continue
			}
			if present && receipt.ID == id && !receipt.Pending() {
				if receipt.Phase == "rolled-back-stopped" {
					cleanup = true
					continue
				}
				if (receipt.Phase == "accepted" && command != "start-candidate-panel") || (receipt.Phase == "rolled-back" && command != "start-rollback-panel") {
					cleanup = true
					continue
				}
				if _, e := a.ownedFileRuntime(id, r.Supervisor.PID, review, command == "start-rollback-panel"); e != nil {
					cleanup = true
					continue
				}
				if onlyFileRuntimeChild(os.Getpid(), r.Runtime) != nil {
					continue
				}
				if a.checkStop(ctx, id, "start/live") != nil {
					cleanup = true
					continue
				}
				r.State = "runtime-handed-off"
				if e := writeFileCommand(root, r); e != nil {
					cleanup = true
					continue
				}
				if a.checkStop(ctx, id, "start/live") != nil {
					cleanup = true
					continue
				}
				_ = cmd.Process.Release()
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = cmd.Process.Release()
	var diagnosticErr error
	if diagnostic != nil {
		data, err := diagnostic.finish(ctx)
		diagnosticErr = err
		if err == nil && code != 0 && !cleanup {
			diagnosticErr = retainRuntimeQuiesceDiagnostic(root, data)
		}
	}
	if writeErr != nil {
		return writeErr
	}
	if cleanup {
		code = 125
		r.Cancelled = true
	}
	if code == 0 && command == "quiesce-old-runtime" {
		inactiveCtx := ctx
		releaseJoin := func() {}
		if review.Bootstrap == nil {
			// This point follows actual direct-child exit 0 and wait4 ECHILD.
			// Keep the original finite context and revoke the join after this
			// synchronous observation; a process receipt cannot mint it.
			inactiveCtx, releaseJoin = ordinaryJoinedQuiesceContext(a, ctx, launched, r.Reaped)
		}
		inactiveErr := ErrFileProtocol
		if a.runtimeInactive != nil {
			inactiveErr = a.runtimeInactive(inactiveCtx, id)
		}
		releaseJoin()
		if inactiveErr != nil {
			code = 125
			r.Cancelled = true
		}
	}
	r.State = "reaped"
	r.WaitECHILD = true
	r.ExitCode = code
	if err := writeFileCommand(root, r); err != nil {
		return err
	}
	if code != 0 {
		return errors.Join(fmt.Errorf("self update command completion %d", code), diagnosticErr)
	}
	return diagnosticErr
}

func (a *SelfUpdateFileAdapter) ownedPanelBeforeStop(id string, review fileReview, command string) error {
	var expected fileProcess
	if command == "stop-old-panel" {
		identity, err := a.helperIdentity(id, review)
		if err != nil {
			return err
		}
		expected = identity.OldPanel
	} else {
		root, err := a.commandRoot(id)
		if err != nil {
			return err
		}
		defer root.Close()
		receipt, err := readFileCommand(root, id, "start-candidate-panel")
		if err != nil || receipt.State != "runtime-ready" {
			return ErrFileProtocol
		}
		expected = receipt.Runtime
		actual, err := a.ownedFileRuntime(id, receipt.Supervisor.PID, review, false)
		if err != nil || actual != expected {
			return ErrFileProtocol
		}
	}
	data, err := os.ReadFile(filepath.Join(a.installation, "razvilka/run/razvilka.pid"))
	if err != nil || len(data) > 32 {
		return ErrFileProtocol
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid != expected.PID {
		return ErrFileProtocol
	}
	return fileProcessMatches(expected)
}

// This inventory limits the deliberate handoff to the one exact adopted
// application runtime. It is never used as an ECHILD/quiescence substitute.
func onlyFileRuntimeChild(parent int, runtime fileProcess) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	count := 0
	found := false
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid <= 1 {
			continue
		}
		count++
		if count > 4096 {
			return ErrFileProtocol
		}
		birth, ppid, e := fileBirth(pid)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if ppid != parent {
			continue
		}
		if pid != runtime.PID || birth != runtime.Start || fileProcessMatches(runtime) != nil {
			return ErrFileProtocol
		}
		found = true
	}
	if !found {
		return ErrFileProtocol
	}
	return nil
}

func killFileChildren(parent int) {
	entries, _ := os.ReadDir("/proc")
	read := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		read++
		if read > 4096 {
			break
		}
		birth, ppid, err := fileBirth(pid)
		if err != nil || ppid != parent {
			continue
		}
		after, ppid, e := fileBirth(pid)
		if e == nil && ppid == parent && birth == after {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func (a *SelfUpdateFileAdapter) ownedFileRuntime(id string, helper int, review fileReview, rollback bool) (fileProcess, error) {
	var runtime fileProcess
	data, err := os.ReadFile(filepath.Join(a.installation, "razvilka/run/razvilka.pid"))
	if err != nil {
		return runtime, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return runtime, err
	}
	runtime, err = fileProcessOf(pid)
	if err != nil {
		return runtime, err
	}
	wanted := review.OldExecutableSHA256
	if !rollback {
		for _, file := range review.Files {
			if file.Target == "bin/razvilka" {
				wanted = file.SHA256
			}
		}
	}
	if runtime.ExecutableSHA256 != wanted {
		return runtime, ErrFileProtocol
	}
	installed, err := os.Stat(filepath.Join(a.installation, "bin/razvilka"))
	if err != nil {
		return runtime, err
	}
	actual, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil || !os.SameFile(installed, actual) {
		return runtime, ErrFileProtocol
	}
	commandFile, err := os.Open("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return runtime, err
	}
	cmdline, err := io.ReadAll(io.LimitReader(commandFile, 8193))
	commandFile.Close()
	if err != nil || len(cmdline) > 8192 {
		return runtime, ErrFileProtocol
	}
	args := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
	jobCount, helperCount := 0, 0
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-self-update-job" {
			if args[i+1] != id {
				return runtime, ErrFileProtocol
			}
			jobCount++
		}
		if args[i] == "-self-update-helper-pid" {
			if args[i+1] != strconv.Itoa(helper) {
				return runtime, ErrFileProtocol
			}
			helperCount++
		}
	}
	if jobCount != 1 || helperCount != 1 {
		return runtime, ErrFileProtocol
	}
	return runtime, nil
}

func (a *SelfUpdateFileAdapter) fileStartup(ctx context.Context, id, pidText string) error {
	_, review, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	if _, err := a.helperIdentity(id, review); err != nil {
		return err
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	current, present, err := store.Current()
	store.Close()
	if err != nil || !present || current.ID != id || (current.Phase != "command-started" && current.Phase != "command-finished") {
		return ErrFileProtocol
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 1 {
		return ErrFileProtocol
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, command := range []string{"start-candidate-panel", "start-rollback-panel"} {
		if current.Command != command {
			continue
		}
		r, err := readFileCommand(root, id, command)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if r.Supervisor.PID != pid {
			continue
		}
		if (r.State != "running" && r.State != "runtime-ready") || fileProcessMatches(r.Supervisor) != nil {
			return ErrFileProtocol
		}
		runtime, err := a.ownedFileRuntime(id, pid, review, command == "start-rollback-panel")
		if err != nil {
			return err
		}
		adopted := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			if err := a.checkStop(ctx, id, "start/live"); err != nil {
				return err
			}
			birth, parent, e := fileBirth(runtime.PID)
			if e != nil || birth != runtime.Start || fileProcessMatches(r.Supervisor) != nil {
				return ErrFileProtocol
			}
			if parent == pid {
				adopted = true
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		if !adopted {
			return ErrFileProtocol
		}
		return ctx.Err()
	}
	return ErrFileProtocol
}

// CORE's fixed early quiesce CLI calls this before opening live Stores or
// invoking owned runtime deactivation. The child can start before its parent
// has published DirectPID; wait briefly for that exact durable publication.
func (a *SelfUpdateFileAdapter) RuntimeQuiesceAuthority(ctx context.Context, id string, revision uint64, workerPID int) error {
	if workerPID <= 1 {
		return ErrFileProtocol
	}
	_, review, err := a.loadHeader(ctx, id)
	if err != nil || revision != review.Revision {
		return errors.Join(ErrFileProtocol, err)
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := a.oldPanelInactive(ctx, id); err != nil {
		return err
	}
	snapshot, err := a.privateSnapshot(ctx, id)
	if err != nil || snapshot.Schema != 2 {
		return errors.Join(ErrFileProtocol, err)
	}
	for _, command := range []string{"stop-old-panel", "prepare-private-state"} {
		r, err := readFileCommand(root, id, command)
		if err != nil || fileCommandInactive(ctx, r) != nil {
			return errors.Join(ErrFileProtocol, err)
		}
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if err := a.AuthorityAction(ctx, id, revision, fileCommandAuthorityForReview(review, "quiesce-old-runtime")); err != nil {
			return err
		}
		store, err := a.OpenFileJournal()
		if err != nil {
			return err
		}
		current, present, err := store.Current()
		store.Close()
		if err != nil || !present || current.ID != id || current.Phase != "command-started" || !current.BeforeFiles || current.Command != "quiesce-old-runtime" {
			return errors.Join(ErrFileProtocol, err)
		}
		r, err := readFileCommand(root, id, "quiesce-old-runtime")
		if err != nil || r.Supervisor.PID != workerPID || (r.State != "armed" && r.State != "running") || fileProcessMatches(r.Supervisor) != nil {
			return errors.Join(ErrFileProtocol, err)
		}
		if r.State == "running" {
			self, err := fileProcessOf(os.Getpid())
			_, parent, birthErr := fileBirth(os.Getpid())
			if err != nil || birthErr != nil || r.DirectPID != self.PID || parent != workerPID || self.Boot != r.Supervisor.Boot || self.ExecutableSHA256 != reviewedHelperSHA(review) {
				return ErrFileProtocol
			}
			return a.AuthorityAction(ctx, id, revision, fileCommandAuthorityForReview(review, "quiesce-old-runtime"))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return ErrFileProtocol
}

func (a *SelfUpdateFileAdapter) liveFileRuntime(ctx context.Context, id string, rollback bool) error {
	_, review, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	if _, err := a.helperIdentity(id, review); err != nil {
		return err
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	command := "start-candidate-panel"
	version := review.NewVersion
	if rollback {
		command = "start-rollback-panel"
		version = review.OldVersion
	}
	r, err := readFileCommand(root, id, command)
	if err != nil || (r.State != "runtime-ready" && r.State != "runtime-handed-off") {
		return ErrFileProtocol
	}
	actual, err := a.ownedFileRuntime(id, r.Supervisor.PID, review, rollback)
	if err != nil || actual != r.Runtime {
		return ErrFileProtocol
	}
	if r.State == "runtime-ready" && fileProcessMatches(r.Supervisor) != nil {
		return ErrFileProtocol
	}
	if r.State == "runtime-handed-off" {
		store, e := a.OpenFileJournal()
		if e != nil {
			return e
		}
		terminal, present, e := store.Current()
		store.Close()
		if e != nil || !present || terminal.ID != id || terminal.Rollback != rollback || (rollback && terminal.Phase != "rolled-back") || (!rollback && terminal.Phase != "accepted") {
			return ErrFileProtocol
		}
	}
	if err := a.confirmFileLiveHealth(ctx, review, actual, version); err != nil {
		return err
	}
	after, err := a.ownedFileRuntime(id, r.Supervisor.PID, review, rollback)
	if err != nil || after != actual {
		return ErrFileProtocol
	}
	return ctx.Err()
}

func (a *SelfUpdateFileAdapter) fileQuiescenceExcept(ctx context.Context, id, skip string) error {
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel"} {
		if command == skip {
			continue
		}
		r, err := readFileCommand(root, id, command)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := fileCommandInactive(ctx, r); err != nil {
			return err
		}
	}
	return ctx.Err()
}
