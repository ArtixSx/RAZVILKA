//go:build linux

package strategylab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const compatibilityHelperGrace = 750 * time.Millisecond

func compatibilityPrivateStateParent(path string) error {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&077 != 0 {
		return errors.New("compatibility state parent must be private")
	}
	return nil // Full ancestry and owner checks are a separate protected-path gate.
}

func compatibilityHelperExecutable() (string, error) {
	path, err := os.Executable()
	if err != nil || compatibilityProtectedPath(path, false) != nil {
		return "", ErrCompatibilityQuiescenceUnknown
	}
	current, err := os.Stat("/proc/self/exe")
	file, fileErr := os.Lstat(path)
	if err != nil || fileErr != nil || !os.SameFile(current, file) {
		return "", ErrCompatibilityQuiescenceUnknown
	}
	return path, nil
}

func compatibilityLaunchSupervisor(ctx context.Context, statePath string, review compatibilityReview, invocationID string, prefix []string) (identity components.NFQWSSupervisionIdentity, err error) {
	program, err := compatibilityHelperExecutable()
	if err != nil {
		return identity, err
	}
	if prefix == nil {
		prefix = []string{"nfqws-compatibility-supervisor"}
	}
	args := append(append([]string(nil), prefix...), invocationID)
	cmd := exec.Command(program, args...)
	cmd.Env = []string{"PATH=/opt/bin:/opt/sbin:/usr/bin:/bin", "LANG=C", "TZ=UTC", "RAZVILKA_STRATEGY_LAB_STATE=" + statePath, "RAZVILKA_SELF_UPDATE_CONTROL_STATE=" + review.ControlPath}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	phase := managedLaunchPhase(ctx, invocationID)
	started := false
	// Intent has been fsynced and its FileTarget lease released. Only Start
	// occurs under the common authority lock; Wait and receipt I/O follow it.
	err = operationgate.WithSelfUpdateEffectAdmission(ctx, review.ControlPath, invocationID, review.InstallationID, review.Sequence, "nfqws-compatibility-helper", func() error {
		startErr := cmd.Start()
		started = startErr == nil
		if phase != nil {
			phase.launched = started
		}
		return startErr
	})
	if !started {
		return identity, err
	}
	admissionErr := err
	identity, identityErr := components.ReadNFQWSSupervisionProcessIdentity(cmd.Process.Pid)
	if phase != nil {
		phase.helper = identity
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }() // Parent owns this one helper, never its descendants.
	joined := func(waitErr error) error {
		if phase != nil {
			phase.joined = true
		}
		return errors.Join(admissionErr, waitErr)
	}
	if admissionErr != nil || identityErr != nil || identity.Group != identity.PID {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		err = errors.Join(ErrCompatibilityQuiescenceUnknown, identityErr)
	} else {
		select {
		case err := <-done:
			return identity, errors.Join(joined(err), ctx.Err())
		case <-ctx.Done():
			_ = cmd.Process.Signal(syscall.SIGTERM)
			err = ctx.Err()
		}
	}
	timer := time.NewTimer(compatibilityHelperGrace)
	defer timer.Stop()
	select {
	case waitErr := <-done:
		return identity, errors.Join(err, joined(waitErr))
	case <-timer.C:
		if phase != nil {
			// Cancellation has already reached the exact owned helper. Keep the
			// original caller/lease until its one Wait really joins; the elapsed
			// grace period remains an unknown outcome, never synthetic ECHILD.
			waitErr := <-done
			return identity, errors.Join(err, joined(waitErr))
		}
		// Keep the exact helper's sole reap owner alive to finish cleanup. A
		// late terminal record remains unacknowledged and cannot permit replay.
		return identity, errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
}

// CORE calls this from its fixed early CLI dispatch, before daemon startup.
// invocationID is the only CLI value. Paths are trusted startup settings, not
// caller-selected paths; the frozen review must match the control setting.
func RunCompatibilitySupervisor(invocationID, statePath, controlPath string) int {
	if err := runCompatibilitySupervisor(invocationID, statePath, controlPath); err != nil {
		return 1
	}
	return 0
}

func runCompatibilitySupervisor(invocationID, statePath, controlPath string) error {
	// Signals are registered before even the first filesystem read or fsync.
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if !compatibilityHex(invocationID, 32) || !compatibilityCleanPath(statePath) || !compatibilityCleanPath(controlPath) || compatibilityProtectedPath(statePath, false) != nil || compatibilityPrivateStateParent(statePath) != nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	lease, err := openCompatibilityStateLease(signalCtx, statePath, invocationID)
	if err != nil {
		return err
	}
	defer lease.close()
	active := compatibilityActiveInvocation(lease.state.CompatibilitySession)
	command, hash := active.Command, active.CommandSHA256
	if command.Review.ControlPath != controlPath {
		return ErrCompatibilityQuiescenceUnknown
	}
	ctx, cancel := context.WithDeadline(signalCtx, command.Deadline)
	defer cancel()
	if compatibilityProtectedReview(statePath, command.Review) != nil || compatibilityFilesUnchanged(command.Review) != nil || compatibilityControlCurrent(ctx, command.Review) != nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	terminalPublished := false
	hooks := components.NFQWSSupervisionHooks{
		Armed: func(identity components.NFQWSSupervisionIdentity) error {
			active.Receipt = compatibilityReceipt{State: "armed", BootID: identity.BootID, Start: identity.Start, PID: identity.PID, Group: identity.Group, CommandSHA256: hash}
			return lease.publish(ctx)
		},
		Started: func(pid int) error {
			active.Receipt.State, active.Receipt.Started, active.Receipt.ChildPID = "running", true, pid
			return lease.publish(ctx)
		},
		StartAdmission: func(begin func() error) error {
			// Armed fsync may have taken time. Recheck immutable files just
			// before admission, outside the authority lock's Start callback.
			if err := compatibilityProtectedReview(statePath, command.Review); err != nil {
				return err
			}
			if err := compatibilityFilesUnchanged(command.Review); err != nil {
				return err
			}
			return operationgate.WithSelfUpdateEffectAdmission(ctx, controlPath, invocationID, command.Review.InstallationID, command.Review.Sequence, "nfqws-compatibility-child", begin)
		},
		StopCheck: func() error { return compatibilityControlCurrent(ctx, command.Review) },
		Result: func(receipt components.NFQWSSupervisionReceipt, output []byte) error {
			armed := active.Receipt
			if receipt.BootID != command.BootID || receipt.CommandSHA256 != hash || receipt.PID != armed.PID || receipt.Start != armed.Start || receipt.Group != armed.Group {
				return ErrCompatibilityQuiescenceUnknown
			}
			active.Receipt = compatibilityReceipt{State: receipt.State, BootID: receipt.BootID, Start: receipt.Start, CommandSHA256: receipt.CommandSHA256, PID: receipt.PID, Group: receipt.Group, ChildPID: receipt.ChildPID, Reaped: receipt.Reaped, ExitCode: receipt.ExitCode, WaitECHILD: receipt.WaitECHILD, DirectReaped: receipt.DirectReaped, Started: receipt.Started, Cancelled: receipt.Cancelled}
			active.Output = compatibilityDiagnostic(output)
			// A cancelled tree may still publish its inactivity proof. Only the
			// parent with a live original context can acknowledge this record.
			storeCtx, cancel := context.WithTimeout(context.Background(), compatibilityHelperGrace)
			defer cancel()
			if err := lease.publish(storeCtx); err != nil {
				return err
			}
			terminalPublished = true
			return nil
		},
	}
	receipt, runErr := components.RunNFQWSSupervision(ctx, components.NFQWSSupervisionCommand{Program: command.Review.Binary.Path, Args: append([]string(nil), command.Args...), BootID: command.BootID, ParentPID: command.ParentPID, ParentStart: command.ParentStart, CommandSHA256: hash, Deadline: command.Deadline}, hooks)
	if !terminalPublished || !receipt.WaitECHILD || (runErr != nil && receipt.ExitCode == 0 && !receipt.Cancelled) {
		return errors.Join(ErrCompatibilityQuiescenceUnknown, runErr)
	}
	// This means durable receipt publication, not compatibility PASS. The
	// parent separately checks the command's exit, cancellation and exact ACK.
	return nil
}
