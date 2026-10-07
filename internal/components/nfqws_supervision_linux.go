//go:build linux

package components

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	nfqwsCleanupGrace = 500 * time.Millisecond
	nfqwsPipeGrace    = 250 * time.Millisecond
	nfqwsWaitPoll     = 10 * time.Millisecond
)

// ReadNFQWSSupervisionIdentity is read-only and safe in the ordinary daemon.
// It does not enable subreaping; only RunNFQWSSupervision in a private helper
// changes that process-wide kernel property.
func ReadNFQWSSupervisionIdentity() (NFQWSSupervisionIdentity, error) {
	return ReadNFQWSSupervisionProcessIdentity(os.Getpid())
}

// ReadNFQWSSupervisionProcessIdentity captures a launched helper's exact birth
// without enabling subreaping. A failed read never proves process inactivity.
func ReadNFQWSSupervisionProcessIdentity(pid int) (NFQWSSupervisionIdentity, error) {
	var identity NFQWSSupervisionIdentity
	var err error
	if pid <= 1 {
		return identity, ErrNFQWSSupervisionUnknown
	}
	identity.PID = pid
	identity.BootID, err = bootIdentity()
	if err != nil {
		return identity, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	identity.Start, identity.Group, err = processBirth(identity.PID)
	if err != nil {
		return identity, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	return identity, nil
}

func nfqwsParentAlive(command NFQWSSupervisionCommand) error {
	if command.ParentPID == os.Getpid() || os.Getppid() != command.ParentPID {
		return ErrNFQWSSupervisionUnknown
	}
	start, _, err := processBirth(command.ParentPID)
	if err != nil || start != command.ParentStart {
		return errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	return nil
}

// RunNFQWSSupervision must run only in the dedicated setsid helper dispatched
// before daemon startup. Its sole wait owner reaps all adopted descendants,
// including detached sessions and clone children with a non-SIGCHLD signal.
// A terminal receipt requires Wait4 ECHILD; a /proc scan is cleanup only.
func RunNFQWSSupervision(ctx context.Context, command NFQWSSupervisionCommand, hooks NFQWSSupervisionHooks) (NFQWSSupervisionReceipt, error) {
	if err := validateNFQWSSupervision(ctx, command, hooks); err != nil {
		return NFQWSSupervisionReceipt{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, command.Deadline)
	defer cancel()
	return runNFQWSSupervision(ctx, command, hooks)
}

func RunNFQWSActiveSupervision(ctx context.Context, command NFQWSActiveSupervisionCommand, hooks NFQWSSupervisionHooks) (NFQWSSupervisionReceipt, error) {
	shape := command.shape()
	if err := validateNFQWSSupervisionShape(ctx, shape, hooks); err != nil {
		return NFQWSSupervisionReceipt{}, err
	}
	return runNFQWSSupervision(ctx, shape, hooks)
}

// Both explicitly selected modes retain this sole kernel wait owner.
func runNFQWSSupervision(ctx context.Context, command NFQWSSupervisionCommand, hooks NFQWSSupervisionHooks) (NFQWSSupervisionReceipt, error) {
	var receipt NFQWSSupervisionReceipt
	identity, err := ReadNFQWSSupervisionIdentity()
	if err != nil || identity.Group != identity.PID || identity.BootID != command.BootID {
		return receipt, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	session, _, sessionErr := syscall.RawSyscall(syscall.SYS_GETSID, 0, 0, 0)
	if sessionErr != 0 || int(session) != identity.PID {
		return receipt, ErrNFQWSSupervisionUnknown
	}
	if err := nfqwsParentAlive(command); err != nil {
		return receipt, err
	}
	if err := hooks.StopCheck(); err != nil {
		return receipt, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	if err := ProbePackageSupervision(); err != nil {
		return receipt, errors.Join(ErrNFQWSSupervisionUnavailable, err)
	}
	// A dedicated helper must start with no previous child ownership. Finding
	// any child here cannot be attributed to this approved invocation.
	var status syscall.WaitStatus
	for {
		pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil)
		if e == syscall.EINTR {
			continue
		}
		if e != syscall.ECHILD || pid > 0 {
			return receipt, errors.Join(ErrNFQWSSupervisionUnknown, e)
		}
		break
	}
	receipt = NFQWSSupervisionReceipt{State: "armed", BootID: identity.BootID, Start: identity.Start, CommandSHA256: command.CommandSHA256, PID: identity.PID, Group: identity.Group}
	if err := hooks.Armed(identity); err != nil {
		return receipt, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nfqwsFinishNotStarted(receipt, hooks, err)
	}
	defer read.Close()
	defer write.Close()
	var output boundedPackageLog
	copied := make(chan error, 1)
	go func() { _, e := io.Copy(&output, read); copied <- e }()
	cmd := exec.Command(command.Program, command.Args...)
	cmd.Stdout, cmd.Stderr = write, write
	cmd.Env = []string{"PATH=/opt/bin:/opt/sbin:/usr/bin:/bin", "LANG=C", "TZ=UTC"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var reason error
	if err := ctx.Err(); err != nil {
		reason = err
	} else if err := nfqwsParentAlive(command); err != nil {
		reason = err
	} else if err := hooks.StopCheck(); err != nil {
		reason = err
	}
	if reason == nil {
		called := false
		reason = hooks.StartAdmission(func() error {
			if called {
				return ErrNFQWSSupervisionUnknown
			}
			called = true
			return cmd.Start()
		})
		if !called || (reason == nil && cmd.Process == nil) {
			reason = errors.Join(reason, ErrNFQWSSupervisionUnknown)
		}
	}
	_ = write.Close()
	if cmd.Process == nil {
		if e := nfqwsJoinPipe(read, copied); e != nil {
			return receipt, errors.Join(ErrNFQWSSupervisionUnknown, reason, e)
		}
		receipt.Cancelled = ctx.Err() != nil || reason != nil
		return nfqwsFinishNotStarted(receipt, hooks, reason)
	}
	defer cmd.Process.Release()
	receipt.Started, receipt.ChildPID, receipt.State = true, cmd.Process.Pid, "running"
	if e := hooks.Started(receipt.ChildPID); e != nil {
		reason = errors.Join(reason, e)
	}
	cleanup := reason != nil
	var cleanupDeadline time.Time
	code := 125
	pipeDone := false
	var pipeErr error
	for {
		if e := ctx.Err(); e != nil {
			reason = errors.Join(reason, e)
			cleanup = true
		} else if e := nfqwsParentAlive(command); e != nil {
			reason = errors.Join(reason, e)
			cleanup = true
		} else if e := hooks.StopCheck(); e != nil {
			reason = errors.Join(reason, e)
			cleanup = true
		}
		if !pipeDone {
			select {
			case pipeErr = <-copied:
				pipeDone = true
				if pipeErr != nil {
					reason = errors.Join(reason, pipeErr)
					cleanup = true
				}
			default:
			}
		}
		if cleanup {
			if cleanupDeadline.IsZero() {
				cleanupDeadline = time.Now().Add(nfqwsCleanupGrace)
			}
			killSupervisorChildren(receipt.PID)
			if !time.Now().Before(cleanupDeadline) {
				return receipt, errors.Join(ErrNFQWSSupervisionUnknown, reason)
			}
		}
		pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil)
		if e == syscall.EINTR {
			continue
		}
		if e == syscall.ECHILD {
			if !receipt.DirectReaped {
				return receipt, errors.Join(ErrNFQWSSupervisionUnknown, reason)
			}
			receipt.WaitECHILD = true
			break
		}
		if e != nil {
			killSupervisorChildren(receipt.PID)
			return receipt, errors.Join(ErrNFQWSSupervisionUnknown, reason, e)
		}
		if pid > 0 {
			if !status.Exited() && !status.Signaled() {
				reason = errors.Join(reason, errors.New("NFQWS child reported nonterminal wait status"))
				cleanup = true
				continue
			}
			receipt.Reaped++
			if pid == receipt.ChildPID {
				receipt.DirectReaped = true
				if status.Exited() {
					code = status.ExitStatus()
				} else if status.Signaled() {
					code = 128 + int(status.Signal())
				}
			}
			continue
		}
		time.Sleep(nfqwsWaitPoll)
	}
	if !pipeDone {
		pipeErr = nfqwsJoinPipe(read, copied)
	}
	if pipeErr != nil {
		return receipt, errors.Join(ErrNFQWSSupervisionUnknown, reason, pipeErr)
	}
	// Recheck after pipe completion: cancellation can arrive after ECHILD but
	// before the terminal write. Forced cleanup must never become exit-zero.
	if e := ctx.Err(); e != nil {
		reason = errors.Join(reason, e)
		cleanup = true
	} else if e := nfqwsParentAlive(command); e != nil {
		reason = errors.Join(reason, e)
		cleanup = true
	} else if e := hooks.StopCheck(); e != nil {
		reason = errors.Join(reason, e)
		cleanup = true
	}
	if cleanup {
		code = 125
		receipt.Cancelled = true
	}
	receipt.State, receipt.ExitCode = "reaped", code
	if e := hooks.Result(receipt, output.data()); e != nil {
		return receipt, errors.Join(ErrNFQWSSupervisionUnknown, reason, e)
	}
	if code != 0 {
		return receipt, errors.Join(reason, fmt.Errorf("NFQWS command exit %d after all descendants reaped", code))
	}
	return receipt, nil
}

func nfqwsJoinPipe(read *os.File, copied <-chan error) error {
	timer := time.NewTimer(nfqwsPipeGrace)
	defer timer.Stop()
	select {
	case err := <-copied:
		return err
	case <-timer.C:
		_ = read.Close()
		return ErrNFQWSSupervisionUnknown
	}
}

func nfqwsFinishNotStarted(receipt NFQWSSupervisionReceipt, hooks NFQWSSupervisionHooks, cause error) (NFQWSSupervisionReceipt, error) {
	var status syscall.WaitStatus
	for {
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != syscall.ECHILD || pid > 0 {
			return receipt, errors.Join(ErrNFQWSSupervisionUnknown, cause, err)
		}
		break
	}
	receipt.State, receipt.WaitECHILD, receipt.ExitCode = "not-started", true, 125
	if err := hooks.Result(receipt, nil); err != nil {
		return receipt, errors.Join(ErrNFQWSSupervisionUnknown, cause, err)
	}
	return receipt, errors.Join(cause, errors.New("NFQWS command was not started"))
}
