//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Actual Start is one-shot, after the same scope authored both planned records.
// The sole Wait reservation is retained even if control is revoked after Start.
func (r *XrayDomainTCPExecutionResource) startOriginalNative(ctx context.Context) error {
	if r.startUsed || r.child != nil {
		return ErrXrayDomainTCPOriginal
	}
	if _, err := r.originalContext(ctx, false); err != nil {
		return err
	}
	if err := r.observeDomainListenerAbsent(ctx); err != nil {
		return err
	}
	if err := r.launchOriginalNative(ctx); err != nil {
		return err
	}
	deadline, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for {
		if err := r.listenerCurrent(deadline); err == nil {
			return r.phase("listener-ready", "prepared")
		}
		select {
		case <-r.child.done:
			return ErrXrayDomainTCPOriginal
		case <-deadline.Done():
			return errors.Join(ErrXrayDomainTCPOriginal, deadline.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (r *XrayDomainTCPExecutionResource) launchOriginalNative(ctx context.Context) error {
	r.scope.startMu.RLock()
	defer r.scope.startMu.RUnlock()
	if _, err := r.originalContextAlreadyHeld(ctx, false); err != nil {
		return err
	}
	if err := r.phase("process-pending", "prepared"); err != nil {
		return err
	}
	r.log, _ = r.root.OpenFile("xray-domain.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if r.log == nil {
		return ErrXrayDomainTCPOriginal
	}
	// FD4 has no filename extension. Xray's auto decoder otherwise refuses
	// before listener creation; the reviewed payload is always JSON.
	cmd := &exec.Cmd{Path: "/proc/self/fd/3", Args: []string{r.executable.path, "run", "-format", "json", "-config", "/proc/self/fd/4"}, Dir: r.rootPath, Env: xraySelectedTCPNativeEnvironment(), ExtraFiles: []*os.File{r.executable.file, r.config}, Stdout: r.log, Stderr: r.log, SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}
	p, err := reserveXraySelectedTCPProcessWait(ctx, cmd)
	if err != nil {
		return err
	}
	r.child = p
	r.startUsed = true
	startErr := r.material.control.WithStart(ctx, cmd.Start)
	if cmd.Process == nil {
		r.child = nil
		return errors.Join(ErrXrayDomainTCPOriginal, startErr, p.abandonUnstartedWait())
	}
	r.startACK = true
	ackErr := p.acknowledgeStart()
	var birthErr error
	if ackErr == nil {
		read, closeRead, err := r.originalProcessReadAlreadyHeld(ctx)
		if err == nil {
			observed, err := r.observeDomainProcess(read)
			if err == nil {
				r.birth = &observed
			}
			birthErr = err
			closeRead()
		} else {
			birthErr = err
		}
	}
	waitErr := p.beginReservedWait()
	if err := errors.Join(startErr, ackErr, birthErr, waitErr); err != nil {
		return err
	}
	if !r.originalFilesSame() {
		return ErrXrayDomainTCPOriginal
	}
	return nil
}

func (r *XrayDomainTCPExecutionResource) stopOriginalNative(ctx context.Context) error {
	if r.child == nil {
		if r.startUsed {
			return r.phase("removed", "removed")
		}
		return r.phase("unused", "unused")
	}
	if _, err := r.originalContext(ctx, true); err != nil {
		return err
	}
	p := r.child
	if p.commandCurrent() != nil || p.child == nil {
		return ErrXrayDomainTCPOriginal
	}
	select {
	case <-p.done:
	default:
		read, closeRead, err := r.originalProcessReadContext(ctx, true)
		if err != nil {
			return err
		}
		observed, observeErr := r.observeDomainProcess(read)
		closeRead()
		if observeErr != nil || r.birth == nil || !r.birth.same(observed) {
			return errors.Join(ErrXrayDomainTCPOriginal, observeErr)
		}
		if err := r.material.control.WithCleanupStart(ctx, r.material.cleanup, func() error {
			err := p.child.Signal(syscall.SIGTERM)
			if errors.Is(err, os.ErrProcessDone) {
				return nil
			}
			return err
		}); err != nil {
			return err
		}
	}
	if err := p.Joined(ctx); err != nil {
		return err
	}
	if err := r.observeDomainListenerAbsent(ctx); err != nil {
		return err
	}
	return r.phase("removed", "removed")
}
