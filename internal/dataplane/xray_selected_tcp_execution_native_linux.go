//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func xraySelectedTCPNativeEnvironment() []string {
	return []string{"PATH=/opt/bin:/usr/bin:/bin", "HOME=/", "LANG=C", "LC_ALL=C", "TZ=UTC"}
}

type xraySelectedTCPVersionOutput struct {
	data     []byte
	overflow bool
}

func (w *xraySelectedTCPVersionOutput) Write(data []byte) (int, error) {
	if len(data) > 4096-len(w.data) {
		w.overflow = true
		return 0, errXraySelectedTCPRuntime
	}
	w.data = append(w.data, data...)
	return len(data), nil
}

// The only caller is the original concrete runtime publisher, after its whole
// policy preflight. Its resource mutex remains held through this bounded
// protocol. Neither a process DTO nor the resource definition is a launcher.
func (r *XraySelectedTCPExecutionResource) startOriginalNative(ctx context.Context) error {
	if r == nil || r.self != r || r.scope == nil || xraySelectedTCPFinite(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	r.scope.startMu.RLock()
	defer r.scope.startMu.RUnlock()
	r.observationMu.Lock()
	defer r.observationMu.Unlock()
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	bound, err := r.owner.context(c)
	if err != nil || r.descriptorsClosed || r.versionUsed || r.startUsed || r.child != nil || r.executable == nil || r.configCurrent(bound) != nil || r.executable.current(bound) != nil ||
		r.scope.networkIdentity == nil || r.scope.networkIdentity.provider == nil {
		return errors.Join(errXraySelectedTCPRuntime, err)
	}
	r.scope.mu.Lock()
	index, err := r.matching()
	if err == nil && r.scope.execution.Resources[index].Phase != "planned" {
		err = errXraySelectedTCPRuntime
	}
	if err == nil {
		r.scope.execution.Resources[index].Phase = "process-pending"
		r.versionUsed = true
		err = r.scope.persist() // Actual resource/config/intent predates every Start, including version.
	}
	r.scope.mu.Unlock()
	if err != nil {
		return err
	}
	if err := xraySelectedTCPObserveListenerAbsent(bound, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match.Listener); err != nil {
		return err
	}
	if err := xraySelectedTCPObserveConntrackSettled(bound, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match); err != nil {
		return err
	}
	if err := r.verifyOriginalNativeVersion(bound); err != nil {
		return err
	}
	if r.owner.checkHeld(bound, false) != nil || r.configCurrent(bound) != nil || r.executable.current(bound) != nil {
		return errXraySelectedTCPRuntime
	}
	if err := xraySelectedTCPObserveListenerAbsent(bound, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match.Listener); err != nil {
		return err
	}
	r.log, err = r.root.OpenFile(r.definition.Process.LogName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errXraySelectedTCPRuntime
	}
	info, err := r.log.Stat()
	if err != nil || !validNetworkPolicyReceiptFile(info) || r.root.Sync() != nil {
		return errXraySelectedTCPRuntime
	}
	cmd := &exec.Cmd{Path: "/proc/self/fd/3", Args: []string{r.executable.path, "run", "-config", "/proc/self/fd/4"}, Dir: r.rootPath,
		Env: xraySelectedTCPNativeEnvironment(), ExtraFiles: []*os.File{r.executable.file, r.config}, Stdout: r.log, Stderr: r.log, SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}
	p, err := reserveXraySelectedTCPProcessWait(bound, cmd)
	if err != nil {
		return err
	}
	r.child = p        // Retain original Wait reservation before actual syscall.
	r.startUsed = true // No replay, including post-syscall control refusal.
	startErr := r.material.control.WithStart(bound, cmd.Start)
	if cmd.Process == nil {
		r.startFailed = true // This actual syscall returned without a child ACK.
		r.child = nil
		return errors.Join(errXraySelectedTCPRuntime, startErr, p.abandonUnstartedWait())
	}
	r.startACK = true
	ackErr := p.acknowledgeStart()
	// Observe actual birth BEFORE this sole Wait can reap the PID. No native
	// reader timeout or lost Start ACK releases the retained child ownership.
	var birthErr error
	if ackErr == nil {
		read, closeRead, err := r.originalProcessReadContext(bound, false)
		if err == nil {
			observed, err := p.observe(read, r.scope.networkIdentity.provider, r.definition.NetworkIdentity)
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
		return errors.Join(errXraySelectedTCPRuntime, err)
	}
	if r.birth == nil || !os.SameFile(r.birth.executable, r.executable.info) || !os.SameFile(r.birth.config, r.configInfo) ||
		r.birth.configSHA256 != r.definition.ConfigSHA256 || r.birth.network != r.definition.NetworkIdentity || r.owner.checkHeld(bound, false) != nil {
		return errXraySelectedTCPRuntime
	}
	return nil
}

func (r *XraySelectedTCPExecutionResource) verifyOriginalNativeVersion(ctx context.Context) error {
	var stdout, stderr xraySelectedTCPVersionOutput
	cmd := &exec.Cmd{Path: "/proc/self/fd/3", Args: []string{r.executable.path, "version"}, Dir: r.rootPath, Env: xraySelectedTCPNativeEnvironment(),
		ExtraFiles: []*os.File{r.executable.file}, Stdout: &stdout, Stderr: &stderr, WaitDelay: 2 * time.Second, SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}
	p, err := reserveXraySelectedTCPProcessWait(ctx, cmd)
	if err != nil {
		return err
	}
	r.versionChild = p
	startErr := r.material.control.WithStart(ctx, cmd.Start)
	if cmd.Process == nil {
		r.versionChild = nil
		return errors.Join(errXraySelectedTCPRuntime, startErr, p.abandonUnstartedWait())
	}
	ackErr := p.acknowledgeStart()
	waitErr := p.beginReservedWait()
	joinErr := p.Joined(ctx)
	if joinErr != nil {
		// This is fresh finite compensation of the SAME still-held operation,
		// never extension of the forward request or a new native admission.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		bound, err := r.owner.cleanupContext(cleanup)
		if err == nil {
			err = p.child.Kill() // SAME actual unreaped Process; never a PID lookup.
			if errors.Is(err, os.ErrProcessDone) {
				err = nil
			}
			joinErr = errors.Join(joinErr, err, p.Joined(bound))
		} else {
			joinErr = errors.Join(joinErr, err)
		}
	}
	if err := errors.Join(startErr, ackErr, waitErr, joinErr); err != nil {
		return errors.Join(errXraySelectedTCPRuntime, err)
	}
	if p.waitErr != nil || p.state == nil || !p.state.Success() || stdout.overflow || stderr.overflow || len(stderr.data) != 0 || !xraySelectedTCPVersionStatement(stdout.data) ||
		r.executable.current(ctx) != nil || r.owner.checkHeld(ctx, false) != nil {
		return errXraySelectedTCPRuntime
	}
	r.versionVerified = true
	return nil
}

func xraySelectedTCPVersionStatement(data []byte) bool {
	if len(data) == 0 || len(data) > 4096 || data[len(data)-1] != '\n' || bytes.ContainsAny(data, "\x00\r") {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > 8 {
		return false
	}
	return strings.HasPrefix(lines[0], "Xray 26.3.27 (Xray, Penetrates Everything.) ") && len(lines[0]) > len("Xray 26.3.27 (Xray, Penetrates Everything.) ")
}
