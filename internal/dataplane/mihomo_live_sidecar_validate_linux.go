//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func (n *mihomoLiveSidecar) validate(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.self != n || n.owner == nil || n.closed || n.started || n.checkUsed || n.binary == nil || n.profile == nil {
		return errMihomoLiveMaterial
	}
	n.checkUsed = true
	if err := errors.Join(n.owner.currentBeforeStart(ctx), n.owner.compiledCurrent(true)); err != nil {
		return err
	}
	if n.owner.definition.Sidecar.Kind == "hev" {
		// HEV has no validation-only command. Its exact installed receipt, reviewed
		// version/config dialect and held image are required; actual Start/TUN and
		// mandatory service health still have to succeed before ACTIVE.
		if n.owner.proxy.hevInstalledCheck == nil {
			return errMihomoLiveMaterial
		}
		return n.owner.proxy.hevInstalledCheck(ctx)
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/proc/self/fd/3", "check", "-c", "/proc/self/fd/4")
	command.Args[0], command.Dir = n.spec.Binary, n.spec.Dir
	command.ExtraFiles = []*os.File{n.binary, n.profile}
	command.Env = []string{}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	started := false
	err := n.owner.control.WithStart(bounded, func() error {
		if err := command.Start(); err != nil {
			return err
		}
		started = true
		return nil
	})
	if started {
		if err != nil {
			cancel()
		}
		err = errors.Join(err, command.Wait())
	}
	if !started || err != nil {
		return errors.Join(errMihomoLiveMaterial, err, bounded.Err())
	}
	return errors.Join(n.owner.currentBeforeStart(ctx), n.owner.compiledCurrent(true))
}
