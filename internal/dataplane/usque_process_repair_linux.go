//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func observeCommittedUSQUEProcessAbsence(ctx context.Context, spec ProcessSpec, port int, session committedUSQUESession) (deadCommittedUSQUEProcess, error) {
	var empty deadCommittedUSQUEProcess
	if ctx.Err() != nil || !filepath.IsAbs(spec.Dir) || filepath.Clean(spec.Dir) != spec.Dir || port < 1024 || port > 65535 {
		return empty, ErrUSQUELocalProcessUnconfirmed
	}
	root, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return empty, ErrUSQUELocalProcessUnconfirmed
	}
	defer root.Close()
	held, err := root.RootInfo()
	named, namedErr := os.Lstat(spec.Dir)
	boot, bootErr := readProxyInactiveProc("/proc/sys/kernel/random/boot_id", 128)
	if err != nil || namedErr != nil || bootErr != nil || !proxyInactivePrivateDirectory(named) || !os.SameFile(held, named) {
		return empty, ErrUSQUELocalProcessUnconfirmed
	}
	dead, err := committedUSQUEProcessRecord(root, spec, session, strings.TrimSpace(string(boot)))
	if err != nil || originalProcessPIDAbsent(dead.pid) != nil || originalProcessListenerAbsent(ctx, port) != nil || usqueOnlyEngineAbsent(ctx, spec) != nil {
		return empty, ErrUSQUELocalProcessUnconfirmed
	}
	current, err := committedUSQUEProcessRecord(root, spec, session, strings.TrimSpace(string(boot)))
	named, namedErr = os.Lstat(spec.Dir)
	if err != nil || namedErr != nil || !os.SameFile(held, named) || current.pid != dead.pid || !bytes.Equal(current.receipt, dead.receipt) ||
		originalProcessPIDAbsent(dead.pid) != nil || originalProcessListenerAbsent(ctx, port) != nil {
		return empty, ErrUSQUELocalProcessUnconfirmed
	}
	dead.root = held
	return dead, ctx.Err()
}

func (p deadCommittedUSQUEProcess) current(ctx context.Context, spec ProcessSpec, port int, session committedUSQUESession) error {
	fresh, err := observeCommittedUSQUEProcessAbsence(ctx, spec, port, session)
	if err != nil || p.root == nil || !os.SameFile(p.root, fresh.root) || p.pid != fresh.pid || !bytes.Equal(p.receipt, fresh.receipt) {
		return ErrUSQUELocalProcessUnconfirmed
	}
	return nil
}

func (p deadCommittedUSQUEProcess) currentAfterJoin(ctx context.Context, spec ProcessSpec, port int, session committedUSQUESession) error {
	if p.pid <= 1 || p.root == nil || p.boot == "" || ctx.Err() != nil || committedUSQUEArgsHash(spec) != session.argsSHA {
		return ErrUSQUELocalProcessUnconfirmed
	}
	root, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return ErrUSQUELocalProcessUnconfirmed
	}
	defer root.Close()
	held, err := root.RootInfo()
	if err != nil || !os.SameFile(held, p.root) {
		return ErrUSQUELocalProcessUnconfirmed
	}
	current := func() bool {
		named, err := os.Lstat(spec.Dir)
		boot, bootErr := readProxyInactiveProc("/proc/sys/kernel/random/boot_id", 128)
		_, pidErr := root.LstatChild("engine.pid")
		_, receiptErr := root.LstatChild("engine.pid" + routeidentity.ReceiptSuffix)
		return err == nil && os.SameFile(named, held) && proxyInactivePrivateDirectory(named) && bootErr == nil && strings.TrimSpace(string(boot)) == p.boot &&
			errors.Is(pidErr, os.ErrNotExist) && errors.Is(receiptErr, os.ErrNotExist) && originalProcessPIDAbsent(p.pid) == nil && originalProcessListenerAbsent(ctx, port) == nil
	}
	if !current() || usqueOnlyEngineAbsent(ctx, spec) != nil || !current() {
		return ErrUSQUELocalProcessUnconfirmed
	}
	return ctx.Err()
}

func usqueOnlyEngineAbsent(ctx context.Context, spec ProcessSpec) (result error) {
	self := os.Getpid()
	pass, err := openLinuxInactiveProc(ctx, "/proc", self)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, pass.Close()) }()
	entries, err := pass.Entries()
	if err != nil {
		return err
	}
	seenSelf, count := false, 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		count++
		if !entry.IsDir() || pid < 1 || count > 4096 {
			return ErrUSQUELocalProcessUnconfirmed
		}
		if pid == self {
			seenSelf = true
			continue
		}
		child, err := pass.OpenPID(pid)
		if err != nil {
			if inactiveProcOpenMissing(err) && pass.GoneBeforeOpen(pid) {
				continue
			}
			return err
		}
		if err := errors.Join(checkUSQUENotEngine(child, pid, spec), child.Close()); err != nil {
			return err
		}
	}
	if !seenSelf {
		return ErrUSQUELocalProcessUnconfirmed
	}
	return ctx.Err()
}

func checkUSQUENotEngine(child inactiveProcPID, pid int, spec ProcessSpec) error {
	stat, err := child.Stat()
	if inactiveProcRetireError(err) && child.Terminal() {
		return nil
	}
	state, flags, _, invalid := proxyInactiveProcStat(stat, pid)
	if err != nil || invalid != nil {
		return ErrUSQUELocalProcessUnconfirmed
	}
	if state == 'Z' && child.Terminal() || flags&0x00200000 != 0 {
		return nil
	}
	cmd, err := child.Command()
	defer clear(cmd)
	if inactiveProcRetireError(err) && child.Terminal() {
		return nil
	}
	args, valid := inactiveProcArguments(cmd)
	if err != nil || !valid {
		return ErrUSQUELocalProcessUnconfirmed
	}
	exe, err := child.Executable()
	if inactiveProcRetireError(err) && child.Terminal() {
		return nil
	}
	if err != nil || exe == "" || slices.Contains(args, spec.MatchArg) || filepath.Base(strings.TrimSuffix(exe, " (deleted)")) == filepath.Base(spec.Binary) ||
		filepath.Base(args[0]) == "usque" || filepath.Base(exe) == "usque" {
		return ErrUSQUELocalProcessUnconfirmed
	}
	err = child.Current()
	if inactiveProcRetireError(err) && child.Terminal() {
		return nil
	}
	return err
}
