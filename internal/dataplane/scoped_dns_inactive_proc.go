package dataplane

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DNS serves in the controller process. Other controller incarnations cannot
// be cleared by this process's lifecycle accounting, even with a missing owner.
func scopedDNSInactiveProc(ctx context.Context, p scopedDNSInactiveProof, root, settings string, ports map[uint16]bool) error {
	netRoot := p.netRoot
	if p.threadNetRoot != nil {
		netRoot = p.threadNetRoot()
	}
	if p.readlink == nil || p.sameExecutable == nil || p.selfPID < 1 || !scopedDNSInactivePath(netRoot) {
		return ErrScopedDNSRuntimeInactive
	}
	selfExe, err := p.readlink(filepath.Join(p.procRoot, strconv.Itoa(p.selfPID), "exe"))
	if err != nil || selfExe == "" {
		return ErrScopedDNSRuntimeInactive
	}
	selfName := filepath.Base(strings.TrimSuffix(selfExe, " (deleted)"))
	dir, err := os.Open(p.procRoot)
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(8193)
	_ = dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) == 0 || len(entries) > 8192 {
		return ErrScopedDNSRuntimeInactive
	}
	self, count, size := false, 0, 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if pid < 1 || strconv.Itoa(pid) != entry.Name() || !entry.IsDir() || count >= 4096 {
			return ErrScopedDNSRuntimeInactive
		}
		count++
		path := filepath.Join(p.procRoot, entry.Name())
		gone := func(err error) bool {
			return pid != p.selfPID && errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path)
		}
		stat, err := readProxyInactiveProc(filepath.Join(path, "stat"), 16<<10)
		if gone(err) {
			continue
		}
		if err != nil {
			return err
		}
		state, flags, ticks, err := proxyInactiveProcStat(stat, pid)
		if err != nil {
			return err
		}
		if state == 'Z' || state == 'X' || state == 'x' {
			if pid == p.selfPID {
				return ErrScopedDNSRuntimeInactive
			}
			continue
		}
		cmd, err := readProxyInactiveProc(filepath.Join(path, "cmdline"), 64<<10)
		if gone(err) {
			continue
		}
		if err != nil {
			return err
		}
		size += len(cmd)
		if size > 4<<20 {
			return ErrScopedDNSRuntimeInactive
		}
		exeBefore := ""
		if len(cmd) == 0 {
			if flags&0x00200000 == 0 || pid == p.selfPID {
				return ErrScopedDNSRuntimeInactive
			}
		} else {
			if cmd[len(cmd)-1] != 0 {
				return ErrScopedDNSRuntimeInactive
			}
			args := strings.Split(string(cmd[:len(cmd)-1]), "\x00")
			if len(args) > 256 || args[0] == "" {
				return ErrScopedDNSRuntimeInactive
			}
			exe, err := p.readlink(filepath.Join(path, "exe"))
			if gone(err) {
				clear(cmd)
				continue
			}
			if err != nil || exe == "" || len(exe) > 4096 || strings.ContainsRune(exe, '\x00') {
				return ErrScopedDNSRuntimeInactive
			}
			exeBefore = exe
			if pid != p.selfPID {
				// Detect a renamed/hard-linked copy of this controller as well as
				// named older images. /proc/exe remains inspectable after deletion.
				same, err := p.sameExecutable(filepath.Join(p.procRoot, strconv.Itoa(p.selfPID), "exe"), filepath.Join(path, "exe"))
				if gone(err) {
					clear(cmd)
					continue
				}
				if err != nil || same {
					return ErrScopedDNSRuntimeInactive
				}
				for _, name := range []string{filepath.Base(strings.TrimSuffix(exe, " (deleted)")), filepath.Base(args[0])} {
					if strings.EqualFold(name, selfName) || strings.EqualFold(name, "razvilka") || strings.EqualFold(name, "razvilka.exe") {
						return ErrScopedDNSRuntimeInactive
					}
				}
				for _, arg := range args {
					if arg == settings || arg == root || arg == filepath.Dir(root) || strings.TrimPrefix(arg, "--dns-state=") == settings || strings.TrimPrefix(arg, "--dataplane-state=") == filepath.Dir(root) {
						return ErrScopedDNSRuntimeInactive
					}
				}
			}
		}
		if len(cmd) > 0 {
			// PID start ticks do not change on exec. A second argv/exe image is
			// required before accepting a stable non-controller incarnation.
			againCmd, err := readProxyInactiveProc(filepath.Join(path, "cmdline"), 64<<10)
			if gone(err) {
				clear(cmd)
				continue
			}
			if err != nil || string(againCmd) != string(cmd) {
				clear(againCmd)
				clear(cmd)
				return ErrScopedDNSRuntimeInactive
			}
			clear(againCmd)
			againExe, err := p.readlink(filepath.Join(path, "exe"))
			if gone(err) {
				clear(cmd)
				continue
			}
			if err != nil || againExe != exeBefore {
				clear(cmd)
				return ErrScopedDNSRuntimeInactive
			}
		}
		clear(cmd)
		again, err := readProxyInactiveProc(filepath.Join(path, "stat"), 16<<10)
		if gone(err) {
			continue
		}
		_, _, current, parseErr := proxyInactiveProcStat(again, pid)
		if err != nil || parseErr != nil || ticks != current {
			return ErrScopedDNSRuntimeInactive
		}
		self = self || pid == p.selfPID
	}
	if !self {
		return ErrScopedDNSRuntimeInactive
	}
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := readProxyInactiveProc(filepath.Join(netRoot, kind), 1<<20)
		if err != nil {
			return err
		}
		if err := scopedDNSInactiveSocketTable(raw, strings.HasSuffix(kind, "6"), strings.HasPrefix(kind, "udp"), ports); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func scopedDNSInactiveSocketTable(raw []byte, v6, udp bool, ports map[uint16]bool) error {
	if len(raw) == 0 || len(raw) > 1<<20 || strings.ContainsRune(string(raw), '\x00') {
		return ErrScopedDNSRuntimeInactive
	}
	lines := strings.Split(string(raw), "\n")
	header := strings.Fields(lines[0])
	if len(lines) > 8192 || len(header) < 12 || header[0] != "sl" || header[1] != "local_address" ||
		(header[2] != "rem_address" && header[2] != "remote_address") || header[3] != "st" || header[11] != "inode" {
		return ErrScopedDNSRuntimeInactive
	}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 10 || len(f[3]) != 2 {
			return ErrScopedDNSRuntimeInactive
		}
		if !strings.HasSuffix(f[0], ":") {
			return ErrScopedDNSRuntimeInactive
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(f[0], ":"), 10, 32); err != nil {
			return ErrScopedDNSRuntimeInactive
		}
		hexPair := func(text string, left, right int) bool {
			parts := strings.Split(text, ":")
			if len(parts) != 2 || len(parts[0]) != left || len(parts[1]) != right {
				return false
			}
			_, e1 := hex.DecodeString(parts[0])
			_, e2 := hex.DecodeString(parts[1])
			return e1 == nil && e2 == nil
		}
		if !hexPair(f[4], 8, 8) || !hexPair(f[5], 2, 8) || len(f[6]) != 8 {
			return ErrScopedDNSRuntimeInactive
		}
		if _, err := hex.DecodeString(f[6]); err != nil {
			return ErrScopedDNSRuntimeInactive
		}
		if _, err := strconv.ParseUint(f[7], 10, 32); err != nil {
			return ErrScopedDNSRuntimeInactive
		}
		if _, err := strconv.ParseUint(f[8], 10, 64); err != nil {
			return ErrScopedDNSRuntimeInactive
		}
		state, e1 := strconv.ParseUint(f[3], 16, 8)
		local, e2 := proxyInactiveSocketPort(f[1], v6)
		_, e3 := proxyInactiveSocketPort(f[2], v6)
		inode, e4 := strconv.ParseUint(f[9], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || state == 0 || state > 12 || udp && state != 1 && state != 7 ||
			(state == 10 || udp) && inode == 0 || ports[local] {
			return ErrScopedDNSRuntimeInactive
		}
	}
	return nil
}
