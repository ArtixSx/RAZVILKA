package dataplane

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

func nfqws2InactiveProcesses(ctx context.Context, proof nfqws2InactivePlatform, a *NFQWS2Adapter) error {
	return nfqws2InactiveProcessesExcept(ctx, proof, a, 0, nil)
}

// The sole exemption is an original, live process rechecked by the actual
// first-start owner. Ordinary inactivity never exempts a PID or a name.
func nfqws2InactiveProcessesExcept(ctx context.Context, proof nfqws2InactivePlatform, a *NFQWS2Adapter, exceptPID int, current func() error) error {
	if ctx == nil || ctx.Err() != nil || a == nil || proof.selfPID < 1 || !filepath.IsAbs(proof.procRoot) || proof.readlink == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	if exceptPID != 0 && (exceptPID <= 1 || exceptPID == proof.selfPID || current == nil) {
		return ErrNFQWSManagedProcessUnknown
	}
	dir, err := os.Open(proof.procRoot)
	if err != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	entries, err := dir.ReadDir(8193)
	_ = dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) == 0 || len(entries) > 8192 {
		return ErrNFQWSManagedProcessUnknown
	}
	self, processes, bytes := false, 0, 0
	exceptSeen := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if pid <= 0 || strconv.Itoa(pid) != entry.Name() || !entry.IsDir() || processes >= 4096 {
			return ErrNFQWSManagedProcessUnknown
		}
		processes++
		path := filepath.Join(proof.procRoot, entry.Name())
		stat, err := readProxyInactiveProc(filepath.Join(path, "stat"), 16<<10)
		if errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path) && pid != proof.selfPID {
			continue
		}
		if err != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		state, flags, ticks, err := proxyInactiveProcStat(stat, pid)
		if err != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		if pid == exceptPID {
			if exceptSeen || state == 'Z' || state == 'X' || state == 'x' || current() != nil {
				return ErrNFQWSManagedProcessUnknown
			}
			exceptSeen = true
			continue
		}
		text := strings.TrimSpace(string(stat))
		name := strings.TrimPrefix(text[:strings.LastIndex(text, ")")], strconv.Itoa(pid)+" (")
		if nfqws2InactiveProcessName(name) {
			return ErrNFQWSManagedProcessUnknown // Also reject un-reaped NFQ zombies.
		}
		if state == 'Z' || state == 'X' || state == 'x' {
			if pid == proof.selfPID {
				return ErrNFQWSManagedProcessUnknown
			}
			continue
		}
		cmd, err := readProxyInactiveProc(filepath.Join(path, "cmdline"), 64<<10)
		if errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path) && pid != proof.selfPID {
			continue
		}
		if err != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		bytes += len(cmd)
		if bytes > 16<<20 {
			return ErrNFQWSManagedProcessUnknown
		}
		if len(cmd) == 0 {
			if flags&0x00200000 == 0 || pid == proof.selfPID {
				return ErrNFQWSManagedProcessUnknown
			}
		} else {
			args, valid := inactiveProcArguments(cmd)
			if !valid {
				return ErrNFQWSManagedProcessUnknown
			}
			// Stock is_running uses pgrep -f of this entire program path. A
			// wrapper/observer mentioning it could change stock's PID choice.
			if exceptPID != 0 && strings.Contains(string(cmd), filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(a.InitPath))), "usr", "bin", "nfqws2")) {
				return ErrNFQWSManagedProcessUnknown
			}
			executable, err := proof.readlink(filepath.Join(path, "exe"))
			if errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path) && pid != proof.selfPID {
				clear(cmd)
				continue
			}
			if err != nil || executable == "" || len(executable) > 4096 || strings.ContainsRune(executable, '\x00') ||
				nfqws2InactiveProcessName(strings.TrimSuffix(executable, " (deleted)")) || nfqws2InactiveProcessName(args[0]) {
				return ErrNFQWSManagedProcessUnknown
			}
			for _, arg := range args {
				if nfqws2InactiveProcessArgument(arg, a) {
					return ErrNFQWSManagedProcessUnknown
				}
			}
		}
		clear(cmd)
		again, err := readProxyInactiveProc(filepath.Join(path, "stat"), 16<<10)
		if errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path) && pid != proof.selfPID {
			continue
		}
		_, _, closingTicks, parseErr := proxyInactiveProcStat(again, pid)
		if err != nil || parseErr != nil || closingTicks != ticks {
			return ErrNFQWSManagedProcessUnknown
		}
		self = self || pid == proof.selfPID
	}
	if !self || processes == 0 || exceptPID != 0 && !exceptSeen {
		return ErrNFQWSManagedProcessUnknown
	}
	return ctx.Err()
}

func nfqws2InactiveProcessName(value string) bool {
	name := strings.ToLower(filepath.Base(value))
	return name == "nfqws" || name == "nfqws2" || name == "dvtws"
}

func nfqws2InactiveProcessArgument(arg string, a *NFQWS2Adapter) bool {
	if arg == "nfqws-managed-process-supervisor" || arg == "nfqws-managed-helper" {
		return true
	}
	key, value, inline := strings.Cut(arg, "=")
	if key == "--qnum" || key == "--intercept" || key == "--queue-num" {
		return true
	}
	if !inline {
		value = arg
	}
	lists := a.ownedListPaths()
	return value == a.StateRoot || value == a.ConfigPath || value == a.InitPath || slices.Contains(lists[:], value)
}

func nfqws2InactiveNetlinkTable(text string) error {
	if len(text) == 0 || len(text) > 1<<20 || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r") {
		return ErrNFQWSManagedKernelOwner
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 8192 || strings.Join(strings.Fields(lines[0]), " ") != "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode" {
		return ErrNFQWSManagedKernelOwner
	}
	seen := map[[2]uint64]bool{}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 10 {
			return ErrNFQWSManagedKernelOwner
		}
		protocol, e1 := strconv.ParseUint(fields[1], 10, 8)
		port, e2 := strconv.ParseUint(fields[2], 10, 32)
		inode, e3 := strconv.ParseUint(fields[9], 10, 64)
		key := [2]uint64{protocol, port}
		if e1 != nil || e2 != nil || e3 != nil || strconv.FormatUint(protocol, 10) != fields[1] || strconv.FormatUint(port, 10) != fields[2] ||
			strconv.FormatUint(inode, 10) != fields[9] || seen[key] || protocol == 12 && port != 0 && inode == 0 {
			return ErrNFQWSManagedKernelOwner
		}
		seen[key] = true
	}
	return nil
}
