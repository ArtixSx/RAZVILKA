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

func readProxyInactiveProc(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrProxyRuntimeInactive
	}
	return raw, nil
}

// The stat field positions are Linux's fixed process ABI. Empty command lines
// prove nothing unless the current task is a kernel thread or exited task.
func proxyInactiveProcStat(raw []byte, pid int) (state byte, flags uint64, ticks string, err error) {
	text := strings.TrimSpace(string(raw))
	end := strings.LastIndex(text, ")")
	if len(raw) > 16<<10 || end < 0 || !strings.HasPrefix(text, strconv.Itoa(pid)+" (") || strings.ContainsRune(text, '\x00') {
		return 0, 0, "", ErrProxyRuntimeInactive
	}
	fields := strings.Fields(text[end+1:])
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.ContainsRune("RSDZTtXxIKP", rune(fields[0][0])) {
		return 0, 0, "", ErrProxyRuntimeInactive
	}
	flags, err = strconv.ParseUint(fields[6], 10, 64)
	start, e := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || e != nil || start == 0 || strconv.FormatUint(start, 10) != fields[19] {
		return 0, 0, "", ErrProxyRuntimeInactive
	}
	return fields[0][0], flags, fields[19], nil
}

func proxyInactiveProc(ctx context.Context, proof proxyInactiveProof, adapter *ProxyTunnelAdapter) error {
	if proof.selfPID < 1 || !filepath.IsAbs(proof.procRoot) || proof.readlink == nil || adapter == nil || adapter.SOCKSPort < 1024 || adapter.SOCKSPort > 65535 {
		return ErrProxyRuntimeInactive
	}
	canaryPort, err := adapter.canaryPort()
	if err != nil {
		return ErrProxyRuntimeInactive
	}
	binaries, err := adapter.inactiveProcessNames()
	if err != nil {
		return err
	}
	dir, err := os.Open(proof.procRoot)
	if err != nil {
		return ErrProxyRuntimeInactive
	}
	entries, readErr := dir.ReadDir(8193)
	_ = dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) == 0 || len(entries) > 8192 {
		return ErrProxyRuntimeInactive
	}
	self, processes, bytes := false, 0, 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Known /proc non-PID entries are not a process listing.
		}
		if pid < 1 || strconv.Itoa(pid) != entry.Name() || !entry.IsDir() || processes >= 4096 {
			return ErrProxyRuntimeInactive
		}
		processes++
		path := filepath.Join(proof.procRoot, entry.Name())
		stat, err := readProxyInactiveProc(filepath.Join(path, "stat"), 16<<10)
		if errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path) && pid != proof.selfPID {
			continue
		}
		if err != nil {
			return ErrProxyRuntimeInactive
		}
		state, flags, ticks, err := proxyInactiveProcStat(stat, pid)
		if err != nil {
			return err
		}
		if state == 'Z' || state == 'X' || state == 'x' {
			if pid == proof.selfPID {
				return ErrProxyRuntimeInactive
			}
			continue
		}
		cmd, err := readProxyInactiveProc(filepath.Join(path, "cmdline"), 64<<10)
		if errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path) && pid != proof.selfPID {
			continue
		}
		if err != nil {
			return ErrProxyRuntimeInactive
		}
		bytes += len(cmd)
		if bytes > 16<<20 {
			return ErrProxyRuntimeInactive
		}
		if len(cmd) == 0 {
			if flags&0x00200000 == 0 || pid == proof.selfPID { // Linux PF_KTHREAD.
				return ErrProxyRuntimeInactive
			}
		} else {
			if cmd[len(cmd)-1] != 0 {
				return ErrProxyRuntimeInactive
			}
			args := strings.Split(string(cmd[:len(cmd)-1]), "\x00")
			if len(args) == 0 || len(args) > 256 || args[0] == "" {
				return ErrProxyRuntimeInactive
			}
			executable, err := proof.readlink(filepath.Join(path, "exe"))
			if errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path) && pid != proof.selfPID {
				clear(cmd)
				continue
			}
			if err != nil || executable == "" || len(executable) > 4096 || strings.ContainsRune(executable, '\x00') {
				return ErrProxyRuntimeInactive
			}
			for _, binary := range binaries {
				if strings.EqualFold(filepath.Base(strings.TrimSuffix(executable, " (deleted)")), filepath.Base(binary)) ||
					strings.EqualFold(filepath.Base(args[0]), filepath.Base(binary)) {
					return ErrProxyRuntimeInactive // Foreign or canary incarnations hold too.
				}
			}
			for _, arg := range args {
				if proxyInactiveConfigArgument(arg, adapter) || adapter.EngineBin != "" && arg == adapter.EngineBin ||
					adapter.SidecarBin != "" && arg == adapter.SidecarBin {
					return ErrProxyRuntimeInactive
				}
			}
		}
		clear(cmd)
		again, err := readProxyInactiveProc(filepath.Join(path, "stat"), 16<<10)
		if errors.Is(err, os.ErrNotExist) && proxyInactivePIDGone(path) && pid != proof.selfPID {
			continue
		}
		_, _, currentTicks, e := proxyInactiveProcStat(again, pid)
		if err != nil || e != nil || currentTicks != ticks {
			return ErrProxyRuntimeInactive
		}
		self = self || pid == proof.selfPID
	}
	if !self || processes == 0 {
		return ErrProxyRuntimeInactive
	}
	for _, kind := range []string{"tcp", "tcp6"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := readProxyInactiveProc(filepath.Join(proof.procRoot, "net", kind), 1<<20)
		if err != nil || proxyInactiveSocketTable(raw, kind == "tcp6", adapter.SOCKSPort) != nil || proxyInactiveSocketTable(raw, kind == "tcp6", canaryPort) != nil {
			return ErrProxyRuntimeInactive
		}
	}
	return ctx.Err()
}

// Current runtime and canary paths are derived solely from trusted startup
// scope. A controller's --dataplane-state=root argument is not a config match.
func proxyInactiveConfigArgument(arg string, adapter *ProxyTunnelAdapter) bool {
	if _, value, option := strings.Cut(arg, "="); option {
		arg = value
	}
	if arg == adapter.engineConfigPath() || arg == adapter.sidecarConfigPath() {
		return true
	}
	if !filepath.IsAbs(arg) || filepath.Clean(arg) != arg {
		return false
	}
	transactions := filepath.Join(filepath.Dir(adapter.StateRoot), "transactions")
	name, err := filepath.Rel(transactions, arg)
	if err != nil || !filepath.IsLocal(name) {
		return false
	}
	parts := strings.Split(name, string(filepath.Separator))
	return len(parts) == 4 && validPlanID(parts[0]) && parts[1] == adapter.ID() && parts[2] == "canary" && parts[3] == "engine.json"
}

func proxyInactivePIDGone(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

func proxyInactiveSocketTable(raw []byte, v6 bool, port int) error {
	if len(raw) == 0 || len(raw) > 1<<20 || strings.ContainsRune(string(raw), '\x00') {
		return ErrProxyRuntimeInactive
	}
	lines := strings.Split(string(raw), "\n")
	header := strings.Fields(lines[0])
	if len(lines) > 8192 || len(header) < 12 || header[0] != "sl" || header[1] != "local_address" ||
		(header[2] != "rem_address" && header[2] != "remote_address") || header[3] != "st" || header[11] != "inode" {
		return ErrProxyRuntimeInactive
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 10 || len(fields[3]) != 2 {
			return ErrProxyRuntimeInactive
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		localPort, e1 := proxyInactiveSocketPort(fields[1], v6)
		_, e2 := proxyInactiveSocketPort(fields[2], v6)
		inode, e3 := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || state == 0 || state > 12 || e1 != nil || e2 != nil || e3 != nil || state == 10 && inode == 0 ||
			state == 10 && localPort == uint16(port) {
			return ErrProxyRuntimeInactive
		}
	}
	return nil
}

// A negative listener observer needs only Linux's fixed hexadecimal address:
// port ABI, not a routed endpoint, socket owner or address conversion grant.
func proxyInactiveSocketPort(raw string, v6 bool) (uint16, error) {
	parts := strings.Split(raw, ":")
	size := 8
	if v6 {
		size = 32
	}
	if len(parts) != 2 || len(parts[0]) != size || len(parts[1]) != 4 {
		return 0, ErrProxyRuntimeInactive
	}
	if _, err := hex.DecodeString(parts[0]); err != nil {
		return 0, ErrProxyRuntimeInactive
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return 0, ErrProxyRuntimeInactive
	}
	return uint16(port), nil
}
