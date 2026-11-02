//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The kernel's fdinfo iff field associates the actual retained sidecar's TUN
// descriptors with the interface. A matching name alone is not the witness.
func (n *mihomoLiveSidecar) tunInterfaceIndex(ctx context.Context, cleanup bool) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.owner == nil || n.owner.proxy == nil {
		return 0, errMihomoLiveMaterial
	}
	if cleanup {
		if err := errors.Join(n.metadata(ctx), n.kernelCurrent(ctx)); err != nil {
			return 0, err
		}
	} else if err := n.currentLocked(ctx); err != nil {
		return 0, err
	}
	root := filepath.Join("/proc", strconv.Itoa(n.command.Process.Pid), "fdinfo")
	dir, err := os.Open(root)
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(2049)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2048 {
		return 0, ErrNodeTransitUnavailable
	}
	found := 0
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 31); err != nil {
			return 0, ErrNodeTransitUnavailable
		}
		data, err := readNodeRouterProc(filepath.Join(root, entry.Name()), 8192)
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "iff:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[1] != n.owner.proxy.Interface {
				return 0, ErrNodeTransitUnavailable
			}
			found++
		}
	}
	if found < 1 || found > 8 {
		return 0, ErrNodeTransitUnavailable
	}
	device, err := net.InterfaceByName(n.owner.proxy.Interface)
	if err != nil || device.Index < 1 || device.Flags&net.FlagLoopback != 0 || device.Flags&net.FlagUp == 0 {
		return 0, ErrNodeTransitUnavailable
	}
	if err := n.kernelCurrent(ctx); err != nil {
		return 0, err
	}
	return device.Index, ctx.Err()
}
