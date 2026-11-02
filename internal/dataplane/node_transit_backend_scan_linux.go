//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Read-only bounded socket accounting. Only original process owners supply
// current; no process, Start, cleanup or packet authority is returned.
func inspectOriginalNodeRouterBackendSockets(ctx context.Context, pid int, source, pin netip.Addr, endpoints map[netip.Addr]bool, current func(context.Context) error) error {
	if ctx == nil || pid <= 1 || current == nil {
		return ErrNodeTransitUnavailable
	}
	if err := current(ctx); err != nil {
		return nodeTransitPhase("backend-process-initial", err)
	}
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	fds, err := os.Open(filepath.Join(proc, "fd"))
	if err != nil {
		return nodeTransitPhase("backend-fd-open", ErrNodeTransitUnavailable)
	}
	entries, err := fds.ReadDir(2049)
	_ = fds.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2048 {
		return nodeTransitPhase("backend-fd-list", ErrNodeTransitUnavailable)
	}
	inodes := map[string]bool{}
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(proc, "fd", entry.Name()))
		if err != nil {
			return nodeTransitPhase("backend-fd-readlink", ErrNodeTransitUnavailable)
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			value, err := strconv.ParseUint(inode, 10, 64)
			if err != nil || value == 0 || strconv.FormatUint(value, 10) != inode {
				return nodeTransitPhase("backend-fd-inode", ErrNodeTransitUnavailable)
			}
			inodes[inode] = true
		}
	}
	found := map[string]bool{}
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		raw, err := readNodeRouterProc(filepath.Join(proc, "net", kind), 1<<20)
		if err != nil {
			return nodeTransitPhase("backend-ip-table-read", ErrNodeTransitUnavailable)
		}
		sockets, err := nodeRouterOwnedSockets(raw, strings.HasSuffix(kind, "6"), inodes)
		if err != nil {
			return nodeTransitPhase("backend-ip-table-parse", err)
		}
		for _, socket := range sockets {
			if found[socket.inode] {
				return nodeTransitPhase("backend-duplicate-"+kind+"-inode", ErrNodeTransitUnavailable)
			}
			if strings.HasPrefix(kind, "udp") && socket.remote.Addr().IsUnspecified() {
				bind := "other-bound"
				if socket.local.Addr().IsLoopback() {
					bind = "loopback-bound"
				} else if socket.local.Addr().IsUnspecified() {
					bind = "wildcard-bound"
				}
				return nodeTransitPhase("backend-unconnected-"+kind+"-"+bind, ErrNodeTransitUnavailable)
			}
			found[socket.inode] = true
			if err := nodeRouterSocketDisjoint(socket, source, pin, endpoints); err != nil {
				return nodeTransitPhase("backend-socket-disjoint", err)
			}
		}
	}
	unix, err := readNodeRouterProc(filepath.Join(proc, "net", "unix"), 1<<20)
	if err != nil || len(unix) > 1<<20 {
		return nodeTransitPhase("backend-unix-table-read", ErrNodeTransitUnavailable)
	}
	lines := strings.Split(string(unix), "\n")
	if len(lines) > 8192 {
		return nodeTransitPhase("backend-unix-table-size", ErrNodeTransitUnavailable)
	}
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || i == 0 && fields[0] == "Num" {
			continue
		}
		if len(fields) < 7 {
			return nodeTransitPhase("backend-unix-table-parse", ErrNodeTransitUnavailable)
		}
		if inodes[fields[6]] {
			if found[fields[6]] {
				return nodeTransitPhase("backend-unix-duplicate", ErrNodeTransitUnavailable)
			}
			found[fields[6]] = true
		}
	}
	netlink, err := readNodeRouterProc(filepath.Join(proc, "net", "netlink"), 1<<20)
	if err != nil {
		return nodeTransitPhase("backend-netlink-table-read", ErrNodeTransitUnavailable)
	}
	controls, err := nodeRouterOwnedRouteNetlink(netlink, inodes)
	if err != nil {
		return nodeTransitPhase("backend-netlink-table-parse", err)
	}
	for inode := range controls {
		if found[inode] {
			return nodeTransitPhase("backend-netlink-duplicate", ErrNodeTransitUnavailable)
		}
		found[inode] = true
	}
	// Known Unix/route-netlink controls cannot traverse IP RPDB. Every
	// other held socket must have an explicitly inspected IP tuple above.
	if len(found) != len(inodes) {
		return nodeTransitPhase("backend-inode-accounting", ErrNodeTransitUnavailable)
	}

	if err := current(ctx); err != nil {
		return nodeTransitPhase("backend-process-closing", err)
	}
	return ctx.Err()
}
