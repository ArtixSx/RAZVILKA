//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Read-only bounded socket accounting. Only original process owners supply
// current; no process, Start, cleanup or packet authority is returned.
func inspectOriginalNodeRouterBackendSockets(ctx context.Context, pid int, source, pin netip.Addr, endpoints map[netip.Addr]bool, current func(context.Context) error) error {
	return inspectOriginalNodeRouterBackendSocketsWithSOCKSUDP(ctx, pid, source, pin, endpoints, current, nil)
}

func inspectOriginalNodeRouterBackendSocketsWithSOCKSUDP(ctx context.Context, pid int, source, pin netip.Addr, endpoints map[netip.Addr]bool, current func(context.Context) error, role *mihomoLiveSOCKSUDPListener) error {
	if ctx == nil || pid <= 1 || current == nil {
		return ErrNodeTransitUnavailable
	}
	observe := func(c context.Context) error {
		if err := current(c); err != nil {
			return err
		}
		if role != nil {
			return role.current(c, pid)
		}
		return nil
	}
	return inspectNodeRouterProcSockets(ctx, filepath.Join("/proc", strconv.Itoa(pid)), source, pin, endpoints, observe, role, readNodeRouterProc)
}

func inspectNodeRouterProcSockets(ctx context.Context, proc string, source, pin netip.Addr, endpoints map[netip.Addr]bool, observe func(context.Context) error, role *mihomoLiveSOCKSUDPListener, readTable func(string, int64) ([]byte, error)) error {
	// A table observation is valid only between matching FD-to-inode maps.
	// A single retiring socket may disappear between these non-atomic procfs
	// reads. A changed map can start one fresh observation, never authorize it.
	var previous map[string]string
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := observe(ctx); err != nil {
			return nodeTransitPhase("backend-process-initial", err)
		}
		opening, err := nodeRouterSocketFDs(ctx, proc)
		if err != nil {
			return err
		}
		if previous != nil && !maps.Equal(previous, opening) {
			return nodeTransitPhase("backend-fd-unstable", ErrNodeTransitUnavailable)
		}
		inodes := make(map[string]bool, len(opening))
		for _, inode := range opening {
			inodes[inode] = true
		}
		found := make(map[string]bool, len(inodes))
		if err := inspectNodeRouterSocketTables(ctx, proc, source, pin, endpoints, role, inodes, found, readTable); err != nil {
			return err
		}
		closing, err := nodeRouterSocketFDs(ctx, proc)
		if err != nil {
			return err
		}
		if err := observe(ctx); err != nil {
			return nodeTransitPhase("backend-process-closing", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, inode := range closing {
			if inodes[inode] && !found[inode] {
				return nodeTransitPhase("backend-inode-unclassified", ErrNodeTransitUnavailable)
			}
		}
		if maps.Equal(opening, closing) {
			return nil
		}
		previous = closing
	}
	return nodeTransitPhase("backend-fd-unstable", ErrNodeTransitUnavailable)
}

func nodeRouterSocketFDs(ctx context.Context, proc string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fds, err := os.Open(filepath.Join(proc, "fd"))
	if err != nil {
		return nil, nodeTransitPhase("backend-fd-open", ErrNodeTransitUnavailable)
	}
	entries, err := fds.ReadDir(2049)
	_ = fds.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2048 {
		return nil, nodeTransitPhase("backend-fd-list", ErrNodeTransitUnavailable)
	}
	sockets := make(map[string]string)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		link, err := os.Readlink(filepath.Join(proc, "fd", entry.Name()))
		if err != nil {
			return nil, nodeTransitPhase("backend-fd-readlink", ErrNodeTransitUnavailable)
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			value, err := strconv.ParseUint(inode, 10, 64)
			if err != nil || value == 0 || strconv.FormatUint(value, 10) != inode {
				return nil, nodeTransitPhase("backend-fd-inode", ErrNodeTransitUnavailable)
			}
			sockets[entry.Name()] = inode
		}
	}
	return sockets, nil
}

func inspectNodeRouterSocketTables(ctx context.Context, proc string, source, pin netip.Addr, endpoints map[netip.Addr]bool, role *mihomoLiveSOCKSUDPListener, inodes, found map[string]bool, readTable func(string, int64) ([]byte, error)) error {
	socksUDPFound := false
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := readTable(filepath.Join(proc, "net", kind), 1<<20)
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
				if role != nil && role.matches(kind, socket, source, pin, socksUDPFound) {
					socksUDPFound = true
					found[socket.inode] = true
					continue
				}
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
	if err := ctx.Err(); err != nil {
		return err
	}
	unix, err := readTable(filepath.Join(proc, "net", "unix"), 1<<20)
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
	if err := ctx.Err(); err != nil {
		return err
	}
	netlink, err := readTable(filepath.Join(proc, "net", "netlink"), 1<<20)
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
	if role != nil && !socksUDPFound {
		return nodeTransitPhase("backend-original-socks-udp-missing", ErrNodeTransitUnavailable)
	}

	return ctx.Err()
}
