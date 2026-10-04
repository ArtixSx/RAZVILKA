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

func readNodeRouterProc(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrNodeTransitUnavailable
	}
	return raw, nil
}

// Read-only capability check. Production never rewrites host sysctls for a
// health probe. Strict reverse filtering needs a separately supported verifier.
func nodeRouterReturnPath(ctx context.Context, device string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !proxyFirewallInterface.MatchString(device) || device == "lo" {
		return ErrNodeTransitUnavailable
	}
	values := map[string]int{}
	for _, name := range []string{"all", "default", device} {
		for _, setting := range []string{"rp_filter", "src_valid_mark"} {
			raw, err := readNodeRouterProc(filepath.Join("/proc/sys/net/ipv4/conf", name, setting), 16)
			if err != nil || len(raw) > 16 {
				return ErrNodeTransitUnavailable
			}
			value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			limit := 2
			if setting == "src_valid_mark" {
				limit = 1
			}
			if err != nil || value < 0 || value > limit {
				return ErrNodeTransitUnavailable
			}
			values[name+"/"+setting] = value
		}
	}
	if max(values["all/rp_filter"], values[device+"/rp_filter"]) == 1 {
		return errors.New("strict reverse-path capability is unsupported for router TUN health")
	}
	return ctx.Err()
}

func (a *ProxyTunnelAdapter) nodeRouterBackendDisjoint(ctx context.Context, manifest proxyNodeManifest, source, pin netip.Addr) error {
	endpoints := map[netip.Addr]bool{}
	for _, endpoint := range manifest.Endpoints {
		address, err := netip.ParseAddr(endpoint.IP)
		if err != nil || address == pin || address == source {
			return ErrNodeTransitUnavailable
		}
		endpoints[address] = true
	}
	if len(endpoints) == 0 {
		return ErrNodeTransitUnavailable
	}
	for _, spec := range []ProcessSpec{a.engineProcess(), a.sidecarProcess()} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := a.verifyNodeProcess(spec, ""); err != nil {
			return err
		}
		pid, err := readManagedPID(spec)
		if err != nil {
			return err
		}
		proc := filepath.Join("/proc", strconv.Itoa(pid))
		fds, err := os.Open(filepath.Join(proc, "fd"))
		if err != nil {
			return ErrNodeTransitUnavailable
		}
		entries, err := fds.ReadDir(2049)
		_ = fds.Close()
		if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2048 {
			return ErrNodeTransitUnavailable
		}
		inodes := map[string]bool{}
		for _, entry := range entries {
			link, err := os.Readlink(filepath.Join(proc, "fd", entry.Name()))
			if err != nil {
				return ErrNodeTransitUnavailable
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				value, err := strconv.ParseUint(inode, 10, 64)
				if err != nil || value == 0 || strconv.FormatUint(value, 10) != inode {
					return ErrNodeTransitUnavailable
				}
				inodes[inode] = true
			}
		}
		found := map[string]bool{}
		for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
			raw, err := readNodeRouterProc(filepath.Join(proc, "net", kind), 1<<20)
			if err != nil {
				return ErrNodeTransitUnavailable
			}
			sockets, err := nodeRouterOwnedSockets(raw, strings.HasSuffix(kind, "6"), inodes)
			if err != nil {
				return err
			}
			for _, socket := range sockets {
				if found[socket.inode] || strings.HasPrefix(kind, "udp") && socket.remote.Addr().IsUnspecified() {
					return ErrNodeTransitUnavailable
				}
				found[socket.inode] = true
				if err := nodeRouterSocketDisjoint(socket, source, pin, endpoints); err != nil {
					return err
				}
			}
		}
		unix, err := readNodeRouterProc(filepath.Join(proc, "net", "unix"), 1<<20)
		if err != nil || len(unix) > 1<<20 {
			return ErrNodeTransitUnavailable
		}
		lines := strings.Split(string(unix), "\n")
		if len(lines) > 8192 {
			return ErrNodeTransitUnavailable
		}
		for i, line := range lines {
			fields := strings.Fields(line)
			if len(fields) == 0 || i == 0 && fields[0] == "Num" {
				continue
			}
			if len(fields) < 7 {
				return ErrNodeTransitUnavailable
			}
			if inodes[fields[6]] {
				if found[fields[6]] {
					return ErrNodeTransitUnavailable
				}
				found[fields[6]] = true
			}
		}
		netlink, err := readNodeRouterProc(filepath.Join(proc, "net", "netlink"), 1<<20)
		if err != nil {
			return ErrNodeTransitUnavailable
		}
		controls, err := nodeRouterOwnedRouteNetlink(netlink, inodes)
		if err != nil {
			return err
		}
		for inode := range controls {
			if found[inode] {
				return ErrNodeTransitUnavailable
			}
			found[inode] = true
		}
		// Known Unix/route-netlink controls cannot traverse IP RPDB. Every
		// other held socket must have an explicitly inspected IP tuple above.
		if len(found) != len(inodes) {
			return ErrNodeTransitUnavailable
		}
		if _, err := a.verifyNodeProcess(spec, ""); err != nil {
			return err
		}
	}
	return ctx.Err()
}
