package dataplane

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func readBoundedProxyConfig(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 4<<20 {
		return nil, errors.New("invalid bounded proxy config")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("proxy config replaced")
	}
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		clear(data)
		return nil, errors.New("proxy config exceeds bound")
	}
	return data, nil
}

func (a *ProxyTunnelAdapter) verifyNodeProcess(spec ProcessSpec, endpoint string) (string, error) {
	if a.nodeRuntimeIdentity != nil {
		return a.nodeRuntimeIdentity(spec, endpoint)
	}
	return verifyNodeLaunch(spec, endpoint)
}

// Verify the launcher-created receipt against the full live process/config.
// No isolated projection of the config and no newly written receipt may stand
// in for the live routed Xray. RecordStart remains exclusively in Start.
func verifyNodeLaunch(spec ProcessSpec, endpoint string) (string, error) {
	pid, err := readManagedPID(spec)
	if err != nil {
		return "", err
	}
	raw, err := readBoundedSidecar(spec.PIDPath + routeidentity.ReceiptSuffix)
	var saved routeidentity.Receipt
	if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Version != 1 || saved.PID != pid {
		return "", errors.New("scoped launch receipt is unavailable")
	}
	capture := func() (routeidentity.Receipt, error) {
		current := routeidentity.Receipt{Version: 1, PID: pid}
		root := filepath.Join("/proc", strconv.Itoa(pid))
		boot, e1 := os.ReadFile("/proc/sys/kernel/random/boot_id")
		stat, e2 := os.ReadFile(filepath.Join(root, "stat"))
		cmd, e3 := os.ReadFile(filepath.Join(root, "cmdline"))
		exe, e4 := os.Readlink(filepath.Join(root, "exe"))
		config, e5 := readBoundedProxyConfig(spec.MatchArg)
		defer clear(config)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || string(cmd) != strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00")+"\x00" {
			return current, errors.New("scoped process command/config is unavailable")
		}
		end := strings.LastIndex(string(stat), ")")
		if end < 0 {
			return current, errors.New("invalid scoped process stat")
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
			return current, errors.New("scoped process is not live")
		}
		if ticks, e := strconv.ParseUint(fields[19], 10, 64); e != nil || ticks == 0 {
			return current, errors.New("invalid scoped start ticks")
		}
		current.BootID, current.StartTicks, current.Executable = strings.TrimSpace(string(boot)), fields[19], exe
		current.ArgsHash, current.ConfigHash = routeidentity.Hash(cmd), routeidentity.Hash(config)
		installed, e1 := os.Stat(spec.Binary)
		active, e2 := os.Stat(filepath.Join(root, "exe"))
		if e1 != nil || e2 != nil || !os.SameFile(installed, active) {
			return current, errors.New("scoped process executable differs from installed binary")
		}
		self, e1 := os.Readlink("/proc/self/ns/net")
		child, e2 := os.Readlink(filepath.Join(root, "ns/net"))
		noNamespaces := errors.Is(e1, os.ErrNotExist) && errors.Is(e2, os.ErrNotExist)
		if !noNamespaces && (e1 != nil || e2 != nil || self == "" || self != child) {
			return current, errors.New("scoped process network namespace is unverified")
		}
		return current, nil
	}
	current, err := capture()
	if err != nil || current != saved {
		return "", errors.New("scoped live identity differs from launch receipt")
	}
	inode := ""
	if endpoint != "" {
		inode, err = nodeListenerOwner(pid, endpoint)
		if err != nil {
			return "", err
		}
	}
	after, err := capture()
	if err != nil || after != current {
		return "", errors.New("scoped identity changed during inspection")
	}
	return routeidentity.Hash(append(raw, []byte("|"+endpoint+"|"+inode)...)), nil
}

func nodeListenerOwner(pid int, endpoint string) (string, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	ip := net.ParseIP(host).To4()
	port, e := strconv.Atoi(portText)
	if err != nil || e != nil || ip == nil || !ip.IsLoopback() || port < 1 || port > 65535 {
		return "", errors.New("invalid scoped SOCKS listener")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp", pid))
	if err != nil || len(data) > 1<<20 {
		return "", errors.New("scoped listener table unavailable")
	}
	want := fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(ip), port)
	inode := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		if fields[1] == want || fields[1] == fmt.Sprintf("00000000:%04X", port) {
			if inode != "" || fields[1] != want {
				return "", errors.New("ambiguous scoped SOCKS listener")
			}
			inode = fields[9]
		}
	}
	if inode == "" || inode == "0" {
		return "", errors.New("scoped listener unavailable")
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err == nil && link == "socket:["+inode+"]" {
			return inode, nil
		}
	}
	return "", errors.New("scoped SOCKS listener belongs to another process")
}

func (a *ProxyTunnelAdapter) scopedRuntimeIdentity() (string, error) {
	m, err := a.readNodeManifest(a.nodeManifestPath())
	if err != nil {
		return "", err
	}
	config, err := readBoundedProxyConfig(a.engineConfigPath())
	if err != nil {
		return "", err
	}
	defer clear(config)
	side, err := readBoundedSidecar(a.sidecarConfigPath())
	if err != nil {
		return "", err
	}
	defer clear(side)
	if routeidentity.Hash(config) != m.ConfigHash || routeidentity.Hash(side) != m.SidecarHash {
		return "", errors.New("scoped runtime config changed")
	}
	if err := validateScopedXrayConfig(config, m.Requests, a.SOCKSPort); err != nil {
		return "", err
	}
	engine, err := a.verifyNodeProcess(a.engineProcess(), net.JoinHostPort("127.0.0.1", strconv.Itoa(a.SOCKSPort)))
	if err != nil {
		return "", err
	}
	sidecar, err := a.verifyNodeProcess(a.sidecarProcess(), "")
	if err != nil {
		return "", err
	}
	return routeidentity.Hash([]byte(engine + "|" + sidecar + "|" + m.ConfigHash + "|" + m.SidecarHash)), nil
}
