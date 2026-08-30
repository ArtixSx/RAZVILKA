package routeidentity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const ReceiptSuffix = ".identity.json"

type Receipt struct {
	Version    int    `json:"version"`
	PID        int    `json:"pid"`
	BootID     string `json:"boot_id"`
	StartTicks string `json:"start_ticks"`
	Executable string `json:"executable"`
	ArgsHash   string `json:"args_sha256"`
	ConfigHash string `json:"config_sha256"`
}

// Passport contains only bounded, non-secret local evidence. Its ID changes
// across config changes, restarts and listener changes.
type Passport struct {
	ID         string `json:"id"`
	Outbound   string `json:"outbound"`
	PID        int    `json:"pid"`
	ConfigHash string `json:"config_sha256"`
}

type procReader struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	readLink func(string) (string, error)
}

func systemProc() procReader { return procReader{os.ReadFile, os.ReadDir, os.Readlink} }

func Hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// RecordStart is called only by the launcher, never retroactively by a probe.
// The config hash is captured before exec and checked again after startup.
func RecordStart(pid int, binary string, args []string, config, expectedHash string) ([]byte, error) {
	return recordStart(systemProc(), pid, binary, args, config, expectedHash)
}

func recordStart(proc procReader, pid int, binary string, args []string, config, expectedHash string) ([]byte, error) {
	r, err := capture(proc, pid, config)
	if err != nil {
		return nil, err
	}
	cmd, err := proc.readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || string(cmd) != strings.Join(append([]string{binary}, args...), "\x00")+"\x00" || expectedHash == "" || r.ConfigHash != expectedHash {
		return nil, errors.New("route-start-identity-mismatch")
	}
	return json.Marshal(r)
}

func capture(proc procReader, pid int, config string) (Receipt, error) {
	r := Receipt{Version: 1, PID: pid}
	if pid <= 1 {
		return r, errors.New("route-pid-invalid")
	}
	root := fmt.Sprintf("/proc/%d", pid)
	boot, e1 := proc.readFile("/proc/sys/kernel/random/boot_id")
	stat, e2 := proc.readFile(root + "/stat")
	cmd, e3 := proc.readFile(root + "/cmdline")
	exe, e4 := proc.readLink(root + "/exe")
	data, e5 := proc.readFile(config)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return r, errors.New("route-process-unavailable")
	}
	// comm can contain spaces and ')'; field 22 is starttime, relative to
	// field 3 after the final closing parenthesis.
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		return r, errors.New("route-process-stat-invalid")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return r, errors.New("route-process-stat-invalid")
	}
	if ticks, err := strconv.ParseUint(fields[19], 10, 64); err != nil || ticks == 0 {
		return r, errors.New("route-process-stat-invalid")
	}
	r.BootID = strings.TrimSpace(string(boot))
	r.StartTicks = fields[19]
	r.Executable = exe
	if r.BootID == "" || exe == "" || len(cmd) == 0 {
		return r, errors.New("route-process-unavailable")
	}
	r.ArgsHash = Hash(cmd)
	r.ConfigHash = Hash(data)
	return r, nil
}

func Verify(root, engine, endpoint string) (Passport, error) {
	return verify(systemProc(), root, engine, endpoint)
}

func verify(proc procReader, root, engine, endpoint string) (Passport, error) {
	var passport Passport
	pidData, err := proc.readFile(filepath.Join(root, "engine.pid"))
	if err != nil {
		return passport, errors.New("route-receipt-missing")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || pid <= 1 {
		return passport, errors.New("route-pid-invalid")
	}
	raw, err := proc.readFile(filepath.Join(root, "engine.pid") + ReceiptSuffix)
	var saved Receipt
	if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Version != 1 || saved.PID != pid {
		return passport, errors.New("route-receipt-missing")
	}
	config := filepath.Join(root, "engine.json")
	current, err := capture(proc, pid, config)
	if err != nil {
		return passport, err
	}
	if current != saved {
		return passport, errors.New("route-runtime-changed")
	}
	if filepath.Base(current.Executable) != engine {
		return passport, errors.New("route-engine-mismatch")
	}
	processNet, netErr := proc.readLink(fmt.Sprintf("/proc/%d/ns/net", pid))
	probeNet, probeNetErr := proc.readLink("/proc/self/ns/net")
	if netErr != nil || probeNetErr != nil || processNet == "" || processNet != probeNet {
		return passport, errors.New("route-network-namespace-mismatch")
	}
	cmd, err := proc.readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return passport, errors.New("route-process-unavailable")
	}
	args := strings.Split(strings.TrimSuffix(string(cmd), "\x00"), "\x00")
	if !managedArgs(engine, config, endpoint, args) {
		return passport, errors.New("route-command-unverified")
	}
	data, err := proc.readFile(config)
	if err != nil || Hash(data) != saved.ConfigHash {
		return passport, errors.New("route-runtime-changed")
	}
	outbound, err := ConfigOutbound(engine, data)
	if err != nil {
		return passport, err
	}
	inode, err := listenerInode(proc, pid, endpoint)
	if err != nil {
		return passport, err
	}
	// Catch a restart or config replacement during the inspection as well.
	after, err := capture(proc, pid, config)
	if err != nil || after != current {
		return passport, errors.New("route-runtime-changed")
	}
	passport = Passport{ID: "managed:" + engine + ":" + Hash(append(raw, []byte("|"+endpoint+"|"+inode)...)), Outbound: outbound, PID: pid, ConfigHash: saved.ConfigHash}
	return passport, nil
}

func managedArgs(engine, config, endpoint string, args []string) bool {
	if len(args) < 2 || filepath.Base(args[0]) != engine {
		return false
	}
	if engine == "sing-box" {
		return len(args) == 4 && args[1] == "run" && args[2] == "-c" && args[3] == config
	}
	if engine == "xray" {
		return len(args) == 4 && args[1] == "run" && args[2] == "-config" && args[3] == config
	}
	if engine != "usque" || len(args) < 10 {
		return false
	}
	want := []string{"-c", config, "socks", "-b", "127.0.0.1", "-p", "", "--always-reconnect", "-S"}
	_, want[6], _ = net.SplitHostPort(endpoint)
	for i, v := range want {
		if args[i+1] != v {
			return false
		}
	}
	for i := 10; i < len(args); i++ {
		if args[i] == "--http2" {
			continue
		}
		if args[i] == "-s" && i+1 < len(args) {
			i++
			continue
		}
		return false
	}
	return true
}

func listenerInode(proc procReader, pid int, endpoint string) (string, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	ip := net.ParseIP(host).To4()
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() {
		return "", errors.New("route-listener-unsupported")
	}
	// Managed engines bind IPv4 loopback. No guessing about wildcard/IPv6
	// sockets or reuseport: ambiguous listeners remain unconfirmed.
	want := fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(ip), port)
	data, err := proc.readFile(fmt.Sprintf("/proc/%d/net/tcp", pid))
	if err != nil {
		return "", errors.New("route-listener-unavailable")
	}
	inode := ""
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		if f[1] == want || f[1] == fmt.Sprintf("00000000:%04X", port) {
			if inode != "" || f[1] != want {
				return "", errors.New("route-listener-ambiguous")
			}
			inode = f[9]
		}
	}
	if inode == "" || inode == "0" {
		return "", errors.New("route-listener-unavailable")
	}
	fdRoot := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := proc.readDir(fdRoot)
	if err != nil {
		return "", errors.New("route-listener-owner-unavailable")
	}
	for _, entry := range entries {
		link, err := proc.readLink(fdRoot + "/" + entry.Name())
		if err == nil && link == "socket:["+inode+"]" {
			return inode, nil
		}
	}
	return "", errors.New("route-listener-owner-mismatch")
}
