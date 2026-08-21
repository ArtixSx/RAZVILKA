package engine

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Status struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Installed    bool      `json:"installed"`
	Configured   bool      `json:"configured"`
	RuntimeReady bool      `json:"runtime_ready"`
	Running      bool      `json:"running"`
	Kind         string    `json:"kind"`
	Description  string    `json:"description"`
	BinaryPath   string    `json:"binary_path,omitempty"`
	Version      string    `json:"version,omitempty"`
	Architecture string    `json:"architecture"`
	Capabilities []string  `json:"capabilities"`
	NativeCheck  bool      `json:"native_check"`
	Ownership    Ownership `json:"ownership"`
	External     bool      `json:"external"`
	ManagedBy    string    `json:"managed_by,omitempty"`
}

// Ownership describes kernel/network resources an adapter may claim. Empty
// lists are intentional: the manager must not imply ownership it cannot prove.
type Ownership struct {
	Ports      []string `json:"ports"`
	Interfaces []string `json:"interfaces"`
	NFQueues   []string `json:"nfqueues"`
}

type specification struct {
	id, name, kind, description               string
	binaries, binaryNames, initScripts, files []string
	capabilities                              []string
	nativeCheck                               bool
	ownership                                 Ownership
}
type Detector struct{}

func specifications() []specification {
	return []specification{
		{id: "nfqws2", name: "NFQWS2", kind: "dpi", binaries: []string{"/opt/usr/bin/nfqws2", "/opt/bin/nfqws2", "/usr/bin/nfqws2"}, binaryNames: []string{"nfqws2"}, files: []string{"/opt/etc/nfqws2/nfqws2.conf"}, initScripts: []string{"/opt/etc/init.d/S51nfqws2"}, description: "Локальный DPI bypass · без внешнего сервера", capabilities: []string{"dpi-desync", "tcp", "udp", "nfqueue"}, nativeCheck: true, ownership: Ownership{NFQueues: []string{"dynamic:config"}}},
		{id: "z2k", name: "z2k · Zapret2", kind: "external", binaries: []string{"/opt/zapret2/nfq2/nfqws2", "/opt/zapret2/binaries/linux-arm64/nfqws2"}, binaryNames: []string{"nfqws2"}, files: []string{"/opt/zapret2/config"}, initScripts: []string{"/opt/etc/init.d/S99zapret2"}, description: "Внешний обход Zapret2: стратегии TCP/QUIC и собственный NFQUEUE", capabilities: []string{"dpi-desync", "tcp", "udp", "quic", "nfqueue", "external-owner"}, nativeCheck: true, ownership: Ownership{NFQueues: []string{"external:z2k"}}},
		{id: "usque", name: "WARP · MASQUE", kind: "masque", binaries: []string{"/opt/usr/bin/usque", "/opt/bin/usque", "/usr/bin/usque"}, binaryNames: []string{"usque"}, files: []string{"/opt/etc/usque/session.conf", "/opt/etc/usque/config.json", "/opt/var/lib/usque/config.json"}, initScripts: []string{"/opt/etc/init.d/S51usque"}, description: "Cloudflare WARP через MASQUE / CONNECT-IP", capabilities: []string{"masque", "connect-ip", "socks"}, ownership: Ownership{Ports: []string{"dynamic:config"}, Interfaces: []string{"dynamic:config"}}},
		{id: "warp-wg", name: "WARP · WireGuard", kind: "warp", binaries: []string{"/opt/bin/wg", "/opt/usr/bin/wg", "/usr/bin/wg"}, binaryNames: []string{"wg"}, files: []string{"/opt/etc/razvilka/warp/wgcf-profile.conf", "/opt/etc/wireguard/warp.conf"}, description: "Резервный WARP транспорт через WireGuard профиль", capabilities: []string{"wireguard", "udp", "tun"}, ownership: Ownership{Interfaces: []string{"dynamic:config"}}},
		{id: "sing-box", name: "Sing-box", kind: "proxy", binaries: []string{"/opt/bin/sing-box", "/opt/usr/bin/sing-box", "/usr/bin/sing-box"}, binaryNames: []string{"sing-box"}, files: []string{"/opt/etc/sing-box/config.json", "/opt/etc/singbox/config.json", "/opt/etc/sing-box.json"}, initScripts: []string{"/opt/etc/init.d/S99sing-box", "/opt/etc/init.d/S51sing-box"}, description: "VLESS / Reality / Hysteria2 / TUIC / Shadowsocks", capabilities: []string{"proxy", "tun", "tcp", "udp", "native-check"}, nativeCheck: true, ownership: Ownership{Ports: []string{"dynamic:config"}, Interfaces: []string{"dynamic:config"}}},
		{id: "xray", name: "Xray", kind: "proxy", binaries: []string{"/opt/bin/xray", "/opt/usr/bin/xray", "/usr/bin/xray"}, binaryNames: []string{"xray"}, files: []string{"/opt/etc/xray/config.json", "/opt/etc/xray.json"}, initScripts: []string{"/opt/etc/init.d/S99xray", "/opt/etc/init.d/S51xray"}, description: "Дополнительные Xray транспорты", capabilities: []string{"proxy", "tcp", "udp", "native-check"}, nativeCheck: true, ownership: Ownership{Ports: []string{"dynamic:config"}}},
		{id: "amneziawg", name: "AmneziaWG", kind: "vpn", binaries: []string{"/opt/bin/awg", "/opt/bin/awg-quick", "/opt/usr/bin/awg", "/usr/bin/awg"}, binaryNames: []string{"awg", "awg-quick"}, files: []string{"/opt/etc/amnezia/amneziawg.conf", "/opt/etc/wireguard/awg.conf"}, description: "Опциональный AmneziaWG туннель", capabilities: []string{"wireguard", "udp", "tun"}, ownership: Ownership{Interfaces: []string{"dynamic:config"}}},
	}
}

func (Detector) All() []Status {
	specs := specifications()
	out := make([]Status, 0, len(specs))
	for _, spec := range specs {
		out = append(out, detectSpec(spec))
	}
	return out
}

// Visible returns only bypasses managed or configured through RAZVILKA. The
// detector keeps external owners such as z2k in its private inventory so
// dataplane preflight can prevent two NFQWS2/NFQUEUE owners from running at
// once, but an external owner is not a second selectable bypass.
func Visible(statuses []Status) []Status {
	out := make([]Status, 0, len(statuses))
	for _, status := range statuses {
		if status.External || status.ID == "z2k" {
			continue
		}
		out = append(out, status)
	}
	return out
}

// Inventory is the low-latency selector/readiness view. Unlike All it never
// starts version commands or init scripts, so a Services or Plan refresh cannot
// stall for several seconds on a slow router binary. Engine Lab still uses All
// when exact version/native lifecycle evidence is explicitly requested.
func (Detector) Inventory() []Status {
	specs := specifications()
	out := make([]Status, 0, len(specs))
	for _, spec := range specs {
		path := findSpecBinary(spec)
		installed := path != ""
		configured := anyFile(spec.files)
		running := false
		if spec.id == "warp-wg" || spec.id == "amneziawg" {
			running = tunnelActive(spec.files)
		} else if len(spec.binaries) > 0 {
			running = specProcessRunning(spec, true)
		}
		out = append(out, Status{
			ID: spec.id, Name: spec.name, Installed: installed, Configured: configured, RuntimeReady: installed && configured, Running: running, Kind: spec.kind,
			Description: spec.description, BinaryPath: path, Architecture: runtime.GOARCH,
			Capabilities: nonNil(spec.capabilities), NativeCheck: spec.nativeCheck && path != "", Ownership: normalizedOwnership(spec.ownership), External: spec.kind == "external", ManagedBy: managedBy(spec),
		})
	}
	return out
}

func detectSpec(spec specification) Status {
	path := findSpecBinary(spec)
	installed := path != ""
	configured := anyFile(spec.files)
	running := false
	if spec.id == "warp-wg" || spec.id == "amneziawg" {
		running = tunnelActive(spec.files)
	} else if len(spec.binaries) > 0 {
		running = specProcessRunning(spec, false)
	}
	if !running {
		for _, p := range spec.initScripts {
			if fileExists(p) && initRunning(p) {
				running = true
				break
			}
		}
	}
	version := ""
	if path != "" {
		version = detectVersion(path)
		if spec.id == "z2k" {
			version = z2kVersion(version)
		}
	}
	return Status{ID: spec.id, Name: spec.name, Installed: installed, Configured: configured, RuntimeReady: installed && configured, Running: running, Kind: spec.kind, Description: spec.description, BinaryPath: path, Version: version, Architecture: runtime.GOARCH, Capabilities: nonNil(spec.capabilities), NativeCheck: spec.nativeCheck && path != "", Ownership: normalizedOwnership(spec.ownership), External: spec.kind == "external", ManagedBy: managedBy(spec)}
}

func managedBy(spec specification) string {
	if spec.id == "z2k" {
		return "z2k"
	}
	return "razvilka"
}

func specProcessRunning(spec specification, fast bool) bool {
	if spec.id == "z2k" {
		return processPathContains("/opt/zapret2/")
	}
	if spec.id == "nfqws2" {
		if processNamedOutside("nfqws2", "/opt/zapret2/") || processNamedOutside("nfqws", "/opt/zapret2/") {
			return true
		}
		return false
	}
	if fast {
		return processRunningProc(spec.id)
	}
	return processRunning(spec.id)
}

func z2kVersion(zapretVersion string) string {
	tag := ""
	if data, err := os.ReadFile("/opt/zapret2/.z2k-installed-tag"); err == nil {
		tag = firstLine(string(data))
	}
	if tag == "" {
		return zapretVersion
	}
	if zapretVersion == "" {
		return tag
	}
	return firstLine(tag + " · " + zapretVersion)
}

func findSpecBinary(spec specification) string {
	for _, name := range spec.binaryNames {
		if path := findBinary(spec.binaries, name); path != "" {
			return path
		}
	}
	return findBinary(spec.binaries, spec.id)
}

func anyFile(paths []string) bool {
	for _, path := range paths {
		if fileExists(path) {
			return true
		}
	}
	return false
}

func tunnelActive(paths []string) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	active := map[string]bool{}
	for _, item := range interfaces {
		addresses, _ := item.Addrs()
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil {
				active[ip.String()] = true
			}
		}
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 2<<20 {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "Address") {
				continue
			}
			for _, candidate := range strings.Split(value, ",") {
				ip, _, parseErr := net.ParseCIDR(strings.TrimSpace(candidate))
				if parseErr == nil && active[ip.String()] {
					return true
				}
			}
		}
	}
	return false
}

func findBinary(paths []string, fallback string) string {
	for _, p := range paths {
		if fileExists(p) {
			return p
		}
	}
	if p, err := exec.LookPath(fallback); err == nil {
		return p
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func detectVersion(path string) string {
	for _, arg := range []string{"--version", "version", "-v"} {
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		out, err := exec.CommandContext(ctx, path, arg).CombinedOutput()
		cancel()
		if err == nil {
			if line := selectVersionLine(string(out), filepath.Base(path)); line != "" {
				return line
			}
		}
	}
	return ""
}

var semanticVersionPattern = regexp.MustCompile(`(?i)\bv?\d+\.\d+(?:\.\d+)?(?:[-+][0-9a-z.-]+)?\b`)

func selectVersionLine(output, binaryName string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	binaryName = strings.ToLower(strings.TrimSpace(binaryName))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if semanticVersionPattern.MatchString(trimmed) && binaryName != "" && strings.Contains(strings.ToLower(trimmed), binaryName) {
			return firstLine(trimmed)
		}
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if semanticVersionPattern.MatchString(trimmed) {
			return firstLine(trimmed)
		}
	}
	return ""
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if i := strings.IndexByte(value, '\n'); i >= 0 {
		value = value[:i]
	}
	value = strings.TrimSpace(value)
	if len(value) > 160 {
		value = value[:160]
	}
	return value
}

func initRunning(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "status").CombinedOutput()
	return err == nil && statusLooksRunning(string(out))
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
func normalizedOwnership(v Ownership) Ownership {
	v.Ports = nonNil(v.Ports)
	v.Interfaces = nonNil(v.Interfaces)
	v.NFQueues = nonNil(v.NFQueues)
	return v
}
func detect(id, name, kind string, bins, initScripts []string, desc string) Status {
	installed := false
	for _, p := range bins {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			installed = true
			break
		}
	}
	if !installed {
		if _, err := exec.LookPath(id); err == nil {
			installed = true
		}
	}
	running := processRunning(id)
	if !running && id == "nfqws2" {
		running = processRunning("nfqws")
	}
	if !running {
		for _, p := range initScripts {
			if _, err := os.Stat(p); err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				out, statusErr := exec.CommandContext(ctx, p, "status").CombinedOutput()
				cancel()
				if statusErr == nil && statusLooksRunning(string(out)) {
					running = true
					break
				}
			}
		}
	}
	return Status{ID: id, Name: name, Installed: installed, Running: running, Kind: kind, Description: desc}
}
func detectFile(id, name, kind string, paths []string, desc string) Status {
	installed := false
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			installed = true
			break
		}
	}
	return Status{ID: id, Name: name, Installed: installed, Running: false, Kind: kind, Description: desc}
}
func processRunning(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	if processRunningProc(name) {
		return true
	}
	out, err := exec.Command("ps").Output()
	if err != nil {
		return false
	}
	return processListHasName(string(out), name)
}

func processRunningProc(name string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		root := filepath.Join("/proc", entry.Name())
		if b, err := os.ReadFile(filepath.Join(root, "comm")); err == nil && executableName(string(b)) == name {
			return true
		}
		if b, err := os.ReadFile(filepath.Join(root, "cmdline")); err == nil {
			command, _, _ := strings.Cut(string(b), "\x00")
			if executableName(command) == name {
				return true
			}
		}
	}
	return false
}

func processPathContains(fragment string) bool {
	fragment = strings.ToLower(filepath.Clean(fragment))
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline")); err == nil {
			command, _, _ := strings.Cut(string(data), "\x00")
			if strings.Contains(strings.ToLower(filepath.Clean(command)), fragment) {
				return true
			}
		}
	}
	return false
}

func processNamedOutside(name, excludedPath string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	excludedPath = strings.ToLower(filepath.Clean(excludedPath))
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		command, _, _ := strings.Cut(string(data), "\x00")
		cleaned := strings.ToLower(filepath.Clean(command))
		if executableName(command) == name && !strings.Contains(cleaned, excludedPath) {
			return true
		}
	}
	return false
}

func processListHasName(output, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.EqualFold(fields[0], "pid") {
			continue
		}
		for _, field := range fields[1:] {
			candidate := executableName(field)
			isCommand := strings.ContainsAny(field, "/\\") || strings.HasPrefix(field, "[") || candidate == name
			if !isCommand {
				continue
			}
			if candidate == name {
				return true
			}
			break
		}
	}
	return false
}

func executableName(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]()")
	return strings.ToLower(filepath.Base(value))
}

func statusLooksRunning(output string) bool {
	status := strings.ToLower(strings.TrimSpace(output))
	for _, negative := range []string{"not running", "not started", "stopped", "inactive", "dead", "failed"} {
		if strings.Contains(status, negative) {
			return false
		}
	}
	for _, positive := range []string{"running", "started", "active"} {
		if strings.Contains(status, positive) {
			return true
		}
	}
	return false
}
