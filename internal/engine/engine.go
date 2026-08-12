package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Status struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}
type Detector struct{}

func (Detector) All() []Status {
	return []Status{
		detect("nfqws2", "NFQWS2", "dpi", []string{"/opt/usr/bin/nfqws2", "/opt/bin/nfqws2", "/usr/bin/nfqws2"}, []string{"/opt/etc/init.d/S51nfqws2"}, "Локальный DPI bypass · без внешнего сервера"),
		detect("usque", "WARP · MASQUE", "masque", []string{"/opt/usr/bin/usque", "/opt/bin/usque", "/usr/bin/usque"}, []string{"/opt/etc/init.d/S51usque"}, "Cloudflare WARP через MASQUE / CONNECT-IP"),
		detectFile("warp-wg", "WARP · WireGuard", "warp", []string{"/opt/etc/razvilka/warp/wgcf-profile.conf", "/opt/etc/wireguard/warp.conf"}, "Резервный WARP транспорт через WireGuard профиль"),
		detect("sing-box", "Sing-box", "proxy", []string{"/opt/bin/sing-box", "/opt/usr/bin/sing-box", "/usr/bin/sing-box"}, []string{"/opt/etc/init.d/S99sing-box", "/opt/etc/init.d/S51sing-box"}, "VLESS / Reality / Hysteria2 / TUIC / Shadowsocks"),
		detect("xray", "Xray", "proxy", []string{"/opt/bin/xray", "/opt/usr/bin/xray", "/usr/bin/xray"}, []string{"/opt/etc/init.d/S99xray", "/opt/etc/init.d/S51xray"}, "Дополнительные Xray транспорты"),
		detectFile("amneziawg", "AmneziaWG", "vpn", []string{"/opt/etc/amnezia/amneziawg.conf", "/opt/etc/wireguard/awg.conf"}, "Опциональный AmneziaWG туннель"),
	}
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
