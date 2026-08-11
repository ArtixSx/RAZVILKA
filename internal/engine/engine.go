package engine

import (
	"os"
	"os/exec"
	"strings"
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
				out, _ := exec.Command(p, "status").CombinedOutput()
				s := strings.ToLower(string(out))
				if strings.Contains(s, "running") || strings.Contains(s, "started") || strings.Contains(s, "active") {
					running = true
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
	out, err := exec.Command("ps").Output()
	if err != nil {
		return false
	}
	needle := strings.ToLower(name)
	for _, line := range strings.Split(strings.ToLower(string(out)), "\n") {
		if strings.Contains(line, needle) && !strings.Contains(line, "grep ") {
			return true
		}
	}
	return false
}
