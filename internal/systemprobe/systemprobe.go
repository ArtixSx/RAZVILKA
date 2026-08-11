package systemprobe

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Snapshot struct {
	Architecture       string   `json:"architecture"`
	Kernel             string   `json:"kernel,omitempty"`
	Hostname           string   `json:"hostname,omitempty"`
	MemTotalKB         uint64   `json:"mem_total_kb,omitempty"`
	MemAvailableKB     uint64   `json:"mem_available_kb,omitempty"`
	OptReady           bool     `json:"opt_ready"`
	Opkg               bool     `json:"opkg"`
	IPCommand          bool     `json:"ip_command"`
	WANInterface       string   `json:"wan_interface,omitempty"`
	TUN                bool     `json:"tun"`
	IPTables           bool     `json:"iptables"`
	IP6Tables          bool     `json:"ip6tables"`
	NFTables           bool     `json:"nftables"`
	NFQueue            bool     `json:"nfqueue"`
	ExternalTunnels    []string `json:"external_tunnels,omitempty"`
	RouteContamination bool     `json:"route_contamination"`
}

func Probe() Snapshot {
	s := Snapshot{Architecture: runtime.GOARCH}
	if h, err := os.Hostname(); err == nil {
		s.Hostname = h
	}
	s.Kernel = commandOutput("uname", "-r")
	s.MemTotalKB, s.MemAvailableKB = memory()
	if st, err := os.Stat("/opt"); err == nil && st.IsDir() {
		s.OptReady = true
	}
	s.Opkg = commandExists("opkg") || fileExists("/opt/bin/opkg")
	s.IPCommand = commandExists("ip") || fileExists("/opt/sbin/ip") || fileExists("/opt/bin/ip")
	s.IPTables = commandExists("iptables") || fileExists("/opt/sbin/iptables")
	s.IP6Tables = commandExists("ip6tables") || fileExists("/opt/sbin/ip6tables")
	s.NFTables = commandExists("nft") || fileExists("/opt/sbin/nft")
	s.TUN = fileExists("/dev/net/tun")
	s.NFQueue = nfqueueAvailable()
	s.WANInterface = wanInterface()
	s.ExternalTunnels = externalTunnels()
	s.RouteContamination = len(s.ExternalTunnels) > 0
	return s
}

func commandExists(name string) bool { _, err := exec.LookPath(name); return err == nil }
func fileExists(path string) bool    { st, err := os.Stat(path); return err == nil && !st.IsDir() }
func commandOutput(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func memory() (total, available uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			total = v
		case "MemAvailable":
			available = v
		}
	}
	return
}
func nfqueueAvailable() bool {
	for _, p := range []string{"/proc/net/ip_tables_targets", "/proc/modules"} {
		if b, err := os.ReadFile(p); err == nil {
			t := strings.ToLower(string(b))
			if strings.Contains(t, "nfqueue") || strings.Contains(t, "nfnetlink_queue") {
				return true
			}
		}
	}
	return false
}
func externalTunnels() []string {
	cmds := [][]string{{"ip", "route", "show"}, {"/opt/sbin/ip", "route", "show"}, {"/opt/bin/ip", "route", "show"}}
	for _, c := range cmds {
		if c[0][0] == '/' && !fileExists(c[0]) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		b, err := exec.CommandContext(ctx, c[0], c[1:]...).Output()
		cancel()
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		var out []string
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			for i := 0; i+1 < len(f); i++ {
				if f[i] != "dev" {
					continue
				}
				dev := f[i+1]
				if isExternalTunnelName(dev) && !seen[dev] {
					seen[dev] = true
					out = append(out, dev)
				}
			}
		}
		return out
	}
	return nil
}

func isExternalTunnelName(dev string) bool {
	prefixes := []string{"nwg", "wg", "tun", "tap", "opkgtun", "awg"}
	for _, p := range prefixes {
		if strings.HasPrefix(dev, p) {
			rest := strings.TrimPrefix(dev, p)
			if rest == "" {
				return true
			}
			if _, err := strconv.Atoi(rest); err == nil {
				return true
			}
		}
	}
	return false
}

func wanInterface() string {
	candidates := [][]string{{"ip", "route", "get", "1.1.1.1"}, {"/opt/sbin/ip", "route", "get", "1.1.1.1"}, {"/opt/bin/ip", "route", "get", "1.1.1.1"}}
	for _, c := range candidates {
		if c[0][0] == '/' && !fileExists(c[0]) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		b, err := exec.CommandContext(ctx, c[0], c[1:]...).Output()
		cancel()
		if err != nil {
			continue
		}
		f := strings.Fields(string(b))
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				return f[i+1]
			}
		}
	}
	return ""
}
