package systemprobe

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type WANProfile struct {
	ID           string `json:"id"`
	WANInterface string `json:"wan_interface,omitempty"`
}

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
	NetworkProfileID   string   `json:"network_profile_id,omitempty"`
	TUN                bool     `json:"tun"`
	IPTables           bool     `json:"iptables"`
	IP6Tables          bool     `json:"ip6tables"`
	NFTables           bool     `json:"nftables"`
	NFQueue            bool     `json:"nfqueue"`
	IPSet              bool     `json:"ipset"`
	TProxy             bool     `json:"tproxy"`
	SocketMatch        bool     `json:"socket_match"`
	Conntrack          bool     `json:"conntrack"`
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
	s.IPSet = commandExists("ipset") || fileExists("/opt/sbin/ipset") || fileExists("/opt/bin/ipset")
	s.TProxy = kernelFeatureAvailable("tproxy", "/proc/net/ip_tables_targets", "/proc/modules")
	s.SocketMatch = kernelFeatureAvailable("socket", "/proc/net/ip_tables_matches", "/proc/modules")
	s.Conntrack = commandExists("conntrack") || fileExists("/opt/sbin/conntrack") || fileExists("/opt/bin/conntrack") || fileExists("/proc/net/nf_conntrack")
	profile := DetectWANProfile()
	s.WANInterface = profile.WANInterface
	s.NetworkProfileID = profile.ID
	s.ExternalTunnels = externalTunnels()
	s.RouteContamination = len(s.ExternalTunnels) > 0
	return s
}

// DetectWANInterface performs only the route lookup needed by the bounded
// traffic sampler. Full Probe also inspects packages, modules and tunnels and
// would be unnecessarily expensive on every metrics interval.
func DetectWANInterface() string { return DetectWANProfile().WANInterface }

var wanProfileCache struct {
	sync.Mutex
	profile WANProfile
	at      time.Time
}

// DetectWANProfile returns a privacy-safe identifier for the current uplink.
// The gateway and source address are used only as local hash input and are
// never persisted or returned to the Web UI.
func DetectWANProfile() WANProfile {
	wanProfileCache.Lock()
	defer wanProfileCache.Unlock()
	if !wanProfileCache.at.IsZero() && time.Since(wanProfileCache.at) < 10*time.Second {
		return wanProfileCache.profile
	}
	profile := WANProfile{ID: "network-unknown"}
	if line := wanRouteLine(); line != "" {
		profile = networkProfileFromRoute(line)
	}
	wanProfileCache.profile = profile
	wanProfileCache.at = time.Now()
	return profile
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
	return kernelFeatureAvailable("nfqueue", "/proc/net/ip_tables_targets") || kernelFeatureAvailable("nfnetlink_queue", "/proc/modules")
}

func kernelFeatureAvailable(feature string, paths ...string) bool {
	feature = strings.ToLower(strings.TrimSpace(feature))
	if feature == "" {
		return false
	}
	for _, path := range paths {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(strings.ToLower(string(b)), feature) {
			return true
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

func wanInterface() string { return DetectWANProfile().WANInterface }

func wanRouteLine() string {
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
		return strings.TrimSpace(string(b))
	}
	return ""
}

func networkProfileFromRoute(line string) WANProfile {
	fields := strings.Fields(line)
	values := map[string]string{}
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "dev", "via", "src":
			values[fields[i]] = fields[i+1]
		}
	}
	dev := strings.TrimSpace(values["dev"])
	if dev == "" {
		return WANProfile{ID: "network-unknown"}
	}
	identity := dev + "|" + values["via"]
	if values["via"] == "" {
		identity += "|" + values["src"]
	}
	digest := sha256.Sum256([]byte(identity))
	return WANProfile{ID: fmt.Sprintf("wan-%x", digest[:6]), WANInterface: dev}
}
