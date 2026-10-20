package routeprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/commandrun"
)

var errStockProbePath = errors.New("stock NFQWS2 packet path is not proven")

type stockProbePath struct {
	passive bool
	graph   string
	route   string
	packets uint64
	iface   string
}

// Read whole bounded rules, never the shortened diagnostic-command output.
func readStockProbePath(ctx context.Context, address netip.Addr, queue int, own string, port int) (stockProbePath, error) {
	save := findSystemBinary([]string{"/opt/sbin/iptables-save", "/opt/bin/iptables-save", "/usr/sbin/iptables-save", "iptables-save"})
	ip := findSystemBinary([]string{"/opt/sbin/ip", "/opt/bin/ip", "/sbin/ip", "ip"})
	if save == "" || ip == "" {
		return stockProbePath{}, errStockProbePath
	}
	rules, err := commandrun.Output(ctx, 4*time.Second, 64<<10, save, "-c", "-t", "mangle")
	if err != nil {
		return stockProbePath{}, errStockProbePath
	}
	route, err := commandrun.Output(ctx, 4*time.Second, 4096, ip, "-4", "route", "get", address.String())
	if err != nil {
		return stockProbePath{}, errStockProbePath
	}
	return inspectStockProbePath(string(rules), string(route), address, queue, own, port)
}

// This deliberately recognizes only the official Entware nfqws_post grammar.
// Unknown rules are a refusal, not permission to infer where a socket went.
// No foreign rule, mark or stock chain is modified by this observation.
func inspectStockProbePath(raw, route string, address netip.Addr, queue int, own string, port int) (stockProbePath, error) {
	refuse := func() (stockProbePath, error) { return stockProbePath{}, errStockProbePath }
	first := strings.Fields(strings.Split(strings.TrimSpace(route), "\n")[0])
	if len(first) < 3 || first[0] != address.String() {
		return refuse()
	}
	iface := ""
	for i := 0; i+1 < len(first); i++ {
		if first[i] == "dev" {
			iface = first[i+1]
		}
	}
	if iface == "" || iface == "lo" {
		return refuse()
	}
	chains := map[string][]string{}
	canonical := []string{}
	counts := map[string]uint64{}
	ownRules := []string{}
	ownHooks := []string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var count uint64
		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "] ")
			if end < 0 {
				return refuse()
			}
			var err error
			count, err = strconv.ParseUint(strings.Split(line[1:end], ":")[0], 10, 64)
			if err != nil {
				return refuse()
			}
			line = line[end+2:]
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(line, ":") {
			if len(fields) != 3 {
				return refuse()
			}
			name := strings.TrimPrefix(fields[0], ":")
			chains[name] = nil
			if name == own {
				continue
			}
			line = fields[0] + " " + fields[1] // Chain counters are traffic, not structure.
		} else if len(fields) >= 4 && fields[0] == "-A" {
			if fields[1] == own {
				ownRules = append(ownRules, strings.Join(fields[2:], " "))
				continue
			}
			if ownStockProbeJump(fields, address, port, own, iface) {
				ownHooks = append(ownHooks, fields[1])
				continue
			}
			chains[fields[1]] = append(chains[fields[1]], strings.Join(fields[2:], " "))
			counts[line] = count
		} else if line != "*mangle" && line != "COMMIT" {
			return refuse()
		}
		canonical = append(canonical, line)
	}
	if !strings.Contains(strings.Join(canonical, "\n"), ":POSTROUTING ACCEPT") {
		return refuse()
	}
	// Stock hook must be unconditional. Preceding/succeeding hooks may only be
	// unconditional calls to empty chains: no hidden ACCEPT/RETURN/mark path.
	hooks := 0
	for _, rule := range chains["POSTROUTING"] {
		f := strings.Fields(rule)
		if len(f) != 2 || f[0] != "-j" {
			return refuse()
		}
		if f[1] == "nfqws_post" {
			hooks++
			continue
		}
		if child, exists := chains[f[1]]; !exists || len(child) != 0 {
			return refuse()
		}
	}
	if hooks != 1 {
		return refuse()
	}
	stockIface, packets, matches := "", uint64(0), 0
	for _, rule := range chains["nfqws_post"] {
		f := strings.Fields(rule)
		if len(f) < 4 || f[0] != "-o" || f[2] != "-p" {
			return refuse()
		}
		if f[3] == "udp" {
			continue // Cannot match this fixed TCP probe.
		}
		if f[3] != "tcp" || len(f) < 14 || f[4] != "-m" || f[5] != "mark" || f[6] != "!" || f[7] != "--mark" || f[8] != "0x40000000/0x40000000" || f[9] != "-m" || f[10] != "multiport" || f[11] != "--dports" {
			return refuse()
		}
		ports := strings.Split(f[12], ",")
		if !containsPort443(ports) {
			return refuse()
		}
		prefix := strings.Join(f[:13], " ")
		suffix := strings.Join(f[13:], " ")
		queueTarget := fmt.Sprintf(" -j NFQUEUE --queue-num %d --queue-bypass", queue)
		counted := "-m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original" + queueTarget
		if suffix != counted && suffix != "-m tcp --tcp-flags FIN FIN"+queueTarget && suffix != "-m tcp --tcp-flags RST RST"+queueTarget {
			return refuse()
		}
		if stockIface != "" && stockIface != f[1] {
			return refuse()
		}
		stockIface = f[1]
		if suffix == counted {
			matches++
			packets = counts["-A nfqws_post "+prefix+" "+suffix]
		}
	}
	if matches != 1 {
		return refuse()
	}
	if len(ownRules) > 0 {
		want := "-j RETURN"
		wantHook := "POSTROUTING"
		if iface != stockIface {
			want = fmt.Sprintf("-j NFQUEUE --queue-num %d", queue)
			wantHook = "OUTPUT"
		}
		if len(ownRules) != 1 || ownRules[0] != want || len(ownHooks) != 1 || ownHooks[0] != wantHook {
			return refuse()
		}
	}
	// Reject an OUTPUT path that can change the stock skip mark or enqueue to
	// this queue independently. The official vendor delay queue is distinct.
	if !stockProbeOutputSafe(chains, "OUTPUT", queue, map[string]bool{}) {
		return refuse()
	}
	hash := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return stockProbePath{passive: iface == stockIface, graph: hex.EncodeToString(hash[:]), route: strings.Join(first, " "), packets: packets, iface: iface}, nil
}

// iptables-save canonicalizes option order and adds the implicit tcp module.
// Ignore only this exact owned socket tuple, never merely a jump's chain name.
func ownStockProbeJump(fields []string, address netip.Addr, port int, own, iface string) bool {
	if len(fields) < 2 || fields[0] != "-A" || fields[1] != "OUTPUT" && fields[1] != "POSTROUTING" {
		return false
	}
	want := map[string]string{"-p": "tcp", "-d": address.String() + "/32", "--dport": "443", "--sport": strconv.Itoa(port), "-j": own}
	passive := fields[1] == "POSTROUTING"
	if passive {
		want["-o"], want["--connbytes"], want["--connbytes-mode"], want["--connbytes-dir"] = iface, "1:15", "packets", "original"
	}
	seen := map[string]bool{}
	modules := map[string]bool{}
	negatedMark := false
	for i := 2; i < len(fields); {
		if i+1 >= len(fields) {
			return false
		}
		if fields[i] == "-m" {
			module := fields[i+1]
			if modules[module] || module != "tcp" && (!passive || module != "mark" && module != "connbytes") {
				return false
			}
			modules[module] = true
			i += 2
			continue
		}
		if passive && fields[i] == "!" && i+2 < len(fields) && fields[i+1] == "--mark" && fields[i+2] == "0x40000000/0x40000000" && !negatedMark {
			negatedMark = true
			i += 3
			continue
		}
		if seen[fields[i]] {
			return false
		}
		seen[fields[i]] = true
		if value, exists := want[fields[i]]; !exists || value != fields[i+1] {
			return false
		}
		i += 2
	}
	for key := range want {
		if !seen[key] {
			return false
		}
	}
	return !passive || negatedMark && modules["mark"] && modules["connbytes"]
}

func scopedNFQProbeJump(address netip.Addr, port int, chain string, path stockProbePath) (string, []string) {
	hook := "OUTPUT"
	args := []string{"-p", "tcp", "-d", address.String(), "--dport", "443", "--sport", strconv.Itoa(port)}
	if path.passive {
		hook = "POSTROUTING"
		args = append(args, "-o", path.iface, "-m", "mark", "!", "--mark", "0x40000000/0x40000000", "-m", "connbytes", "--connbytes", "1:15", "--connbytes-mode", "packets", "--connbytes-dir", "original")
	}
	return hook, append(args, "-j", chain)
}

func containsPort443(ports []string) bool {
	for _, port := range ports {
		if port == "443" {
			return true
		}
	}
	return false
}

func stockProbeOutputSafe(chains map[string][]string, chain string, queue int, seen map[string]bool) bool {
	if seen[chain] {
		return false
	}
	seen[chain] = true
	defer delete(seen, chain)
	for _, rule := range chains[chain] {
		f := strings.Fields(rule)
		if len(f) >= 2 && f[0] == "-p" && f[1] == "udp" {
			continue
		}
		if len(f) == 2 && f[0] == "-j" {
			if _, exists := chains[f[1]]; exists && stockProbeOutputSafe(chains, f[1], queue, seen) {
				continue
			}
		}
		// Known firmware delay hook; no MARK/CONNMARK and not the NFQWS queue.
		vendor := "! -s 127.0.0.1/32 ! -d 127.0.0.1/32 -m ndmmark --ndmmark 0x0/0x80 -j NFQUEUE --queue-num 64511"
		if chain == "_NDM_OUTPUT_DELAY" && rule == vendor && queue != 64511 {
			continue
		}
		return false
	}
	return true
}

func stockProbeSamePath(before, after stockProbePath) bool {
	return before.passive == after.passive && before.graph == after.graph && before.route == after.route
}

func stockProbeSocketConfirmed(before, after stockProbePath, packets uint64) bool {
	return packets > 0 && stockProbeSamePath(before, after) && (!before.passive || after.packets > before.packets)
}
