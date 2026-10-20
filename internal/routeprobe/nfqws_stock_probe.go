package routeprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
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
	source  netip.Addr
	policy  string
}

// Read whole bounded rules, never the shortened diagnostic-command output.
func readStockProbePath(ctx context.Context, address netip.Addr, queue int, own string, port int) (stockProbePath, error) {
	return readStockProbePathForSource(ctx, address, queue, own, port, netip.Addr{})
}

func readStockProbePathForSource(ctx context.Context, address netip.Addr, queue int, own string, port int, source netip.Addr) (stockProbePath, error) {
	// This limits observation work, never extends the original caller's
	// admission. The HTTPS client's existing network/TLS budgets are unchanged.
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	save := findSystemBinary([]string{"/opt/sbin/iptables-save", "/opt/bin/iptables-save", "/usr/sbin/iptables-save", "iptables-save"})
	ip := findSystemBinary([]string{"/opt/sbin/ip", "/opt/bin/ip", "/sbin/ip", "ip"})
	if save == "" || ip == "" {
		return stockProbePath{}, errStockProbePath
	}
	rules, err := commandrun.Output(ctx, 4*time.Second, 64<<10, save, "-c", "-t", "mangle")
	if err != nil {
		return stockProbePath{}, errStockProbePath
	}
	args := []string{"-4", "route", "get", address.String()}
	if source.IsValid() {
		args = append(args, "from", source.String())
	}
	route, err := commandrun.Output(ctx, 4*time.Second, 4096, ip, args...)
	if err != nil {
		return stockProbePath{}, errStockProbePath
	}
	initial, err := parseStockProbeRoute(string(route), address)
	if err != nil {
		return stockProbePath{}, err
	}
	if !source.IsValid() {
		// An unbound lookup is only a source-selection hint. Some vendor
		// caches alternate table decoration despite unchanged RPDB/FIB. Bind
		// the socket and both authoritative lookups to this same local source;
		// retain the entire resulting table/path and policy snapshot instead
		// of dropping the table field from either observation.
		source = initial.source
		bound, err := commandrun.Output(ctx, 4*time.Second, 4096, ip, "-4", "route", "get", address.String(), "from", source.String())
		if err != nil {
			return stockProbePath{}, errStockProbePath
		}
		selected, err := parseStockProbeRoute(string(bound), address)
		if err != nil || !sameStockProbeForwarding(initial, selected) {
			return stockProbePath{}, errStockProbePath
		}
		route = bound
	} else if initial.source != source {
		return stockProbePath{}, errStockProbePath
	}
	path, err := inspectStockProbePath(string(rules), string(route), address, queue, own, port)
	if err != nil || !stockProbeLocalSource(path.iface, source) {
		return stockProbePath{}, errStockProbePath
	}
	policy, err := readStockProbePolicy(ctx, ip)
	if err != nil {
		return stockProbePath{}, err
	}
	path.source, path.policy = source, policy
	return path, nil
}

type stockProbeRoute struct {
	source, gateway  netip.Addr
	iface, canonical string
}

func parseStockProbeRoute(raw string, address netip.Addr) (stockProbeRoute, error) {
	refuse := func() (stockProbeRoute, error) { return stockProbeRoute{}, errStockProbePath }
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) != "cache" {
			return refuse()
		}
	}
	f := strings.Fields(lines[0])
	if len(f) < 3 || f[0] != address.String() {
		return refuse()
	}
	r := stockProbeRoute{canonical: strings.Join(f, " ")}
	seen := map[string]bool{}
	for i := 1; i < len(f); i += 2 {
		if i+1 >= len(f) || seen[f[i]] {
			return refuse()
		}
		seen[f[i]] = true
		switch f[i] {
		case "src", "from", "via":
			ip, err := netip.ParseAddr(f[i+1])
			if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				return refuse()
			}
			if f[i] == "via" {
				r.gateway = ip
			} else {
				if r.source.IsValid() && r.source != ip {
					return refuse()
				}
				r.source = ip
			}
		case "dev":
			r.iface = f[i+1]
			if r.iface == "" || r.iface == "lo" {
				return refuse()
			}
		case "table":
			if f[i+1] != "main" {
				if _, err := strconv.ParseUint(f[i+1], 10, 32); err != nil {
					return refuse()
				}
			}
		case "uid", "metric":
			if _, err := strconv.ParseUint(f[i+1], 10, 32); err != nil {
				return refuse()
			}
		default:
			return refuse()
		}
	}
	if !r.source.IsValid() || r.iface == "" {
		return refuse()
	}
	return r, nil
}

func sameStockProbeForwarding(a, b stockProbeRoute) bool {
	return a.source == b.source && a.gateway == b.gateway && a.iface == b.iface
}

func stockProbeLocalSource(iface string, source netip.Addr) bool {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return false
	}
	addresses, err := i.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addresses {
		p, err := netip.ParsePrefix(a.String())
		if err == nil && p.Addr().Unmap() == source {
			return true
		}
	}
	return false
}

// Preserve the actual RPDB and every referenced FIB, including source-specific
// and foreign VPN routes. No table, lifetime or route annotation is discarded.
func readStockProbePolicy(ctx context.Context, ip string) (string, error) {
	rules, err := commandrun.Output(ctx, 4*time.Second, 64<<10, ip, "-4", "rule", "show")
	if err != nil {
		return "", errStockProbePath
	}
	tables := map[string]bool{"main": true}
	for _, line := range strings.Split(string(rules), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "lookup" {
				table := f[i+1]
				if table != "main" && table != "local" && table != "default" {
					if _, e := strconv.ParseUint(table, 10, 32); e != nil {
						return "", errStockProbePath
					}
				}
				tables[table] = true
			}
		}
	}
	if len(tables) > 32 {
		return "", errStockProbePath
	}
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	hash.Write(rules)
	for _, table := range names {
		routes, err := commandrun.Output(ctx, 4*time.Second, 64<<10, ip, "-4", "route", "show", "table", table)
		if err != nil {
			return "", errStockProbePath
		}
		fmt.Fprintf(hash, "\ntable=%s\n", table)
		hash.Write(routes)
	}
	return hex.EncodeToString(hash.Sum(nil)), ctx.Err()
}

// This deliberately recognizes only the official Entware nfqws_post grammar.
// Unknown rules are a refusal, not permission to infer where a socket went.
// No foreign rule, mark or stock chain is modified by this observation.
func inspectStockProbePath(raw, route string, address netip.Addr, queue int, own string, port int) (stockProbePath, error) {
	refuse := func() (stockProbePath, error) { return stockProbePath{}, errStockProbePath }
	selected, err := parseStockProbeRoute(route, address)
	if err != nil {
		return refuse()
	}
	iface := selected.iface
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
	return stockProbePath{passive: iface == stockIface, graph: hex.EncodeToString(hash[:]), route: selected.canonical, packets: packets, iface: iface, source: selected.source}, nil
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
	return before.passive == after.passive && before.graph == after.graph && before.route == after.route && before.source == after.source && before.policy == after.policy
}

func stockProbeSocketConfirmed(before, after stockProbePath, packets uint64) bool {
	return packets > 0 && stockProbeSamePath(before, after) && (!before.passive || after.packets > before.packets)
}

// Closed diagnostic codes only. The same observations still decide proof;
// diagnostics cannot turn a missing counter or changed path into success.
func nfqwsProofRefusal(before, after stockProbePath, packets uint64, counterErr, stockErr, processErr error, queueActive bool, queue, currentQueue int, process, currentProcess string) string {
	switch {
	case counterErr != nil:
		return "nfq-socket-counter-unavailable"
	case packets == 0:
		return "nfq-socket-unobserved"
	case stockErr != nil:
		return "nfq-stock-readback-refused"
	case !queueActive:
		return "nfq-kernel-queue-unavailable"
	case processErr != nil:
		return "nfq-process-readback-refused"
	case queue != currentQueue:
		return "nfq-queue-changed"
	case process != currentProcess:
		return "nfq-process-changed"
	case before.passive != after.passive:
		return "nfq-route-interface-changed"
	case before.graph != after.graph:
		return "nfq-rules-changed"
	case before.route != after.route:
		return "nfq-route-changed"
	case before.source != after.source:
		return "nfq-source-changed"
	case before.policy != after.policy:
		return "nfq-policy-changed"
	case before.passive && after.packets <= before.packets:
		return "nfq-stock-counter-not-advanced"
	default:
		return ""
	}
}
