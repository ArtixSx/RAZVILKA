package dataplane

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func nfqws2ClosedReachableQueueRule(data, config, running []byte, owner string) bool {
	if engineconfig.NFQWSFirstStartRunningAllLAN(config, owner, running) != nil {
		return false
	}
	effective, err := engineconfig.NFQWSFirstStartEffectiveConfig(config, owner)
	queue, ok := nfqws2LiteralQueue(config)
	return err == nil && ok && nfqws2ReachableQueueRule(data, queue) &&
		nfqws2ExpertReachableQueueRule(data, []byte(effective), running)
}

// Closed all-LAN TCP443 first-start keeps its strict queue-only grammar.
func nfqws2ReachableQueueRule(data []byte, queue string) bool {
	rules, ok := nfqws2ReachablePostRules(data, queue)
	if !ok {
		return false
	}
	tcp443 := false
	for _, rule := range rules {
		// No RETURN, foreign jump, or other queue may hide the owned path.
		f := strings.Fields(rule)
		target, number := 0, 0
		tcp, port443 := false, false
		for i := 0; i+1 < len(f); i++ {
			tcp = tcp || f[i] == "-p" && f[i+1] == "tcp"
			if f[i] == "--dports" || f[i] == "--dport" {
				for _, port := range strings.Split(f[i+1], ",") {
					port443 = port443 || port == "443"
				}
			}
			if f[i] == "-j" {
				if f[i+1] != "NFQUEUE" {
					return false
				}
				target++
			}
			if f[i] == "--queue-num" {
				if f[i+1] != queue {
					return false
				}
				number++
			}
		}
		if target != 1 || number != 1 {
			return false
		}
		tcp443 = tcp443 || tcp && port443
	}
	return tcp443
}

// Shared read-only proof of the exact mangle hook, never a global queue search.
func nfqws2ReachablePostRules(data []byte, queue string) ([]string, bool) {
	if len(data) == 0 || len(data) > 1<<20 || !nfqws2QueueRule(data, queue) {
		return nil, false
	}
	chains := map[string][]string{}
	inMangle, complete, seenMangle := false, false, false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			if inMangle || line == "*mangle" && seenMangle {
				return nil, false
			}
			inMangle = line == "*mangle"
			seenMangle = seenMangle || inMangle
			continue
		}
		if !inMangle {
			continue
		}
		if line == "COMMIT" {
			inMangle, complete = false, true
			continue
		}
		f := strings.Fields(line)
		if strings.HasPrefix(line, ":") && len(f) == 3 {
			name := strings.TrimPrefix(f[0], ":")
			if _, duplicate := chains[name]; duplicate {
				return nil, false
			}
			chains[name] = nil
		} else if len(f) >= 4 && f[0] == "-A" {
			if _, declared := chains[f[1]]; !declared {
				return nil, false
			}
			chains[f[1]] = append(chains[f[1]], strings.Join(f[2:], " "))
		} else {
			return nil, false
		}
	}
	if inMangle || !complete {
		return nil, false
	}
	// The ordinary stock owner publishes exactly one unconditional hook.
	hooks := 0
	for _, rule := range chains["POSTROUTING"] {
		f := strings.Fields(rule)
		if len(f) != 2 || f[0] != "-j" {
			return nil, false
		}
		if f[1] == "nfqws_post" {
			hooks++
		} else if child, declared := chains[f[1]]; !declared || len(child) != 0 {
			return nil, false
		}
	}
	if hooks != 1 || len(chains["nfqws_post"]) == 0 {
		return nil, false
	}
	return chains["nfqws_post"], true
}

// Expert compatibility is limited to the stock IPv4 POSTROUTING grammar.
// Scope is literal main/.run data, never arbitrary shell or arbitrary RETURN.
func nfqws2ExpertReachableQueueRule(data, config, running []byte) bool {
	base, _, err := removeManagedBlock(string(config))
	if err != nil || engineconfig.NFQWSRunningConfigMatches(base, string(running)) != nil {
		return false
	}
	main, ok := nfqws2HealthAssignments(base)
	if !ok {
		return false
	}
	run, ok := nfqws2HealthAssignments(string(running))
	if !ok {
		return false
	}
	for _, key := range []string{"ISP_INTERFACE", "NFQUEUE_NUM", "TCP_PORTS", "UDP_PORTS", "POLICY_NAME", "POLICY_EXCLUDE"} {
		value, present := main[key]
		observed, exists := run[key]
		if !present || !exists || value != observed {
			return false
		}
	}
	queue, err := strconv.Atoi(main["NFQUEUE_NUM"])
	if err != nil || queue < 1 || queue > 65535 {
		return false
	}
	mark, present := run["POLICY_MARK"]
	if !present || main["POLICY_EXCLUDE"] != "0" && main["POLICY_EXCLUDE"] != "1" {
		return false
	}
	if mark != "" {
		normalized, ok := nfqws2HealthMark(mark)
		value, mask, _ := strings.Cut(normalized, "/")
		number, err := strconv.ParseUint(value, 0, 32)
		bits, maskErr := strconv.ParseUint(mask, 0, 32)
		// Preserve literal low-bit expert masks as well as the usual stock
		// low-28-bit mask. Reserved processed/excluded bits or an impossible
		// value must not turn a syntactically present queue into a false proof.
		if !ok || err != nil || maskErr != nil || bits == 0 || bits > 0x0fffffff || number & ^bits != 0 {
			return false
		}
	}
	interfaces := strings.Fields(main["ISP_INTERFACE"])
	if len(interfaces) == 0 || len(interfaces) > 16 {
		return false
	}
	tcp, ok := nfqws2HealthPorts(main["TCP_PORTS"])
	if !ok {
		return false
	}
	udp, ok := nfqws2HealthPorts(main["UDP_PORTS"])
	if !ok || tcp == "" && udp == "" {
		return false
	}
	rules, ok := nfqws2ReachablePostRules(data, strconv.Itoa(queue))
	if !ok {
		return false
	}
	expected := []string{}
	seen := map[string]bool{}
	for _, iface := range interfaces {
		if seen[iface] || !nfqws2HealthInterface.MatchString(iface) {
			return false
		}
		seen[iface] = true
		prefix := "-o " + iface
		if mark != "" {
			if main["POLICY_EXCLUDE"] == "1" {
				expected = append(expected, prefix+" -m mark --mark "+mark+" -j RETURN")
			} else {
				expected = append(expected, prefix+" -m mark ! --mark "+mark+" -j CONNMARK --set-xmark 0x20000000/0x20000000",
					prefix+" -m connmark --mark 0x20000000/0x20000000 -j RETURN",
					prefix+" -m mark ! --mark "+mark+" -j RETURN")
			}
		}
		common := prefix + " -m mark ! --mark 0x40000000/0x40000000"
		target := " -j NFQUEUE --queue-num " + strconv.Itoa(queue) + " --queue-bypass"
		if udp != "" {
			expected = append(expected, common+" -p udp -m multiport --dports "+udp+" -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original"+target)
		}
		if tcp != "" {
			expected = append(expected, common+" -p tcp -m multiport --dports "+tcp+" -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original"+target,
				common+" -p tcp -m multiport --dports "+tcp+" --tcp-flags FIN FIN"+target,
				common+" -p tcp -m multiport --dports "+tcp+" --tcp-flags RST RST"+target)
		}
	}
	if len(rules) != len(expected) {
		return false
	}
	for i, rule := range rules {
		actual, ok := nfqws2HealthRule(rule)
		if !ok {
			return false
		}
		want, ok := nfqws2HealthRule(expected[i])
		if !ok || actual != want {
			return false
		}
	}
	return true
}

var nfqws2HealthInterface = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}$`)

// Anchored, sequential assignment matching preserves quoted multiline strategy
// boundaries. Only firewall scope fields must be literal; the admitted engine
// parser above validates the whole main and generated overlay independently.
var nfqws2HealthAssignment = regexp.MustCompile(`(?s)^[ \t]*(?:export[ \t]+)?([a-zA-Z_][a-zA-Z0-9_]*)=(?:'([^']*)'|"((?:[^"\\]|\\.)*)"|([^ \t\r\n]*))[ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)`)

func nfqws2HealthAssignments(raw string) (map[string]string, bool) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, false
	}
	out := map[string]string{}
	for raw != "" {
		raw = strings.TrimLeft(raw, " \t\r\n")
		if raw == "" {
			break
		}
		if raw[0] == '#' {
			_, raw, _ = strings.Cut(raw, "\n")
			continue
		}
		m := nfqws2HealthAssignment.FindStringSubmatch(raw)
		if m == nil || len(m[0]) == 0 {
			return nil, false
		}
		key, value := m[1], m[2]+m[3]+m[4]
		switch key {
		case "ISP_INTERFACE", "NFQUEUE_NUM", "TCP_PORTS", "UDP_PORTS", "POLICY_NAME", "POLICY_EXCLUDE", "POLICY_MARK":
			if _, exists := out[key]; exists || strings.ContainsAny(value, "$`\\\r\n\x00") {
				return nil, false
			}
			out[key] = value
		}
		raw = raw[len(m[0]):]
	}
	return out, true
}

func nfqws2HealthMark(raw string) (string, bool) {
	parts := strings.Split(raw, "/")
	if len(parts) > 2 || len(parts) == 0 {
		return "", false
	}
	value, err := strconv.ParseUint(parts[0], 0, 32)
	if err != nil {
		return "", false
	}
	mask := uint64(0xffffffff)
	if len(parts) == 2 {
		mask, err = strconv.ParseUint(parts[1], 0, 32)
		if err != nil {
			return "", false
		}
	}
	return fmt.Sprintf("0x%x/0x%x", value, mask), true
}

func nfqws2HealthPorts(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 15 {
		return "", false
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		bounds := strings.Split(part, ":")
		if len(bounds) > 2 {
			return "", false
		}
		low, err := strconv.Atoi(bounds[0])
		if err != nil || low < 1 || low > 65535 {
			return "", false
		}
		high := low
		if len(bounds) == 2 {
			high, err = strconv.Atoi(bounds[1])
			if err != nil || high < low || high > 65535 {
				return "", false
			}
		}
		out = append(out, fmt.Sprintf("%05d:%05d", low, high))
	}
	sort.Strings(out)
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return "", false
		}
	}
	// Preserve valid port syntax for generated expected rules.
	canonical := make([]string, 0, len(out))
	for _, part := range out {
		a, b, _ := strings.Cut(part, ":")
		low, _ := strconv.Atoi(a)
		high, _ := strconv.Atoi(b)
		value := strconv.Itoa(low)
		if low != high {
			value += ":" + strconv.Itoa(high)
		}
		canonical = append(canonical, value)
	}
	return strings.Join(canonical, ","), true
}

// Canonicalize only the options emitted by stock _firewall_start. Unknown
// predicates, duplicates and arbitrary jumps cannot be hidden by normalization.
func nfqws2HealthRule(raw string) (string, bool) {
	f := strings.Fields(raw)
	values := map[string]string{}
	modules := map[string]bool{}
	put := func(key, value string) bool {
		if _, exists := values[key]; exists {
			return false
		}
		values[key] = value
		return true
	}
	for i := 0; i < len(f); i++ {
		key := f[i]
		if key == "-m" {
			i++
			if i == len(f) || modules[f[i]] {
				return "", false
			}
			switch f[i] {
			case "mark", "connmark", "multiport", "tcp", "udp", "connbytes":
			default:
				return "", false
			}
			modules[f[i]] = true
			continue
		}
		if key == "--queue-bypass" {
			if !put(key, "true") {
				return "", false
			}
			continue
		}
		negative := false
		if key == "!" {
			i++
			if i == len(f) || f[i] != "--mark" {
				return "", false
			}
			key = f[i]
			negative = true
		}
		i++
		if i == len(f) {
			return "", false
		}
		value := f[i]
		switch key {
		case "--mark", "--set-xmark":
			normalized, ok := nfqws2HealthMark(value)
			if !ok {
				return "", false
			}
			value = normalized
			if negative {
				value = "!" + value
			}
		case "--dport", "--dports":
			key = "ports"
			normalized, ok := nfqws2HealthPorts(value)
			if !ok || normalized == "" {
				return "", false
			}
			value = normalized
		case "--tcp-flags":
			i++
			if i == len(f) {
				return "", false
			}
			a := strings.Split(strings.ToUpper(value), ",")
			b := strings.Split(strings.ToUpper(f[i]), ",")
			sort.Strings(a)
			sort.Strings(b)
			value = strings.Join(a, ",") + "/" + strings.Join(b, ",")
		case "--queue-num":
			number, err := strconv.Atoi(value)
			if err != nil || number < 1 || number > 65535 {
				return "", false
			}
			value = strconv.Itoa(number)
		case "-o", "-p", "-j", "--connbytes", "--connbytes-mode", "--connbytes-dir":
		default:
			return "", false
		}
		if !put(key, value) {
			return "", false
		}
	}
	if _, ok := values["--mark"]; ok {
		// --mark belongs to exactly one of these two stock match extensions.
		if modules["mark"] == modules["connmark"] {
			return "", false
		}
		values["mark-module"] = fmt.Sprint(modules["mark"])
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&canonical, "%s=%s;", key, values[key])
	}
	return canonical.String(), true
}
