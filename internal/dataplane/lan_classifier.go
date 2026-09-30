package dataplane

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The LAN classifier is the kernel part of the whole-internet path
// (docs/plans/v2-all-internet-2026-09-29/ALL_INTERNET_EXECUTOR_RU.md).
//
// Excluded devices skip every RAZVILKA route through one early rule:
// "from <device> goto <anchor>" jumps over the adapters' service slots
// (priorities 60–71) to the anchor, after which the firmware's own policy
// rules (100+) and main apply unchanged; nothing is forced to main.
//
// The default path marks, in its own mangle chain, the LAN ingress traffic
// that no earlier rule classified: packets another chain already marked
// (Keenetic policies, domain routing) are left alone, then excluded devices,
// local and private destinations and direct sites return unmarked. The mark
// selects the tunnel table at the anchor priority, after all service rules,
// so a service with its own route still wins. Without routes in the tunnel
// table the lookup falls through to main: traffic passes directly (the
// owner's fail-open decision). Router-originated traffic is never marked.
const (
	lanClassifierMark         = 0x10000000
	lanClassifierSkipPriority = 59
	lanClassifierPriority     = 72
	maxLANClassifierIngress   = 4
	maxLANClassifierSources   = 128
	maxLANClassifierMACs      = 128
	maxLANClassifierDirect    = 512
)

var (
	lanClassifierChainPattern = regexp.MustCompile(`^RZC_[0-9a-f]{12}$`)
	lanClassifierMAC          = regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){5}$`)
)

// LANClassifierState is recorded intent; it grants no route by itself.
type LANClassifierState struct {
	Chain              string   `json:"chain"`
	Ingress            []string `json:"ingress"`
	ExcludedSources    []string `json:"excluded_sources,omitempty"`
	ExcludedMACs       []string `json:"excluded_macs,omitempty"`
	DirectDestinations []string `json:"direct_destinations,omitempty"`
	DefaultTable       int      `json:"default_table,omitempty"` // 0: exclusions only
}

// Local, private and special-purpose destinations never take the default path.
var lanClassifierLocal = map[bool][]string{
	false: {"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"},
	true:  {"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"},
}

func validLANClassifier(state LANClassifierState) error {
	if !lanClassifierChainPattern.MatchString(state.Chain) {
		return errors.New("invalid LAN classifier chain")
	}
	if len(state.Ingress) == 0 || len(state.Ingress) > maxLANClassifierIngress {
		return errors.New("LAN classifier needs 1..4 ingress interfaces")
	}
	seen := map[string]bool{}
	for _, name := range state.Ingress {
		if !proxyFirewallInterface.MatchString(name) || strings.Contains(name, "+") || seen[name] {
			return errors.New("invalid LAN classifier ingress")
		}
		seen[name] = true
	}
	if len(state.ExcludedSources) > maxLANClassifierSources || len(state.ExcludedMACs) > maxLANClassifierMACs || len(state.DirectDestinations) > maxLANClassifierDirect {
		return errors.New("LAN classifier bound exceeded")
	}
	for _, list := range [][]string{state.ExcludedSources, state.DirectDestinations} {
		seen := map[string]bool{}
		for _, value := range list {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix.Bits() == 0 || seen[value] {
				return errors.New("invalid LAN classifier prefix")
			}
			seen[value] = true
		}
	}
	macs := map[string]bool{}
	for _, mac := range state.ExcludedMACs {
		if !lanClassifierMAC.MatchString(mac) || macs[mac] {
			return errors.New("invalid LAN classifier MAC")
		}
		if hw, err := net.ParseMAC(mac); err != nil || hw[0]&1 != 0 {
			return errors.New("invalid LAN classifier MAC")
		}
		macs[mac] = true
	}
	if state.DefaultTable != 0 && (state.DefaultTable < 1 || state.DefaultTable > 252) {
		return errors.New("invalid LAN classifier table")
	}
	if state.DefaultTable == 0 && (len(state.ExcludedSources) == 0 || len(state.ExcludedMACs) > 0 || len(state.DirectDestinations) > 0) {
		// Without a default path only source exclusions have an effect: MAC
		// and site exclusions need the classifier chain.
		return errors.New("LAN classifier without a default path accepts only excluded addresses")
	}
	return nil
}

// lanClassifierChainRules lists the mangle chain specifications in order,
// exactly as iptables -S prints them. No chain exists without a default path.
func lanClassifierChainRules(state LANClassifierState, v6 bool) [][]string {
	if state.DefaultTable == 0 {
		return nil
	}
	rules := [][]string{{"-m", "mark", "!", "--mark", "0x0", "-j", "RETURN"}}
	family := func(value string) bool { return strings.Contains(value, ":") == v6 }
	for _, source := range state.ExcludedSources {
		if family(source) {
			rules = append(rules, []string{"-s", source, "-j", "RETURN"})
		}
	}
	for _, mac := range state.ExcludedMACs {
		rules = append(rules, []string{"-m", "mac", "--mac-source", mac, "-j", "RETURN"})
	}
	for _, destination := range lanClassifierLocal[v6] {
		rules = append(rules, []string{"-d", destination, "-j", "RETURN"})
	}
	for _, destination := range state.DirectDestinations {
		if family(destination) {
			rules = append(rules, []string{"-d", destination, "-j", "RETURN"})
		}
	}
	mark := fmt.Sprintf("0x%x/0x%x", lanClassifierMark, lanClassifierMark)
	return append(rules, []string{"-j", "MARK", "--set-xmark", mark})
}

// lanClassifierJumps attaches the chain at the tail of mangle PREROUTING for
// LAN ingress only: firmware chains run first and keep their marks.
func lanClassifierJumps(state LANClassifierState) [][]string {
	if state.DefaultTable == 0 {
		return nil
	}
	jumps := make([][]string, 0, len(state.Ingress))
	for _, ingress := range state.Ingress {
		jumps = append(jumps, []string{"-i", ingress, "-j", state.Chain})
	}
	return jumps
}

type lanClassifierRule struct {
	family   int
	priority int
	source   string // "all" or a prefix
	action   string // "goto 72", "nop", "fwmark ... lookup N"
}

// lanClassifierPolicyRules lists the ip rules. The anchor exists whenever a
// goto needs a target: the kernel skips a goto to an absent priority.
func lanClassifierPolicyRules(state LANClassifierState) []lanClassifierRule {
	var rules []lanClassifierRule
	families := map[int]bool{}
	for _, source := range state.ExcludedSources {
		family := 4
		if strings.Contains(source, ":") {
			family = 6
		}
		families[family] = true
		rules = append(rules, lanClassifierRule{family: family, priority: lanClassifierSkipPriority, source: source, action: "goto " + strconv.Itoa(lanClassifierPriority)})
	}
	for _, family := range []int{4, 6} {
		if state.DefaultTable != 0 {
			rules = append(rules, lanClassifierRule{family: family, priority: lanClassifierPriority, source: "all", action: fmt.Sprintf("fwmark 0x%x/0x%x lookup %d", lanClassifierMark, lanClassifierMark, state.DefaultTable)})
		} else if families[family] {
			rules = append(rules, lanClassifierRule{family: family, priority: lanClassifierPriority, source: "all", action: "nop"})
		}
	}
	return rules
}

// args returns the ip(8) arguments that add or delete this exact rule.
func (r lanClassifierRule) args(verb string) []string {
	args := []string{"rule", verb, "priority", strconv.Itoa(r.priority)}
	if r.source != "all" {
		args = append(args, "from", r.source)
	}
	args = append(args, strings.Fields(r.action)...)
	if r.family == 6 {
		return append([]string{"-6"}, args...)
	}
	return append([]string{"-4"}, args...)
}

// line is the rule as "ip rule show" prints it, whitespace-normalized.
func (r lanClassifierRule) line() string {
	source := r.source
	if prefix, err := netip.ParsePrefix(source); err == nil && prefix.IsSingleIP() {
		source = prefix.Addr().String()
	}
	return fmt.Sprintf("%d: from %s %s", r.priority, source, r.action)
}

// lanClassifierRuleReadback compares one family's "ip rule show" output with
// the expected rules. Every rule at the classifier priorities must be ours:
// a foreign occupant there could redirect or hide LAN traffic.
func lanClassifierRuleReadback(output string, expected []lanClassifierRule, family int) (missing, foreign []string) {
	want := map[string]int{}
	for _, rule := range expected {
		if rule.family == family {
			want[rule.line()]++
		}
	}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.Join(strings.Fields(raw), " ")
		priority, ok := policyLinePriority(line)
		if !ok || priority != lanClassifierSkipPriority && priority != lanClassifierPriority {
			continue
		}
		if want[line] > 0 {
			want[line]--
			continue
		}
		foreign = append(foreign, line)
	}
	for line, count := range want {
		for ; count > 0; count-- {
			missing = append(missing, line)
		}
	}
	sort.Strings(missing)
	sort.Strings(foreign)
	return missing, foreign
}

// lanClassifierChainKey normalizes an iptables -S specification of this
// chain's vocabulary; anything else stays distinct and counts as foreign.
func lanClassifierChainKey(rule []string) string {
	out := make([]string, len(rule))
	for i, token := range rule {
		out[i] = token
		if i == 0 || rule[i-1] != "-s" && rule[i-1] != "-d" {
			if i > 0 && rule[i-1] == "--mac-source" {
				out[i] = strings.ToUpper(token)
			}
			continue
		}
		if prefix, err := netip.ParsePrefix(token); err == nil {
			out[i] = prefix.Masked().String()
		} else if address, err := netip.ParseAddr(token); err == nil {
			out[i] = netip.PrefixFrom(address, address.BitLen()).String()
		}
	}
	return strings.Join(out, " ")
}

// lanClassifierChainReadback compares "iptables -t mangle -S <chain>" output
// with the expected order. Order matters: the mark rule must stay last.
func lanClassifierChainReadback(output, chain string, expected [][]string) error {
	var actual []string
	declared := false
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 2 && fields[0] == "-N" && fields[1] == chain:
			declared = true
		case len(fields) > 2 && fields[0] == "-A" && fields[1] == chain:
			actual = append(actual, lanClassifierChainKey(fields[2:]))
		}
	}
	if !declared {
		return errors.New("LAN classifier chain is missing")
	}
	if len(actual) != len(expected) {
		return errors.New("LAN classifier chain has missing or foreign rules")
	}
	for i, rule := range expected {
		if actual[i] != lanClassifierChainKey(rule) {
			return errors.New("LAN classifier chain rules changed or reordered")
		}
	}
	return nil
}
