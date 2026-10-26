package dataplane

import (
	"fmt"
	"regexp"
	"slices"
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

// The PREROUTING half of the closed first-start proof. The same builder that
// renders the restore graph supplies the expected nfqws_pre body; the shared
// verifier proves no earlier rule can end traversal before its single hook.
func nfqws2ClosedReachablePreRule(data, config, running []byte, owner string) bool {
	graph, err := nfqws2FirstStartHookGraph(config, running, owner)
	if err != nil || len(graph.Families) == 0 || graph.Families[0].Family != 4 {
		return false
	}
	image, ok := nfqws2SaveMangleImage(data)
	if !ok || nfqws2PreroutingReaches(image, false) != nil {
		return false
	}
	var actual []string
	for _, rule := range image.rules[nfqws2HookPreChain] {
		actual = append(actual, strings.Join(rule, " "))
	}
	return nfqws2HealthRulesMatch(actual, graph.Families[0].bodyText(nfqws2HookPreChain))
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

// nfqws2MangleImage is one family's parsed mangle table: declarations and
// ordered rule bodies (the tokens after "-A <chain>"). It feeds pure
// predicates only and is never an ownership receipt or an effect grant.
type nfqws2MangleImage struct {
	chains map[string]bool // true only for a built-in policy declaration
	rules  map[string][][]string
}

// A user chain spelled like a target is ambiguous in -S output: "-j MARK"
// could be either. Such a table is never resolved, as in the stock graph.
var nfqws2MangleTargetNames = []string{"ACCEPT", "DROP", "RETURN", "MARK", "CONNMARK", "NDMMARK", "CONNNDMMARK", "TCPMSS", "TTL", "NFQUEUE", "QUEUE", "REJECT"}

func (image nfqws2MangleImage) declare(name string, builtin bool) bool {
	if _, duplicate := image.chains[name]; duplicate || !nfqwsDirectStockChain(name) || slices.Contains(nfqws2MangleTargetNames, name) ||
		builtin != slices.Contains(nfqwsDirectStockHooks, name) {
		return false
	}
	image.chains[name] = builtin
	return true
}

// The same strict single-table grammar as nfqws2ReachablePostRules. Each rule
// keeps the xtables token boundaries that the -S inventory also uses.
func nfqws2SaveMangleImage(data []byte) (nfqws2MangleImage, bool) {
	image := nfqws2MangleImage{chains: map[string]bool{}, rules: map[string][][]string{}}
	if len(data) == 0 || len(data) > 1<<20 {
		return image, false
	}
	inMangle, complete, seenMangle := false, false, false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			if inMangle || line == "*mangle" && seenMangle {
				return image, false
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
			if !image.declare(strings.TrimPrefix(f[0], ":"), f[1] != "-") {
				return image, false
			}
			continue
		}
		tokens, err := backendXTablesTokens(line)
		if err != nil || len(tokens) < 4 || tokens[0] != "-A" {
			return image, false
		}
		if _, declared := image.chains[tokens[1]]; !declared {
			return image, false
		}
		image.rules[tokens[1]] = append(image.rules[tokens[1]], tokens[2:])
	}
	if inMangle || !complete {
		return image, false
	}
	return image, true
}

// One family of the complete -S inventory. Rows keep kernel order; every
// rule's chain must be declared by the same image.
func nfqws2RowsMangleImage(rows []BackendInventoryRow, family int) (nfqws2MangleImage, bool) {
	image := nfqws2MangleImage{chains: map[string]bool{}, rules: map[string][][]string{}}
	for _, row := range rows {
		if row.Family != family || row.Table != "mangle" {
			continue
		}
		t := row.Tokens
		switch {
		case len(t) == 3 && t[0] == "-P" && (t[2] == "ACCEPT" || t[2] == "DROP"):
			if !image.declare(t[1], true) {
				return image, false
			}
		case len(t) == 2 && t[0] == "-N":
			if !image.declare(t[1], false) {
				return image, false
			}
		case len(t) >= 4 && t[0] == "-A":
		default:
			return image, false
		}
	}
	for _, row := range rows {
		if row.Family != family || row.Table != "mangle" || row.Tokens[0] != "-A" {
			continue
		}
		if _, declared := image.chains[row.Tokens[1]]; !declared {
			return image, false
		}
		image.rules[row.Tokens[1]] = append(image.rules[row.Tokens[1]], slices.Clone(row.Tokens[2:]))
	}
	return image, true
}

// The nfqws2ReachablePostRules hook semantics over an image: every
// POSTROUTING rule is an unconditional jump to the owned chain or to a
// declared empty user chain. appended means the owned jump is still absent
// and a restore would append it after every rule seen here.
func nfqws2PostroutingReaches(image nfqws2MangleImage, appended bool) error {
	if builtin, declared := image.chains["POSTROUTING"]; !declared || !builtin {
		return nfqws2HookPostUnreachable
	}
	hooks := 0
	for _, rule := range image.rules["POSTROUTING"] {
		if len(rule) != 2 || rule[0] != "-j" {
			return nfqws2HookPostUnreachable
		}
		if rule[1] == nfqws2HookPostChain {
			hooks++
			continue
		}
		if builtin, declared := image.chains[rule[1]]; !declared || builtin || len(image.rules[rule[1]]) != 0 {
			return nfqws2HookPostUnreachable
		}
	}
	if appended && hooks != 0 {
		return nfqws2HookPostUnreachable
	}
	if !appended && hooks != 1 {
		return nfqws2HookPostJump
	}
	return nil
}

// nfqws2PreroutingReaches proves that every packet traversing PREROUTING
// reaches the single unconditional owned jump. appended means the jump is
// absent and a restore would append it at the end of PREROUTING. Matches are
// ignored (overapproximation); only targets decide. Before the hook only the
// non-terminal RETURN, TTL, MARK and CONNMARK targets, rules without a
// target, and jumps into user chains built solely from those may run.
// RETURN continues only inside a called chain: in PREROUTING itself it ends
// traversal with the policy verdict. Any goto, terminal or unknown target,
// cycle, or other reference to the owned chain refuses.
func nfqws2PreroutingReaches(image nfqws2MangleImage, appended bool) error {
	if builtin, declared := image.chains["PREROUTING"]; !declared || !builtin {
		return nfqws2HookPreChainInvalid
	}
	rules := image.rules["PREROUTING"]
	hooks, position := 0, len(rules)
	for chain, body := range image.rules {
		for i, rule := range body {
			if !slices.Contains(rule, nfqws2HookPreChain) {
				continue
			}
			if chain != "PREROUTING" || !slices.Equal(rule, []string{"-j", nfqws2HookPreChain}) {
				return nfqws2HookPreForeign
			}
			hooks++
			position = i
		}
	}
	builtin, declared := image.chains[nfqws2HookPreChain]
	switch {
	case appended && (hooks != 0 || declared):
		return nfqws2HookPreForeign
	case !appended && hooks == 0:
		return nfqws2HookPreJumpMissing
	case !appended && hooks != 1:
		return nfqws2HookPreJumpDuplicate
	case !appended && (!declared || builtin):
		return nfqws2HookPreChainInvalid
	}
	walk := nfqws2PreroutingWalk{image: image, proven: map[string]bool{}, active: map[string]bool{}}
	for _, rule := range rules[:position] {
		if err := walk.rule(rule, true, 0); err != nil {
			return err
		}
	}
	return nil
}

type nfqws2PreroutingWalk struct {
	image          nfqws2MangleImage
	proven, active map[string]bool
}

const nfqws2PreroutingDepth = 16

func (w nfqws2PreroutingWalk) rule(rule []string, top bool, depth int) error {
	target, jump, ok := nfqws2RuleTarget(rule)
	switch {
	case !ok:
		return nfqws2HookPreUnknown
	case jump == "-g":
		return nfqws2HookPreGoto
	case target == "", target == "TTL", target == "MARK", target == "CONNMARK":
		return nil
	case target == "RETURN" && top:
		return nfqws2HookPreReturn
	case target == "RETURN":
		return nil
	}
	builtin, declared := w.image.chains[target]
	if !declared {
		if slices.Contains([]string{"ACCEPT", "DROP", "REJECT", "NFQUEUE", "QUEUE"}, target) {
			return nfqws2HookPreTerminal
		}
		return nfqws2HookPreUnknown
	}
	if nfqws2HookOwnedToken(target) {
		return nfqws2HookPreForeign
	}
	// -S prints a user-chain jump last and bare. Target options after it, or
	// a name shaped like a target extension, leave the verdict ambiguous.
	if builtin || !slices.Equal(rule[len(rule)-2:], []string{jump, target}) || strings.Trim(target, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == "" {
		return nfqws2HookPreUnknown
	}
	if w.proven[target] {
		return nil
	}
	if w.active[target] || depth >= nfqws2PreroutingDepth {
		return nfqws2HookPreCycle
	}
	w.active[target] = true
	for _, child := range w.image.rules[target] {
		if err := w.rule(child, false, depth+1); err != nil {
			return err
		}
	}
	delete(w.active, target)
	w.proven[target] = true
	return nil
}

// nfqws2RuleTarget finds the one -j/-g control operand of a tokenized rule.
// Every token is inspected, comment text included: a value spelled like a
// control option makes the rule unknown, never safe. Queue options belong to
// NFQUEUE only.
func nfqws2RuleTarget(rule []string) (target, jump string, ok bool) {
	queueOptions := false
	for i := 0; i < len(rule); i++ {
		token := rule[i]
		switch token {
		case "-j", "-g":
			if jump != "" || i+1 >= len(rule) || !nfqwsDirectStockChain(rule[i+1]) || strings.HasPrefix(rule[i+1], "-") {
				return "", "", false
			}
			target, jump = rule[i+1], token
			i++
			continue
		}
		if strings.HasPrefix(token, "-j") || strings.HasPrefix(token, "-g") || strings.HasPrefix(token, "--jump") || strings.HasPrefix(token, "--goto") {
			return "", "", false
		}
		queueOptions = queueOptions || strings.HasPrefix(token, "--queue-")
	}
	if queueOptions && target != "NFQUEUE" {
		return "", "", false
	}
	return target, jump, true
}

// Expert compatibility is limited to the stock IPv4 POSTROUTING grammar.
// Scope is literal main/.run data, never arbitrary shell or arbitrary RETURN.
func nfqws2ExpertReachableQueueRule(data, config, running []byte) bool {
	scope, ok := nfqws2StockHookScopeOf(config, running)
	if !ok {
		return false
	}
	rules, ok := nfqws2ReachablePostRules(data, strconv.Itoa(scope.queue))
	return ok && nfqws2HealthRulesMatch(rules, scope.postRules())
}

// nfqws2StockHookScope is the literal stock firewall scope of main plus .run.
// It only renders expected rule text; it never proves the current network.
type nfqws2StockHookScope struct {
	interfaces []string
	queue      int
	tcp, udp   string // nfqws2HealthPorts form; empty disables the protocol.
	mark       string // Literal .run POLICY_MARK; empty is the all-LAN scope.
	exclude    bool
}

func nfqws2StockHookScopeOf(config, running []byte) (nfqws2StockHookScope, bool) {
	var none nfqws2StockHookScope
	base, _, err := removeManagedBlock(string(config))
	if err != nil || engineconfig.NFQWSRunningConfigMatches(base, string(running)) != nil {
		return none, false
	}
	main, ok := nfqws2HealthAssignments(base)
	if !ok {
		return none, false
	}
	run, ok := nfqws2HealthAssignments(string(running))
	if !ok {
		return none, false
	}
	for _, key := range []string{"ISP_INTERFACE", "NFQUEUE_NUM", "TCP_PORTS", "UDP_PORTS", "POLICY_NAME", "POLICY_EXCLUDE"} {
		value, present := main[key]
		observed, exists := run[key]
		if !present || !exists || value != observed {
			return none, false
		}
	}
	queue, err := strconv.Atoi(main["NFQUEUE_NUM"])
	if err != nil || queue < 1 || queue > 65535 {
		return none, false
	}
	mark, present := run["POLICY_MARK"]
	if !present || main["POLICY_EXCLUDE"] != "0" && main["POLICY_EXCLUDE"] != "1" {
		return none, false
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
			return none, false
		}
	}
	interfaces := strings.Fields(main["ISP_INTERFACE"])
	if len(interfaces) == 0 || len(interfaces) > 16 {
		return none, false
	}
	seen := map[string]bool{}
	for _, iface := range interfaces {
		if seen[iface] || !nfqws2HealthInterface.MatchString(iface) {
			return none, false
		}
		seen[iface] = true
	}
	tcp, ok := nfqws2HealthPorts(main["TCP_PORTS"])
	if !ok {
		return none, false
	}
	udp, ok := nfqws2HealthPorts(main["UDP_PORTS"])
	if !ok || tcp == "" && udp == "" {
		return none, false
	}
	return nfqws2StockHookScope{interfaces: interfaces, queue: queue, tcp: tcp, udp: udp, mark: mark, exclude: main["POLICY_EXCLUDE"] == "1"}, true
}

const (
	nfqws2StockProcessedMark = "0x40000000/0x40000000"
	nfqws2StockExcludeMark   = "0x20000000/0x20000000"
)

// postRules mirrors stock _firewall_start nfqws_post per interface, rendered
// in the iptables -S order observed on the 1.4.21 router. A disabled
// protocol has no rule: stock multiport refuses an empty port list.
func (s nfqws2StockHookScope) postRules() []string {
	var rules []string
	target := " -j NFQUEUE --queue-num " + strconv.Itoa(s.queue) + " --queue-bypass"
	unprocessed := " -m mark ! --mark " + nfqws2StockProcessedMark
	for _, iface := range s.interfaces {
		prefix := "-o " + iface
		if s.mark != "" {
			mark := nfqws2SaveMark(s.mark)
			if s.exclude {
				rules = append(rules, prefix+" -m mark --mark "+mark+" -j RETURN")
			} else {
				rules = append(rules, prefix+" -m mark ! --mark "+mark+" -j CONNMARK --set-xmark "+nfqws2StockExcludeMark,
					prefix+" -m connmark --mark "+nfqws2StockExcludeMark+" -j RETURN",
					prefix+" -m mark ! --mark "+mark+" -j RETURN")
			}
		}
		if s.udp != "" {
			rules = append(rules, prefix+" -p udp"+unprocessed+" -m multiport --dports "+s.udp+" -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original"+target)
		}
		if s.tcp != "" {
			tcp := prefix + " -p tcp" + unprocessed + " -m multiport --dports " + s.tcp
			rules = append(rules, tcp+" -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original"+target,
				tcp+" -m tcp --tcp-flags FIN FIN"+target,
				tcp+" -m tcp --tcp-flags RST RST"+target)
		}
	}
	return rules
}

// preRules mirrors stock _firewall_start nfqws_pre (S51nfqws2:304-319) in the
// same -S order. Reply-direction packets already marked processed return.
func (s nfqws2StockHookScope) preRules() []string {
	var rules []string
	target := " -j NFQUEUE --queue-num " + strconv.Itoa(s.queue) + " --queue-bypass"
	unprocessed := " -m mark ! --mark " + nfqws2StockProcessedMark
	for _, iface := range s.interfaces {
		prefix := "-i " + iface
		if s.mark != "" && s.exclude {
			rules = append(rules, prefix+" -m mark --mark "+nfqws2SaveMark(s.mark)+" -j RETURN")
		}
		if s.mark != "" && !s.exclude {
			rules = append(rules, prefix+" -m connmark --mark "+nfqws2StockExcludeMark+" -j RETURN")
		}
		rules = append(rules, prefix+" -m mark --mark "+nfqws2StockProcessedMark+" -j RETURN")
		if s.udp != "" {
			rules = append(rules, prefix+" -p udp"+unprocessed+" -m multiport --sports "+s.udp+" -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir reply"+target)
		}
		if s.tcp != "" {
			tcp := prefix + " -p tcp" + unprocessed + " -m multiport --sports " + s.tcp
			rules = append(rules, tcp+" -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir reply"+target,
				tcp+" -m tcp --tcp-flags SYN,ACK SYN,ACK"+target,
				tcp+" -m tcp --tcp-flags FIN FIN"+target,
				tcp+" -m tcp --tcp-flags RST RST"+target)
		}
	}
	return rules
}

// nfqws2SaveMark renders a valid literal mark the way the mark match prints
// it: an all-ones mask is implicit. Callers validate the value beforehand.
func nfqws2SaveMark(raw string) string {
	normalized, ok := nfqws2HealthMark(raw)
	if !ok {
		return raw
	}
	return strings.TrimSuffix(normalized, "/0xffffffff")
}

// Canonical rule comparison in order; equal length is part of the proof.
func nfqws2HealthRulesMatch(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i, rule := range actual {
		got, ok := nfqws2HealthRule(rule)
		if !ok {
			return false
		}
		want, ok := nfqws2HealthRule(expected[i])
		if !ok || got != want {
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
	return nfqws2LiteralAssignments(raw, "ISP_INTERFACE", "NFQUEUE_NUM", "TCP_PORTS", "UDP_PORTS", "POLICY_NAME", "POLICY_EXCLUDE", "POLICY_MARK")
}

// Only the named keys must be literal and unique; other assignments are
// still required to parse but their values are not retained.
func nfqws2LiteralAssignments(raw string, keys ...string) (map[string]string, bool) {
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
		if slices.Contains(keys, key) {
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
		case "--dport", "--dports", "--sport", "--sports":
			// Destination and source ports stay distinct canonical keys.
			if key == "--sport" || key == "--sports" {
				key = "sports"
			} else {
				key = "ports"
			}
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
			a, ok := nfqws2HealthTCPFlags(value)
			b, set := nfqws2HealthTCPFlags(f[i])
			if !ok || !set {
				return "", false
			}
			value = a + "/" + b
		case "--queue-num":
			number, err := strconv.Atoi(value)
			if err != nil || number < 1 || number > 65535 {
				return "", false
			}
			value = strconv.Itoa(number)
		case "-i", "-o", "-p", "-j", "--connbytes", "--connbytes-mode", "--connbytes-dir":
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

// One xt_tcp flag set: the stock names in either case, each at most once.
// Sorting makes SYN,ACK and ack,syn the same set; unknown names refuse.
func nfqws2HealthTCPFlags(raw string) (string, bool) {
	flags := strings.Split(strings.ToUpper(raw), ",")
	seen := map[string]bool{}
	for _, flag := range flags {
		switch flag {
		case "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ALL", "NONE":
		default:
			return "", false
		}
		if seen[flag] {
			return "", false
		}
		seen[flag] = true
	}
	sort.Strings(flags)
	return strings.Join(flags, ","), true
}
