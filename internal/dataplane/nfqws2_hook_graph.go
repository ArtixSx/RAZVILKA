package dataplane

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// Stock S51nfqws2 group names. The closed first-start owner never creates an
// RZQ_ chain: every RZQ_ token belongs to the managed NFQ owner and refuses.
const (
	nfqws2HookPostChain = "nfqws_post"
	nfqws2HookPreChain  = "nfqws_pre"
	nfqws2HookNATChain  = "nfqws_nat"
)

var errNFQWS2HookGraph = errors.New("NFQWS2 owned hook graph is outside the closed first-start scope")

// nfqws2HookRule is one owned rule: its -A argv and its iptables -S row.
type nfqws2HookRule struct {
	Chain string
	Args  []string
}

func (r nfqws2HookRule) tokens() []string {
	return append([]string{"-A", r.Chain}, r.Args...)
}

// nfqws2HookFamily is the exact owned mangle graph of one address family.
// Chains are created in order, bodies are appended in order (every post rule,
// then every pre rule) and the two jumps are appended last, as stock does.
type nfqws2HookFamily struct {
	Family int
	Chains []string
	Bodies []nfqws2HookRule
	Jumps  []nfqws2HookRule
}

// rows renders the owned mangle rows exactly as iptables -S prints them.
func (f nfqws2HookFamily) rows() []BackendInventoryRow {
	var rows []BackendInventoryRow
	for _, chain := range f.Chains {
		rows = append(rows, BackendInventoryRow{Family: f.Family, Table: "mangle", Tokens: []string{"-N", chain}})
	}
	for _, rule := range append(slices.Clone(f.Bodies), f.Jumps...) {
		rows = append(rows, BackendInventoryRow{Family: f.Family, Table: "mangle", Tokens: rule.tokens()})
	}
	return rows
}

// bodyArgs returns one owned chain's rules in order, without "-A <chain>".
func (f nfqws2HookFamily) bodyArgs(chain string) [][]string {
	var body [][]string
	for _, rule := range f.Bodies {
		if rule.Chain == chain {
			body = append(body, slices.Clone(rule.Args))
		}
	}
	return body
}

func (f nfqws2HookFamily) bodyText(chain string) []string {
	var body []string
	for _, args := range f.bodyArgs(chain) {
		body = append(body, strings.Join(args, " "))
	}
	return body
}

// nfqws2HookGraph is a pure rendering of the closed first-start scope. It is
// expected data only and implies no write, ownership or kernel authority.
type nfqws2HookGraph struct {
	Interface string
	Queue     uint16
	IPv6      bool
	Families  []nfqws2HookFamily // IPv4 first; IPv6 only with IPV6_ENABLED=1.
	// The IPv4 nat state stock leaves in the closed case (the UDP MASQUERADE
	// is guarded off): an empty nfqws_nat and one jump.
	NAT []BackendInventoryRow
}

// nfqws2FirstStartHookGraph admits only the closed case: one ISP_INTERFACE,
// empty POLICY_MARK, TCP 443 and no UDP. Health and the restore share it, so
// the post rules come from the same stock scope the expert proof renders.
func nfqws2FirstStartHookGraph(config, running []byte, owner string) (nfqws2HookGraph, error) {
	var none nfqws2HookGraph
	if engineconfig.NFQWSFirstStartRunningAllLAN(config, owner, running) != nil {
		return none, errNFQWS2HookGraph
	}
	effective, err := engineconfig.NFQWSFirstStartEffectiveConfig(config, owner)
	if err != nil {
		return none, errNFQWS2HookGraph
	}
	scope, ok := nfqws2StockHookScopeOf([]byte(effective), running)
	if !ok || len(scope.interfaces) != 1 || scope.mark != "" || scope.tcp != "443" || scope.udp != "" {
		return none, errNFQWS2HookGraph
	}
	main, mainOK := nfqws2LiteralAssignments(effective, "IPV6_ENABLED")
	run, runOK := nfqws2LiteralAssignments(string(running), "IPV6_ENABLED")
	ipv6, present := main["IPV6_ENABLED"]
	if !mainOK || !runOK || !present || run["IPV6_ENABLED"] != ipv6 || ipv6 != "0" && ipv6 != "1" {
		return none, errNFQWS2HookGraph
	}
	graph := nfqws2HookGraph{Interface: scope.interfaces[0], Queue: uint16(scope.queue), IPv6: ipv6 == "1"}
	post, pre := scope.postRules(), scope.preRules()
	if len(post) != 3 || len(pre) != 5 {
		return none, errNFQWS2HookGraph
	}
	families := []int{4}
	if graph.IPv6 {
		families = append(families, 6)
	}
	for _, family := range families {
		g := nfqws2HookFamily{Family: family, Chains: []string{nfqws2HookPostChain, nfqws2HookPreChain}}
		for _, rule := range post {
			g.Bodies = append(g.Bodies, nfqws2HookRule{Chain: nfqws2HookPostChain, Args: strings.Fields(rule)})
		}
		for _, rule := range pre {
			g.Bodies = append(g.Bodies, nfqws2HookRule{Chain: nfqws2HookPreChain, Args: strings.Fields(rule)})
		}
		g.Jumps = []nfqws2HookRule{{Chain: "POSTROUTING", Args: []string{"-j", nfqws2HookPostChain}}, {Chain: "PREROUTING", Args: []string{"-j", nfqws2HookPreChain}}}
		graph.Families = append(graph.Families, g)
	}
	graph.NAT = []BackendInventoryRow{
		{Family: 4, Table: "nat", Tokens: []string{"-N", nfqws2HookNATChain}},
		{Family: 4, Table: "nat", Tokens: []string{"-A", "POSTROUTING", "-j", nfqws2HookNATChain}},
	}
	return graph, nil
}

// nfqws2HookReason is a fixed refusal vocabulary: no row, address, interface,
// option or queue value is retained in it.
type nfqws2HookReason string

func (r nfqws2HookReason) Error() string { return "NFQWS2 owned hook graph refused: " + string(r) }

const (
	nfqws2HookInventoryIncomplete nfqws2HookReason = "inventory-incomplete"
	nfqws2HookInventoryShape      nfqws2HookReason = "inventory-shape"
	nfqws2HookOutsideMangle       nfqws2HookReason = "owned-object-outside-mangle"
	nfqws2HookIPv6Disabled        nfqws2HookReason = "owned-object-with-ipv6-disabled"
	nfqws2HookForeignQueue        nfqws2HookReason = "foreign-rule-references-owned-queue"
	nfqws2HookNATMissing          nfqws2HookReason = "nat-hook-missing"
	nfqws2HookNATNonEmpty         nfqws2HookReason = "nat-chain-not-empty"
	nfqws2HookNATForeign          nfqws2HookReason = "nat-owned-object-differs"
	nfqws2HookPartial             nfqws2HookReason = "owned-graph-partial"
	nfqws2HookBodyDiffers         nfqws2HookReason = "owned-chain-body-differs"
	nfqws2HookJumpDuplicate       nfqws2HookReason = "owned-jump-duplicate"
	nfqws2HookForeignReference    nfqws2HookReason = "owned-chain-foreign-reference"
	nfqws2HookPostUnreachable     nfqws2HookReason = "postrouting-hook-unreachable"
	nfqws2HookPostJump            nfqws2HookReason = "postrouting-jump-count"
	nfqws2HookPreChainInvalid     nfqws2HookReason = "prerouting-chain-invalid"
	nfqws2HookPreJumpMissing      nfqws2HookReason = "prerouting-jump-missing"
	nfqws2HookPreJumpDuplicate    nfqws2HookReason = "prerouting-jump-duplicate"
	nfqws2HookPreForeign          nfqws2HookReason = "prerouting-owned-chain-foreign-reference"
	nfqws2HookPreTerminal         nfqws2HookReason = "prerouting-terminal-before-hook"
	nfqws2HookPreUnknown          nfqws2HookReason = "prerouting-unknown-target-before-hook"
	nfqws2HookPreGoto             nfqws2HookReason = "prerouting-goto-before-hook"
	nfqws2HookPreReturn           nfqws2HookReason = "prerouting-return-before-hook"
	nfqws2HookPreCycle            nfqws2HookReason = "prerouting-chain-cycle"
)

func nfqws2HookAt(family int, table string, reason error) error {
	return fmt.Errorf("ipv%d %s: %w", family, table, reason)
}

type nfqws2HookClass uint8

const (
	nfqws2HookOther nfqws2HookClass = iota
	nfqws2HookFull
	nfqws2HookLoss
)

type nfqws2HookFamilyClass struct {
	Family int
	Class  nfqws2HookClass
	Reason error // Set only for nfqws2HookOther.
}

// nfqws2HookClassification is a detached observation of one snapshot. It is
// neither a receipt nor a grant: a caller must still hold every admission
// and re-read the kernel before and after any write.
type nfqws2HookClassification struct {
	Class    nfqws2HookClass
	Families []nfqws2HookFamilyClass
	Reason   error // Set only for nfqws2HookOther.
	NATLoss  bool  // Both exact IPv4 NAT objects absent with complete mangle loss.
}

// restore lists the families in LOSS when no family is OTHER.
func (c nfqws2HookClassification) restore() []int {
	if c.Class != nfqws2HookLoss {
		return nil
	}
	var families []int
	for _, family := range c.Families {
		if family.Class == nfqws2HookLoss {
			families = append(families, family.Family)
		}
	}
	return families
}

// Owned stock and managed tokens, comment text included: an inert comment
// that spells an owned name refuses rather than hiding an owned object.
func nfqws2HookOwnedToken(token string) bool {
	return strings.Contains(token, "RZQ_") || strings.HasPrefix(strings.ToLower(token), "nfqws")
}

func nfqws2HookOwnedRow(row BackendInventoryRow) bool {
	return slices.ContainsFunc(row.Tokens, nfqws2HookOwnedToken)
}

// nfqws2HookQueueReference reports any rule that may deliver to queue.
// Noncanonical or unparsable queue options are treated as references.
func nfqws2HookQueueReference(tokens []string, queue uint16) bool {
	for i := 2; i < len(tokens); i++ {
		option, _, inline := strings.Cut(tokens[i], "=")
		if !strings.HasPrefix(option, "--queue-") {
			continue
		}
		if inline {
			return true
		}
		switch option {
		case "--queue-bypass", "--queue-cpu-fanout":
			continue
		case "--queue-num":
			if i+1 >= len(tokens) {
				return true
			}
			i++
			n, err := strconv.ParseUint(tokens[i], 10, 16)
			if err != nil || uint16(n) == queue {
				return true
			}
		case "--queue-balance":
			if i+1 >= len(tokens) {
				return true
			}
			i++
			low, high, ok := strings.Cut(tokens[i], ":")
			first, lowErr := strconv.ParseUint(low, 10, 16)
			last, highErr := strconv.ParseUint(high, 10, 16)
			if !ok || lowErr != nil || highErr != nil || first > last || uint64(queue) >= first && uint64(queue) <= last {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// nfqws2ClassifyHookGraph classifies one complete -S inventory against the
// closed graph. FULL: each family's owned mangle rows are token for token the
// rendered graph (one jump each) and both hooks are reachable. LOSS: a
// family's mangle holds no owned token and appending the two jumps would make
// both hooks reachable. IPv4 nat must be exact, or entirely absent together
// with the IPv4 mangle graph. There may be no owned token in any other table
// (or in IPv6 when it is disabled)
// and no rule outside the graph that may deliver to the owned queue.
// Anything else is OTHER with a fixed reason and must refuse every write.
func nfqws2ClassifyHookGraph(graph nfqws2HookGraph, snapshot BackendInventorySnapshot) nfqws2HookClassification {
	other := func(err error) nfqws2HookClassification {
		return nfqws2HookClassification{Class: nfqws2HookOther, Reason: err}
	}
	if len(graph.Families) == 0 || graph.Families[0].Family != 4 || graph.Queue == 0 || len(graph.Families) != map[bool]int{false: 1, true: 2}[graph.IPv6] {
		return other(errNFQWS2HookGraph)
	}
	if err := snapshot.RequireComplete(); err != nil {
		return other(errors.Join(nfqws2HookInventoryIncomplete, err))
	}
	if len(snapshot.Rows) > backendClassicRows {
		return other(nfqws2HookInventoryShape)
	}
	graphFamily := map[int]bool{}
	for _, family := range graph.Families {
		graphFamily[family.Family] = true
	}
	var budget nfqwsDirectStockBudget
	for _, row := range snapshot.Rows {
		if !budget.add(row) || row.Tokens[0] != "-N" && row.Tokens[0] != "-P" && row.Tokens[0] != "-A" {
			return other(nfqws2HookInventoryShape)
		}
	}
	for _, row := range snapshot.Rows {
		owned := nfqws2HookOwnedRow(row)
		if owned {
			switch {
			case row.Table == "mangle" && graphFamily[row.Family], row.Table == "nat" && row.Family == 4:
			case row.Family == 6 && !graph.IPv6:
				return other(nfqws2HookAt(row.Family, row.Table, nfqws2HookIPv6Disabled))
			default:
				return other(nfqws2HookAt(row.Family, row.Table, nfqws2HookOutsideMangle))
			}
		}
		// Owned mangle rows are judged token for token per family below; any
		// other rule must not be able to deliver to the owned queue.
		if !(owned && row.Table == "mangle") && row.Tokens[0] == "-A" && nfqws2HookQueueReference(row.Tokens, graph.Queue) {
			return other(nfqws2HookAt(row.Family, row.Table, nfqws2HookForeignQueue))
		}
	}
	natErr := nfqws2HookNATState(snapshot.Rows, graph.NAT)
	natAbsent := !slices.ContainsFunc(snapshot.Rows, func(row BackendInventoryRow) bool {
		return row.Family == 4 && row.Table == "nat" && nfqws2HookOwnedRow(row)
	})
	if natErr != nil && !(natErr == nfqws2HookNATMissing && natAbsent) {
		return other(nfqws2HookAt(4, "nat", natErr))
	}
	result := nfqws2HookClassification{Class: nfqws2HookFull}
	loss := false
	for _, family := range graph.Families {
		class, err := nfqws2ClassifyHookFamily(snapshot.Rows, family)
		state := nfqws2HookFamilyClass{Family: family.Family, Class: class}
		if class == nfqws2HookOther {
			state.Reason = nfqws2HookAt(family.Family, "mangle", err)
			if result.Reason == nil {
				result.Class, result.Reason = nfqws2HookOther, state.Reason
			}
		}
		loss = loss || class == nfqws2HookLoss
		result.Families = append(result.Families, state)
	}
	if result.Class == nfqws2HookFull && loss {
		result.Class = nfqws2HookLoss
	}
	if natErr != nil {
		// Never adopt or complete existing NAT objects, and never repair NAT
		// alone. This is only the complete IPv4 graph disappearance case.
		if result.Class != nfqws2HookLoss || result.Families[0].Class != nfqws2HookLoss {
			return other(nfqws2HookAt(4, "nat", natErr))
		}
		result.NATLoss = true
	}
	return result
}

// The exact IPv4 nat state: one empty nfqws_nat declaration and one
// unconditional POSTROUTING jump. Partial state never grants restoration.
func nfqws2HookNATState(rows []BackendInventoryRow, expected []BackendInventoryRow) error {
	if len(expected) != 2 {
		return errNFQWS2HookGraph
	}
	declared, jumps := 0, 0
	for _, row := range rows {
		if row.Family != 4 || row.Table != "nat" || !nfqws2HookOwnedRow(row) {
			continue
		}
		switch {
		case slices.Equal(row.Tokens, expected[0].Tokens):
			declared++
		case slices.Equal(row.Tokens, expected[1].Tokens):
			jumps++
		case len(row.Tokens) > 2 && row.Tokens[0] == "-A" && row.Tokens[1] == nfqws2HookNATChain:
			return nfqws2HookNATNonEmpty
		default:
			return nfqws2HookNATForeign
		}
	}
	if declared == 0 || jumps == 0 {
		return nfqws2HookNATMissing
	}
	if declared != 1 || jumps != 1 {
		return nfqws2HookNATForeign
	}
	return nil
}

func nfqws2ClassifyHookFamily(rows []BackendInventoryRow, g nfqws2HookFamily) (nfqws2HookClass, error) {
	image, ok := nfqws2RowsMangleImage(rows, g.Family)
	if !ok {
		return nfqws2HookOther, nfqws2HookInventoryShape
	}
	var owned []BackendInventoryRow
	for _, row := range rows {
		if row.Family == g.Family && row.Table == "mangle" && nfqws2HookOwnedRow(row) {
			owned = append(owned, row)
		}
	}
	if len(owned) == 0 {
		if err := nfqws2PostroutingReaches(image, true); err != nil {
			return nfqws2HookOther, err
		}
		if err := nfqws2PreroutingReaches(image, true); err != nil {
			return nfqws2HookOther, err
		}
		return nfqws2HookLoss, nil
	}
	expected := map[nfqwsDirectStockRowKey]int{}
	jumps := map[nfqwsDirectStockRowKey]bool{}
	for _, row := range g.rows() {
		expected[nfqwsDirectStockKey(row)] = 0
	}
	for _, jump := range g.Jumps {
		jumps[nfqwsDirectStockKey(BackendInventoryRow{Family: g.Family, Table: "mangle", Tokens: jump.tokens()})] = true
	}
	for _, row := range owned {
		key := nfqwsDirectStockKey(row)
		count, rendered := expected[key]
		switch {
		case rendered && count != 0 && jumps[key]:
			return nfqws2HookOther, nfqws2HookJumpDuplicate
		case rendered && count != 0:
			return nfqws2HookOther, nfqws2HookBodyDiffers
		case rendered:
			expected[key] = 1
		case row.Tokens[0] == "-A" && slices.Contains(g.Chains, row.Tokens[1]):
			return nfqws2HookOther, nfqws2HookBodyDiffers
		default:
			return nfqws2HookOther, nfqws2HookForeignReference
		}
	}
	for _, count := range expected {
		if count != 1 {
			return nfqws2HookOther, nfqws2HookPartial
		}
	}
	for _, chain := range g.Chains {
		if !slices.EqualFunc(image.rules[chain], g.bodyArgs(chain), slices.Equal[[]string]) {
			return nfqws2HookOther, nfqws2HookBodyDiffers
		}
	}
	if err := nfqws2PostroutingReaches(image, false); err != nil {
		return nfqws2HookOther, err
	}
	if err := nfqws2PreroutingReaches(image, false); err != nil {
		return nfqws2HookOther, err
	}
	return nfqws2HookFull, nil
}
