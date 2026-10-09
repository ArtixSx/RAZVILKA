package dataplane

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var errNFQWSDirectStockQueue = errors.New("direct NFQ stock queue graph refused")

var nfqwsDirectStockHooks = []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}

type nfqwsDirectStockGraph struct {
	chains map[string]bool // true only for an actual built-in policy declaration
	edges  map[string][]string
}

type nfqwsDirectStockAction struct {
	target      string
	gotoChain   bool
	queue       *uint16
	vendorMatch bool
}

type nfqwsDirectStockRowKey struct {
	family int
	table  string
	tokens string
}

type nfqwsDirectStockBudget struct {
	tokens, bytes int
}

// inspectNFQWSDirectStockQueues returns detached comparison rows, never an
// owner/effect grant. The caller must authenticate SAME direct-mode execution,
// identity and managed queue before supplying its original complete capture.
// Genuine receipt-owned rows are handled outside this helper; no RZ prefix is
// skipped here. First support is deliberately limited to mangle OUTPUT.
func inspectNFQWSDirectStockQueues(actualComplete BackendInventorySnapshot, managedQueue uint16) ([]BackendInventoryRow, error) {
	return inspectNFQWSDirectStockQueuesWithOwned(actualComplete, managedQueue, nil)
}

// WithOwned is also only a pure comparison. exactOwned must come from the
// caller's original typed receipt/compiled scope/process/context observation,
// matched against this SAME raw capture. It is not an authority constructor.
// Missing planned effects are not passed; each supplied row must occur once.
// The untouched complete graph includes every owned declaration/body/reference.
func inspectNFQWSDirectStockQueuesWithOwned(actualComplete BackendInventorySnapshot, managedQueue uint16, exactOwned []BackendInventoryRow) ([]BackendInventoryRow, error) {
	return inspectStockOutputQueueGraph(actualComplete, &managedQueue, exactOwned)
}

// nil managedQueue represents a consumer that owns no NFQ queue. It cannot
// exempt any owned NFQ row or borrow a guessed reservation. NFQ callers pass
// their original actual nonzero reservation through the unchanged wrappers.
func inspectStockOutputQueueGraph(actualComplete BackendInventorySnapshot, managedQueue *uint16, exactOwned []BackendInventoryRow) ([]BackendInventoryRow, error) {
	refuse := func() ([]BackendInventoryRow, error) { return nil, errNFQWSDirectStockQueue }
	if err := actualComplete.RequireComplete(); err != nil {
		return nil, errors.Join(errNFQWSDirectStockQueue, err)
	}
	if managedQueue != nil && *managedQueue == 0 || managedQueue == nil && len(exactOwned) != 0 || len(actualComplete.Rows) > backendClassicRows || len(exactOwned) > len(actualComplete.Rows) {
		return refuse()
	}
	owned := map[nfqwsDirectStockRowKey]int{}
	var ownedBudget nfqwsDirectStockBudget
	for _, row := range exactOwned {
		if !ownedBudget.add(row) || row.Table != "mangle" || row.Tokens[0] != "-N" && row.Tokens[0] != "-A" || !networkPolicyNFQRow(row) {
			return refuse()
		}
		key := nfqwsDirectStockKey(row)
		if _, duplicate := owned[key]; duplicate {
			return refuse()
		}
		owned[key] = 0
	}
	actualOwned := make([]bool, len(actualComplete.Rows))
	graphs := map[int]*nfqwsDirectStockGraph{}
	var actualBudget nfqwsDirectStockBudget
	for i, row := range actualComplete.Rows {
		if !actualBudget.add(row) {
			return refuse()
		}
		if len(owned) != 0 {
			key := nfqwsDirectStockKey(row)
			if count, match := owned[key]; match {
				if count != 0 {
					return refuse()
				}
				owned[key], actualOwned[i] = 1, true
			}
		}
		if row.Table != "mangle" {
			continue
		}
		g := graphs[row.Family]
		if g == nil {
			g = &nfqwsDirectStockGraph{chains: map[string]bool{}, edges: map[string][]string{}}
			graphs[row.Family] = g
		}
		chain := row.Tokens[1]
		if !nfqwsDirectStockChain(chain) || networkPolicyReservedChain(chain) && (!actualOwned[i] || !strings.HasPrefix(chain, "RZQ_")) {
			return refuse()
		}
		switch row.Tokens[0] {
		case "-N", "-P":
			if slices.Contains([]string{"ACCEPT", "DROP", "RETURN", "MARK", "CONNMARK", "NDMMARK", "CONNNDMMARK", "TCPMSS", "TTL", "NFQUEUE", "QUEUE"}, chain) {
				return refuse() // Never resolve ambiguous target/chain spellings.
			}
			if _, duplicate := g.chains[chain]; duplicate {
				return refuse()
			}
			builtin := row.Tokens[0] == "-P"
			if builtin && (len(row.Tokens) != 3 || !slices.Contains(nfqwsDirectStockHooks, chain) || row.Tokens[2] != "ACCEPT" && row.Tokens[2] != "DROP") || !builtin && (len(row.Tokens) != 2 || slices.Contains(nfqwsDirectStockHooks, chain)) {
				return refuse()
			}
			g.chains[chain] = builtin
		case "-A":
		default:
			return refuse()
		}
	}
	for _, count := range owned {
		if count != 1 {
			return refuse()
		}
	}
	for _, family := range []int{4, 6} {
		g := graphs[family]
		if g == nil {
			return refuse()
		}
		for _, hook := range nfqwsDirectStockHooks {
			if !g.chains[hook] {
				return refuse()
			}
		}
	}
	var queues []BackendInventoryRow
	for i, row := range actualComplete.Rows {
		if row.Tokens[0] != "-A" {
			continue
		}
		if row.Table != "mangle" {
			if nfqwsDirectStockOtherTableQueue(row.Tokens) {
				return refuse()
			}
			continue // Other-table rules still receive the caller's full predicates.
		}
		action, err := nfqwsDirectStockRuleAction(row.Tokens)
		if err != nil {
			return refuse()
		}
		if action.vendorMatch && (actualComplete.Scope.Network.Kind != netidentity.ReviewedSingleInitNet || actualComplete.Scope.Network.PlatformReviewSHA256 != backendNFTStockScopeSHA256) {
			return refuse()
		}
		g := graphs[row.Family]
		if _, exists := g.chains[row.Tokens[1]]; !exists || networkPolicyReservedChain(action.target) && (!actualOwned[i] || !strings.HasPrefix(action.target, "RZQ_")) {
			return refuse()
		}
		if builtin, chain := g.chains[action.target]; chain {
			if builtin { // Xtables jumps/gotos cannot call a built-in hook.
				return refuse()
			}
			g.edges[row.Tokens[1]] = append(g.edges[row.Tokens[1]], action.target)
			continue
		}
		if action.gotoChain {
			return refuse()
		}
		switch action.target {
		case "", "ACCEPT", "DROP", "RETURN", "MARK", "CONNMARK":
			// No hidden chain/queue transfer. MARK and CONNMARK return
			// XT_CONTINUE in upstream Linux v4.9 xt_mark.c/xt_connmark.c.
		case "NDMMARK", "CONNNDMMARK":
			// Accepted NC-1812 kernel 7b6c9477d429217042117fbfa3d2e9894a087607:
			// xt_ndmmark.c / xt_connndmmark.c revision 1 return XT_CONTINUE;
			// FOE_ALG_MARK and event_cache only update metadata. The caller
			// still authenticates the original current platform/tool scope.
			if actualComplete.Scope.Network.Kind != netidentity.ReviewedSingleInitNet || actualComplete.Scope.Network.PlatformReviewSHA256 != backendNFTStockScopeSHA256 {
				return refuse()
			}
		case "TCPMSS":
			// Linux v4.9 xt_TCPMSS.c returns XT_CONTINUE or NF_DROP,
			// never a queue verdict or a hidden chain transfer.
		case "TTL":
			// Linux v4.9 xt_HL.c ttl_tg has the same closed verdicts.
			if row.Family != 4 {
				return refuse()
			}
		case "NFQUEUE":
			if action.queue == nil || managedQueue != nil && (actualOwned[i] && *action.queue != *managedQueue || !actualOwned[i] && *action.queue == *managedQueue) {
				return refuse()
			}
			if !actualOwned[i] {
				queues = append(queues, row)
			}
		default:
			return refuse() // Unknown vendor target semantics never become safe.
		}
	}
	reachable := map[int]map[string]uint8{}
	for _, family := range []int{4, 6} {
		if !nfqwsDirectStockAcyclic(graphs[family]) {
			return refuse()
		}
		reachable[family] = nfqwsDirectStockReachability(graphs[family])
	}
	var preserved []BackendInventoryRow
	for _, row := range queues {
		if reachable[row.Family][row.Tokens[1]] != 1<<3 {
			return refuse() // Includes orphan queues and every other hook.
		}
		preserved = append(preserved, BackendInventoryRow{Family: row.Family, Table: row.Table, Tokens: slices.Clone(row.Tokens)})
	}
	return preserved, nil
}

func (b *nfqwsDirectStockBudget) add(row BackendInventoryRow) bool {
	if row.Family != 4 && row.Family != 6 || !backendClassicTableName(row.Table) || len(row.Tokens) < 2 || len(row.Tokens) > 128 {
		return false
	}
	b.tokens += len(row.Tokens)
	if b.tokens > backendClassicTokens {
		return false
	}
	for _, token := range row.Tokens {
		b.bytes += len(token) + 1
		if token == "" || len(token) > 4096 || b.bytes > backendClassicBytes || !utf8.ValidString(token) || strings.ContainsAny(token, "\x00\r\n") {
			return false
		}
	}
	return true
}

// NUL cannot occur in validated tokens; this key retains exact token boundaries.
func nfqwsDirectStockKey(row BackendInventoryRow) nfqwsDirectStockRowKey {
	return nfqwsDirectStockRowKey{family: row.Family, table: row.Table, tokens: strings.Join(row.Tokens, "\x00")}
}

func nfqwsDirectStockOtherTableQueue(fields []string) bool {
	for i := 2; i < len(fields); i++ {
		if fields[i] == "--comment" {
			if i+1 >= len(fields) {
				return true
			}
			i++
			continue
		}
		option, value, inline := strings.Cut(fields[i], "=")
		if strings.HasPrefix(option, "--queue-") {
			return true
		}
		if option == "-j" || option == "-g" || option == "--jump" || option == "--goto" {
			if !inline {
				if i+1 >= len(fields) {
					return true
				}
				i++
				value = fields[i]
			}
			if value == "NFQUEUE" || value == "QUEUE" {
				return true
			}
		} else if strings.HasPrefix(option, "-j") || strings.HasPrefix(option, "-g") || strings.HasPrefix(option, "--jump") || strings.HasPrefix(option, "--goto") {
			return true // Noncanonical control operands cannot hide a queue.
		}
	}
	return false
}

// The original kernel producer has already tokenized a valid -S image. This
// closed structural vocabulary ignores all match values (overapproximation),
// including the stock ndmmark predicate, without treating them as disjointness.
func nfqwsDirectStockRuleAction(fields []string) (nfqwsDirectStockAction, error) {
	var a nfqwsDirectStockAction
	markOptions, connmarkOptions := false, false
	ndmOptions := false
	ttlOptions, mssOptions := 0, 0
	for i := 2; i < len(fields); i++ {
		option := fields[i]
		if option == "--comment" {
			if i+1 >= len(fields) {
				return a, errNFQWSDirectStockQueue
			}
			i++
			continue
		}
		if strings.ContainsAny(option, " \t") {
			return a, errNFQWSDirectStockQueue
		}
		if option == "!" {
			if i+1 >= len(fields) || !slices.Contains([]string{"-p", "-s", "-d", "-i", "-o", "--mark", "--ndmmark", "--ctstate", "--state", "--dport", "--sport", "--dports", "--sports", "--icmp-type", "--icmpv6-type", "--mac-source", "--tcp-flags", "--syn", "--match-set", "--tls-sni", "--update-counters", "--update-subcounters"}, fields[i+1]) {
				return a, errNFQWSDirectStockQueue
			}
			continue
		}
		arity := 1
		switch option {
		case "-j", "-g":
			if a.target != "" || i+1 >= len(fields) || !nfqwsDirectStockChain(fields[i+1]) {
				return a, errNFQWSDirectStockQueue
			}
			a.target, a.gotoChain = fields[i+1], option == "-g"
		case "--queue-num":
			if a.queue != nil || i+1 >= len(fields) {
				return a, errNFQWSDirectStockQueue
			}
			n, err := strconv.ParseUint(fields[i+1], 10, 16)
			if err != nil || strconv.FormatUint(n, 10) != fields[i+1] {
				return a, errNFQWSDirectStockQueue
			}
			queue := uint16(n)
			a.queue = &queue
		case "-p", "-s", "-d", "-i", "-o", "-m", "--mark", "--ndmmark", "--ctstate", "--state", "--dport", "--sport", "--dports", "--sports", "--icmp-type", "--icmpv6-type", "--mac-source", "--limit", "--limit-burst":
		case "--connskip", "--tls-sni":
			// Accepted SDK 940-xt_connskip.patch / 960-xt_tls.patch.
			// The pinned kernel's matches return bool (TLS may hotdrop),
			// never a hidden queue/chain verdict. Values prune no edge.
			a.vendorMatch = true
			if option == "--connskip" {
				if i+1 >= len(fields) {
					return a, errNFQWSDirectStockQueue
				}
				n, err := strconv.ParseUint(fields[i+1], 10, 32)
				if err != nil || strconv.FormatUint(n, 10) != fields[i+1] {
					return a, errNFQWSDirectStockQueue
				}
			}
		case "--match-set":
			// iptables 1.8.2 libxt_set.c save grammar; xt_set.c's
			// corresponding matches are bool, including counter updates.
			arity = 2
		case "--return-nomatch":
			arity = 0
		case "--update-counters", "--update-subcounters":
			// -S only prints these when the update is disabled, with !.
			if i == 2 || fields[i-1] != "!" {
				return a, errNFQWSDirectStockQueue
			}
			arity = 0
		case "--set-mark", "--set-xmark", "--or-mark", "--xor-mark", "--and-mark":
			markOptions = true
		case "--set-xndmmark":
			ndmOptions = true
		case "--nfmask", "--ctmask":
			connmarkOptions = true
		case "--ttl-set", "--ttl-inc", "--ttl-dec":
			ttlOptions++
		case "--set-mss":
			mssOptions++
		case "--clamp-mss-to-pmtu":
			mssOptions++
			arity = 0
		case "--tcp-flags":
			arity = 2
		case "--syn":
			arity = 0
		case "--save-mark", "--restore-mark":
			arity, connmarkOptions = 0, true
		default:
			return a, errNFQWSDirectStockQueue
		}
		if i+arity >= len(fields) {
			return a, errNFQWSDirectStockQueue
		}
		for j := 1; j <= arity; j++ {
			if fields[i+j] == "!" || strings.HasPrefix(fields[i+j], "-") || strings.ContainsAny(fields[i+j], " \t") {
				return a, errNFQWSDirectStockQueue
			}
		}
		i += arity
	}
	if a.queue != nil && a.target != "NFQUEUE" || a.target == "NFQUEUE" && a.queue == nil || markOptions && a.target != "MARK" && a.target != "CONNMARK" && a.target != "CONNNDMMARK" || connmarkOptions && a.target != "CONNMARK" && a.target != "CONNNDMMARK" || ndmOptions && a.target != "NDMMARK" {
		return a, errNFQWSDirectStockQueue
	}
	if ttlOptions > 1 || ttlOptions != 0 && a.target != "TTL" || a.target == "TTL" && ttlOptions != 1 || mssOptions > 1 || mssOptions != 0 && a.target != "TCPMSS" || a.target == "TCPMSS" && mssOptions != 1 {
		return a, errNFQWSDirectStockQueue
	}
	if (a.target == "NDMMARK" || a.target == "CONNNDMMARK") && !nfqwsDirectStockVendorOptions(fields, a.target) {
		return a, errNFQWSDirectStockQueue
	}
	return a, nil
}

// Exact canonical -S target vocabulary from accepted SDK
// 1d58c10c46e270d6876836e5455fa4e9b786ad1e package/system/iptables/patches/
// 920-xt_ndmmark.patch and 930-xt_conndmmark.patch, both revision 1/u32 ABI.
// Values are shape-checked only; mark effects never prune a graph edge.
func nfqwsDirectStockVendorOptions(fields []string, target string) bool {
	options := map[string]string{}
	for i := 2; i < len(fields); i++ {
		if fields[i] == "--comment" {
			i++
			continue
		}
		option := fields[i]
		switch option {
		case "--set-xndmmark", "--set-mark", "--set-xmark", "--or-mark", "--xor-mark", "--and-mark", "--save-mark", "--restore-mark", "--nfmask", "--ctmask":
		default:
			continue
		}
		if _, duplicate := options[option]; duplicate {
			return false
		}
		if target == "NDMMARK" && option != "--set-xndmmark" || target == "CONNNDMMARK" && option != "--set-xmark" && option != "--restore-mark" && option != "--nfmask" && option != "--ctmask" {
			return false
		}
		if option == "--restore-mark" {
			options[option] = ""
		} else {
			if i+1 >= len(fields) {
				return false
			}
			i++
			options[option] = fields[i]
		}
	}
	if target == "NDMMARK" {
		return len(options) == 1 && nfqwsDirectStockMarkMask32(options["--set-xndmmark"])
	}
	if value, set := options["--set-xmark"]; set {
		return len(options) == 1 && nfqwsDirectStockMarkMask32(value)
	}
	_, restore := options["--restore-mark"]
	return len(options) == 3 && restore && nfqwsDirectStockHex32(options["--nfmask"]) && nfqwsDirectStockHex32(options["--ctmask"])
}

func nfqwsDirectStockMarkMask32(value string) bool {
	mark, mask, pair := strings.Cut(value, "/")
	return pair && nfqwsDirectStockHex32(mark) && nfqwsDirectStockHex32(mask)
}

func nfqwsDirectStockHex32(value string) bool {
	if !strings.HasPrefix(value, "0x") {
		return false
	}
	n, err := strconv.ParseUint(value[2:], 16, 32)
	return err == nil && value == "0x"+strconv.FormatUint(n, 16)
}

func nfqwsDirectStockChain(value string) bool {
	// -S reads kernel chain labels from xt_error_target.errorname[30]
	// (XT_FUNCTION_MAXNAMELEN), hence 29 bytes plus NUL. Extension names
	// and the userland CLI's new-chain limit use a different 29-byte field.
	// Existing firmware-created labels must not inherit that CLI limit.
	if len(value) == 0 || len(value) > 29 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func nfqwsDirectStockAcyclic(g *nfqwsDirectStockGraph) bool {
	degree := map[string]int{}
	for chain := range g.chains {
		degree[chain] = 0
	}
	for _, edges := range g.edges {
		for _, target := range edges {
			degree[target]++
		}
	}
	var ready []string
	for chain, n := range degree {
		if n == 0 {
			ready = append(ready, chain)
		}
	}
	seen := 0
	for len(ready) > 0 {
		chain := ready[len(ready)-1]
		ready = ready[:len(ready)-1]
		seen++
		for _, target := range g.edges[chain] {
			degree[target]--
			if degree[target] == 0 {
				ready = append(ready, target)
			}
		}
	}
	return seen == len(g.chains)
}

func nfqwsDirectStockReachability(g *nfqwsDirectStockGraph) map[string]uint8 {
	reached := map[string]uint8{}
	for i, hook := range nfqwsDirectStockHooks {
		bit, pending := uint8(1<<i), []string{hook}
		for len(pending) > 0 {
			chain := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if reached[chain]&bit != 0 {
				continue
			}
			reached[chain] |= bit
			pending = append(pending, g.edges[chain]...)
		}
	}
	return reached
}
