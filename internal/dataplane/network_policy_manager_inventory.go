package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// InventoryCheck consumes fresh complete captures, not a supplied snapshot or
// hash. Consumer observations bracket the final capture; neither a mark match
// nor an adapter/chain name supplies an allowance.
func (c *NetworkPolicyChecks) InventoryCheck(ctx context.Context, identity netidentity.Identity, allowedLAN *LANPolicyRuntimePlan) error {
	return c.observeInventory(ctx, identity, allowedLAN, false)
}

func (c *NetworkPolicyChecks) ConsumerCheck(ctx context.Context, lan *LANPolicyRuntimePlan) error {
	if c == nil || c.gate == nil || c.gate.identity == nil || lan == nil {
		return ErrNetworkPolicyConsumers
	}
	return c.observeInventory(ctx, c.gate.identity.value, lan, true)
}

func (c *NetworkPolicyChecks) observeInventory(ctx context.Context, identity netidentity.Identity, lan *LANPolicyRuntimePlan, requireConsumer bool) error {
	lan = CloneLANPolicyRuntime(lan)
	if lan != nil && (ValidateLANPolicyRuntime(lan) != nil || c == nil || c.gate == nil || c.gate.identity == nil || lan.Mode != c.gate.identity.mode) {
		return lanPolicyPreflightAt("inventory-mode", ErrLANPolicyRuntime)
	}
	return lanPolicyPreflightAt("inventory-boundary", c.boundary(ctx, func(held context.Context) error {
		if identity != c.gate.identity.value {
			return lanPolicyPreflightAt("inventory-identity", ErrNetworkPolicyIdentity)
		}
		stock, err := c.stockQueueExecution(held)
		if err != nil {
			return lanPolicyPreflightAt("inventory-consumer-open", err)
		}
		opening, err := c.proxyConsumers(held, lan)
		defer closeNetworkPolicyProxyObservations(opening)
		if err != nil {
			return lanPolicyPreflightAt("inventory-consumer-open", errors.Join(ErrNetworkPolicyConsumers, err))
		}
		openingNFQ, err := c.nfqConsumers(held, lan)
		defer func() {
			for _, o := range openingNFQ {
				o.close()
			}
		}()
		if err != nil || requireConsumer && len(opening)+len(openingNFQ) == 0 {
			return lanPolicyPreflightAt("inventory-consumer-open", errors.Join(ErrNetworkPolicyConsumers, err))
		}
		first, err := c.read(held, identity)
		if err != nil {
			return lanPolicyPreflightAt("inventory-read-open", err)
		}
		stockRows, err := stock.comparison(first, openingNFQ)
		if err != nil {
			return lanPolicyPreflightAt("inventory-row-unallowed", err)
		}
		if err := checkNetworkPolicyInventoryWithStock(first, identity, lan, c.gate.identity.mode, opening, stockRows, openingNFQ...); err != nil {
			return err
		}
		closing, err := c.proxyConsumers(held, lan)
		defer closeNetworkPolicyProxyObservations(closing)
		if err != nil || !equalNetworkPolicyProxyObservations(opening, closing) {
			return lanPolicyPreflightAt("inventory-consumer-close", errors.Join(ErrNetworkPolicyConsumers, err))
		}
		closingNFQ, err := c.nfqConsumers(held, lan)
		defer func() {
			for _, o := range closingNFQ {
				o.close()
			}
		}()
		if err != nil || !equalNetworkPolicyNFQObservations(openingNFQ, closingNFQ) {
			return lanPolicyPreflightAt("inventory-consumer-close", errors.Join(ErrNetworkPolicyConsumers, err))
		}
		closingStock, err := c.stockQueueExecution(held)
		if err != nil || !stock.equal(closingStock) {
			return lanPolicyPreflightAt("inventory-consumer-close", errors.Join(ErrNetworkPolicyConsumers, err))
		}
		// No external owner callback runs after this final complete capture.
		// Compare the entire image, including unrelated/custom-table rows. This
		// does not claim an atomic snapshot or immunity to undetected ABA.
		last, err := c.read(held, identity)
		if err != nil || !reflect.DeepEqual(first, last) {
			stage := "inventory-image-changed"
			if err != nil {
				stage = "inventory-read-close"
			}
			return lanPolicyPreflightAt(stage, errors.Join(ErrBackendInventoryUnknown, err))
		}
		var nfqErr error
		for _, observations := range [][]networkPolicyNFQObservation{openingNFQ, closingNFQ} {
			for _, o := range observations {
				nfqErr = errors.Join(nfqErr, o.current(held))
			}
		}
		lastStockRows, stockErr := closingStock.comparison(last, closingNFQ)
		if stockErr == nil && !reflect.DeepEqual(stockRows, lastStockRows) {
			stockErr = ErrNetworkPolicyConsumers
		}
		return lanPolicyPreflightAt("inventory-owner-current", errors.Join(stockErr, stock.current(held), closingStock.current(held), checkNetworkPolicyInventoryWithStock(last, identity, lan, c.gate.identity.mode, closing, lastStockRows, closingNFQ...), checkNetworkPolicyProxyObservations(opening), checkNetworkPolicyProxyObservations(closing), nfqErr))
	}))
}

// CheckLANPolicyInventory is a pure observation predicate allowing only the
// exact compiled LAN body (including known partial apply/cleanup). No consumer
// rows are allowed by this standalone function. It grants no ownership, effect
// or cleanup permission, even for an identical tuple.
func CheckLANPolicyInventory(s BackendInventorySnapshot, identity netidentity.Identity, allowedLAN *LANPolicyRuntimePlan) error {
	return checkNetworkPolicyInventory(s, identity, allowedLAN, nil)
}

type networkPolicyInventoryAllowance struct {
	counts    map[string]int
	required  map[string]int
	gateOrder map[string][]string
}

func networkPolicyRowKey(row BackendInventoryRow, consumer bool) string {
	var body string
	if len(row.Tokens) < 2 {
		return ""
	}
	if networkPolicyNFQRow(row) {
		key := nfqwsScopedRuleKey(row.Tokens)
		if strings.HasPrefix(key, "unknown\x00") {
			return ""
		}
		data, _ := json.Marshal([]any{row.Family, row.Table, "nfqws", key})
		return string(data)
	}
	if row.Tokens[0] == "-A" {
		if consumer {
			body = proxyFirewallRuleKey(row.Tokens[2:])
			if strings.HasPrefix(body, "!") {
				return ""
			}
		} else {
			for _, token := range row.Tokens[2:] {
				if strings.ContainsAny(token, " \t\r\n\x00") {
					return ""
				}
			}
			body = lanClassifierChainKey(row.Tokens[2:])
		}
	}
	data, _ := json.Marshal([]any{row.Family, row.Table, row.Tokens[0], row.Tokens[1], body})
	return string(data)
}

func networkPolicyChainCoordinate(row BackendInventoryRow) string {
	data, _ := json.Marshal([]any{row.Family, row.Table, row.Tokens[1]})
	return string(data)
}

func networkPolicyInventoryAllowed(lan *LANPolicyRuntimePlan, consumers []networkPolicyProxyObservation, nfqConsumers ...networkPolicyNFQObservation) (networkPolicyInventoryAllowance, error) {
	a := networkPolicyInventoryAllowance{counts: map[string]int{}, required: map[string]int{}, gateOrder: map[string][]string{}}
	add := func(row BackendInventoryRow, consumer bool) {
		key := networkPolicyRowKey(row, consumer)
		a.counts[key]++
		if consumer {
			a.required[key]++
		}
		if !consumer && row.Tokens[0] == "-A" && strings.HasPrefix(row.Tokens[1], "RZG_") {
			coordinate := networkPolicyChainCoordinate(row)
			a.gateOrder[coordinate] = append(a.gateOrder[coordinate], key)
		}
	}
	if lan != nil {
		if ValidateLANPolicyRuntime(lan) != nil {
			return a, ErrLANPolicyRuntime
		}
		for _, chain := range lanPolicyChains(CloneLANPolicyRuntime(lan)) {
			add(BackendInventoryRow{Family: chain.family, Table: "mangle", Tokens: []string{"-N", chain.name}}, false)
			for _, rule := range chain.rules {
				add(BackendInventoryRow{Family: chain.family, Table: "mangle", Tokens: append([]string{"-A", chain.name}, rule...)}, false)
			}
			add(BackendInventoryRow{Family: chain.family, Table: "mangle", Tokens: append([]string{"-A", "PREROUTING"}, chain.jump...)}, false)
		}
	}
	for _, consumer := range consumers {
		for _, row := range consumer.rows {
			add(row, true)
		}
	}
	for _, consumer := range nfqConsumers {
		if len(consumer.rows) != len(consumer.required) {
			return a, ErrNetworkPolicyConsumers
		}
		for i, row := range consumer.rows {
			key := networkPolicyRowKey(row, true)
			if key == "" || !networkPolicyNFQRow(row) {
				return a, ErrNetworkPolicyConsumers
			}
			a.counts[key]++
			if consumer.required[i] {
				a.required[key]++
			}
		}
	}
	return a, nil
}

func checkNetworkPolicyInventory(s BackendInventorySnapshot, identity netidentity.Identity, lan *LANPolicyRuntimePlan, consumers []networkPolicyProxyObservation, nfqConsumers ...networkPolicyNFQObservation) error {
	mode := ""
	if lan != nil {
		mode = lan.Mode
	}
	return checkNetworkPolicyInventoryForMode(s, identity, lan, mode, consumers, nfqConsumers...)
}

func checkNetworkPolicyInventoryForMode(s BackendInventorySnapshot, identity netidentity.Identity, lan *LANPolicyRuntimePlan, mode string, consumers []networkPolicyProxyObservation, nfqConsumers ...networkPolicyNFQObservation) error {
	return checkNetworkPolicyInventoryWithStock(s, identity, lan, mode, consumers, nil, nfqConsumers...)
}

// Only the original-owner bridge above supplies exact stock comparison rows.
// Public/bare observation predicates remain strict and cannot infer a queue.
func checkNetworkPolicyInventoryWithStock(s BackendInventorySnapshot, identity netidentity.Identity, lan *LANPolicyRuntimePlan, mode string, consumers []networkPolicyProxyObservation, stockRows []BackendInventoryRow, nfqConsumers ...networkPolicyNFQObservation) error {
	if mode != "" && mode != LANPolicyNFQWSDirectMode || lan != nil && lan.Mode != mode {
		return lanPolicyPreflightAt("inventory-mode", ErrLANPolicyRuntime)
	}
	if err := s.RequireComplete(); err != nil || identity.Validate() != nil || s.Scope.Network != identity {
		stage := "inventory-identity"
		if err != nil {
			stage = "inventory-coverage"
		}
		return lanPolicyPreflightAt(stage, errors.Join(ErrBackendInventoryUnknown, err))
	}
	a, err := networkPolicyInventoryAllowed(lan, consumers, nfqConsumers...)
	if err != nil {
		return lanPolicyPreflightAt("inventory-definition", err)
	}
	stock := map[nfqwsDirectStockRowKey]int{}
	for _, row := range stockRows {
		if mode != LANPolicyNFQWSDirectMode || row.Table != "mangle" || networkPolicyNFQRow(row) || !nfqwsDirectStockOtherTableQueue(row.Tokens) {
			return lanPolicyPreflightAt("inventory-definition", ErrNetworkPolicyConsumers)
		}
		key := nfqwsDirectStockKey(row)
		if stock[key] != 0 {
			return lanPolicyPreflightAt("inventory-definition", ErrNetworkPolicyConsumers)
		}
		stock[key] = 1
	}
	positions := map[string]int{}
	for _, row := range s.Rows {
		if row.Family != 4 && row.Family != 6 || !backendClassicTableName(row.Table) || len(row.Tokens) < 2 || len(row.Tokens) > 128 {
			return lanPolicyPreflightAt("inventory-row-shape", ErrBackendInventoryUnknown)
		}
		reserved, err := networkPolicyReservedRowForMode(row.Tokens, mode)
		if err != nil {
			return lanPolicyPreflightAt("inventory-row-syntax", err)
		}
		if !reserved {
			continue
		}
		stockKey := nfqwsDirectStockKey(row)
		if stock[stockKey] > 0 {
			stock[stockKey]--
			continue
		}
		consumer := strings.HasPrefix(row.Tokens[1], "RZP_") || networkPolicyReferencesPrefix(row.Tokens, "RZP_") || networkPolicyNFQRow(row)
		key := networkPolicyRowKey(row, consumer)
		if key == "" || a.counts[key] <= 0 {
			stage := "inventory-row-unallowed"
			if key == "" {
				stage = "inventory-row-key"
			}
			return lanPolicyPreflightAt(stage, ErrLANPolicyRuntime)
		}
		a.counts[key]--
		if consumer {
			a.required[key]--
		}
		if row.Tokens[0] == "-A" && strings.HasPrefix(row.Tokens[1], "RZG_") {
			coordinate := networkPolicyChainCoordinate(row)
			order := a.gateOrder[coordinate]
			position := positions[coordinate]
			offset := slices.Index(order[position:], key)
			if offset < 0 {
				return lanPolicyPreflightAt("inventory-row-order", ErrLANPolicyRuntime)
			}
			positions[coordinate] = position + offset + 1
		}
	}
	for _, count := range a.required {
		if count != 0 {
			return lanPolicyPreflightAt("inventory-consumer-required", ErrNetworkPolicyConsumers)
		}
	}
	for _, count := range stock {
		if count != 0 {
			return lanPolicyPreflightAt("inventory-consumer-required", ErrNetworkPolicyConsumers)
		}
	}
	return nil
}

func networkPolicyReservedChain(value string) bool {
	for _, prefix := range []string{"RZG_", "RZP_", "RZC_", "RZD_", "RZQ_", "RZT_"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func networkPolicyReferencesPrefix(tokens []string, prefix string) bool {
	for i := 2; i+1 < len(tokens); i++ {
		if tokens[i] == "--comment" {
			i++
			continue
		}
		if (tokens[i] == "-j" || tokens[i] == "-g" || tokens[i] == "--jump" || tokens[i] == "--goto") && strings.HasPrefix(tokens[i+1], prefix) {
			return true
		}
	}
	return false
}

func networkPolicyReservedRow(tokens []string) (bool, error) {
	return networkPolicyReservedRowForMode(tokens, "")
}

func networkPolicyReservedRowForMode(tokens []string, mode string) (bool, error) {
	if mode != "" && mode != LANPolicyNFQWSDirectMode {
		return false, ErrBackendInventoryUnknown
	}
	if len(tokens) < 2 {
		return false, ErrBackendInventoryUnknown
	}
	switch tokens[0] {
	case "-N":
		if len(tokens) != 2 {
			return false, ErrBackendInventoryUnknown
		}
	case "-P":
		if len(tokens) != 3 {
			return false, ErrBackendInventoryUnknown
		}
	case "-A":
		if len(tokens) < 4 {
			return false, ErrBackendInventoryUnknown
		}
	default:
		return false, ErrBackendInventoryUnknown
	}
	reserved := networkPolicyReservedChain(tokens[1])
	for i := 2; i < len(tokens); i++ {
		token := tokens[i]
		if token == "--comment" {
			if i+1 >= len(tokens) {
				return false, ErrBackendInventoryUnknown
			}
			i++ // A quoted comment is an inert single operand, never rule syntax.
			continue
		}
		option, operand, inline := strings.Cut(token, "=")
		switch option {
		case "--mark", "--set-mark", "--set-xmark", "--or-mark", "--xor-mark", "--tproxy-mark", "--nfmask", "--ctmask":
			if !inline {
				if i+1 >= len(tokens) {
					return false, ErrBackendInventoryUnknown
				}
				i++
				operand = tokens[i]
			}
			reserved = reserved || mode != LANPolicyNFQWSDirectMode && lanPolicyMarkTouches(operand)
		case "--and-mark", "--restore-mark", "--save-mark":
			reserved = reserved || mode != LANPolicyNFQWSDirectMode
		case "-j", "-g", "--jump", "--goto", "-m", "--match":
			if !inline {
				if i+1 >= len(tokens) {
					return false, ErrBackendInventoryUnknown
				}
				i++
				operand = tokens[i]
			}
			if option == "-m" || option == "--match" {
				reserved = reserved || mode != LANPolicyNFQWSDirectMode && operand == "connmark"
			} else {
				reserved = reserved || networkPolicyReservedChain(operand) || slices.Contains([]string{"NFQUEUE", "QUEUE"}, operand) || mode != LANPolicyNFQWSDirectMode && slices.Contains([]string{"CONNMARK", "HMARK"}, operand)
			}
		default:
			if strings.HasPrefix(option, "--") && strings.Contains(option, "mark") {
				reserved = reserved || mode != LANPolicyNFQWSDirectMode
			}
		}
	}
	return reserved, nil
}
