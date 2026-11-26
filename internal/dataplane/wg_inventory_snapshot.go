package dataplane

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
)

// These helpers compare one complete firewall image only. Neither a reference,
// a receipt state string nor the returned rows establish consumer ownership.
// CORE must first authenticate the original scope-issued WG owner and anchored
// COMMON observation, and separately bracket full routing/endpoint readback.
func (a *WARPWireGuardAdapter) wgNetworkInventoryAllowance(ref warpWGPolicyReference, effects wgNetworkEffects, snapshot BackendInventorySnapshot) ([]BackendInventoryRow, []bool, error) {
	states := make([]string, len(effects.plan.Effects))
	for i := range states {
		states[i] = "added"
	}
	return a.wgNetworkInventoryReceiptAllowance(ref, effects, states, false, snapshot)
}

// No command, Provider, control or owner callback runs here. Optional states
// are meaningful only after CORE authenticates a borrowed original COMMON
// writer. Return only matched rows from THIS image, with detached token slices.
func (a *WARPWireGuardAdapter) wgNetworkInventoryReceiptAllowance(ref warpWGPolicyReference, effects wgNetworkEffects, states []string, borrowed bool, snapshot BackendInventorySnapshot) ([]BackendInventoryRow, []bool, error) {
	if a == nil || a.IP == "" || a.IPTables == "" || a.IP6Tables == "" {
		return nil, nil, ErrNetworkPolicyConsumers
	}
	if err := snapshot.RequireComplete(); err != nil {
		return nil, nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	if err := a.validWGPolicyReference(ref); err != nil {
		return nil, nil, err
	}
	compiled, err := a.compileWGNetworkEffects(ref)
	if err != nil || !reflect.DeepEqual(compiled, effects) || len(states) != len(compiled.plan.Effects) {
		return nil, nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	type expectedRow struct {
		required bool
		index    int
	}
	expected := map[string]expectedRow{}
	chain := ref.Policy.Forwarding.Chain
	for i, state := range states {
		switch state {
		case "planned", "removed", "added":
		case "intent", "cleanup-intent":
			if !borrowed {
				return nil, nil, ErrPolicyAdditionReceipt
			}
		default:
			return nil, nil, ErrPolicyAdditionReceipt
		}
		effect, firewall := compiled.firewall[i]
		if !firewall || state == "planned" || state == "removed" {
			continue
		}
		family := 4
		if effect.table.v6 {
			family = 6
		}
		tokens := []string{"-N", effect.chain}
		if !effect.creation {
			tokens = append([]string{"-A", effect.chain}, effect.rule...)
		}
		key := wgNetworkInventoryRowKey(BackendInventoryRow{Family: family, Table: effect.table.table, Tokens: tokens})
		if key == "" {
			return nil, nil, ErrWGNetworkPolicy
		}
		if _, duplicate := expected[key]; duplicate {
			return nil, nil, ErrWGNetworkPolicy
		}
		expected[key] = expectedRow{required: state == "added", index: i}
	}
	seen := map[string]bool{}
	lastBody := map[string]int{}
	natForeign := map[int]bool{}
	var rows []BackendInventoryRow
	var required []bool
	for _, row := range snapshot.Rows {
		if row.Family != 4 && row.Family != 6 || !backendClassicTableName(row.Table) || len(row.Tokens) < 2 || len(row.Tokens) > 128 {
			return nil, nil, ErrBackendInventoryUnknown
		}
		ownsChain := strings.HasPrefix(row.Tokens[1], chain)
		references := wgNetworkInventoryReferencesChain(row.Tokens, chain)
		if row.Table == "nat" && row.Tokens[0] == "-A" && row.Tokens[1] == "POSTROUTING" {
			if references && natForeign[row.Family] {
				return nil, nil, ErrWGNetworkPolicy
			}
			if !references {
				natForeign[row.Family] = true
			}
		}
		if !ownsChain && !references {
			continue // Other consumers/firmware remain for CORE's full union.
		}
		key := wgNetworkInventoryRowKey(row)
		want, allowed := expected[key]
		if key == "" || !allowed || seen[key] {
			return nil, nil, ErrWGNetworkPolicy
		}
		seen[key] = true
		if ownsChain && row.Tokens[0] == "-A" {
			coordinate := networkPolicyChainCoordinate(row)
			if previous, exists := lastBody[coordinate]; exists && previous >= want.index {
				return nil, nil, ErrWGNetworkPolicy
			}
			lastBody[coordinate] = want.index
		}
		rows = append(rows, BackendInventoryRow{Family: row.Family, Table: row.Table, Tokens: slices.Clone(row.Tokens)})
		required = append(required, want.required)
	}
	for key, want := range expected {
		if want.required && !seen[key] {
			return nil, nil, ErrWGNetworkPolicy
		}
	}
	return rows, required, nil
}

// Scope coordinates and exact SNAT address stay in the key. Only the existing
// WG readback grammar normalizes canonical same-family universe elision.
func wgNetworkInventoryRowKey(row BackendInventoryRow) string {
	if row.Family != 4 && row.Family != 6 || row.Table != "filter" && row.Table != "nat" || len(row.Tokens) < 2 {
		return ""
	}
	body := ""
	switch row.Tokens[0] {
	case "-N":
		if len(row.Tokens) != 2 {
			return ""
		}
	case "-A":
		body = wgNetworkFirewallKey(row.Tokens[2:], row.Family == 6)
		if strings.HasPrefix(body, "!") {
			return ""
		}
	default:
		return ""
	}
	data, _ := json.Marshal([]any{row.Family, row.Table, row.Tokens[0], row.Tokens[1], body})
	return string(data)
}

func wgNetworkInventoryReferencesChain(tokens []string, chain string) bool {
	for i := 2; i+1 < len(tokens); i++ {
		if tokens[i] == "--comment" {
			i++
			continue
		}
		if (tokens[i] == "-j" || tokens[i] == "-g" || tokens[i] == "--jump" || tokens[i] == "--goto") && strings.HasPrefix(tokens[i+1], chain) {
			return true
		}
	}
	return false
}
