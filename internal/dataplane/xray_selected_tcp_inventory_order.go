package dataplane

import (
	"strings"
)

// Counts alone cannot prove the negative RETURN rules precede REDIRECT, or
// that repeated insert-at-one selectors retain their actual native order.
// Compare each chain's ordered owned subsequence against the actual writer's
// effect sequence. Only its in-flight intent may be missing at this instant.
func xraySelectedTCPInventoryOrder(snapshot BackendInventorySnapshot, observations []networkPolicyXraySelectedTCPObservation) error {
	if snapshot.RequireComplete() != nil {
		return ErrNetworkPolicyConsumers
	}
	type expectedRow struct {
		row      BackendInventoryRow
		key      string
		required bool
	}
	expected := make(map[string][]expectedRow)
	for _, o := range observations {
		if len(o.rows) != len(o.required) {
			return ErrNetworkPolicyConsumers
		}
		for i, row := range o.rows {
			if !networkPolicyXraySelectedTCPRow(row) {
				return ErrNetworkPolicyConsumers
			}
			if row.Tokens[0] == "-N" {
				continue // Existence/count is checked by the whole inventory predicate.
			}
			if row.Tokens[0] != "-A" {
				return ErrNetworkPolicyConsumers
			}
			chain := row.Tokens[1]
			key, err := xraySelectedTCPNATRuleKey(row)
			if err != nil {
				return err
			}
			value := expectedRow{row: row, key: key, required: o.required[i]}
			if chain == "PREROUTING" {
				expected[chain] = append([]expectedRow{value}, expected[chain]...)
			} else if strings.HasPrefix(chain, "RZX_") {
				expected[chain] = append(expected[chain], value)
			} else {
				return ErrNetworkPolicyConsumers
			}
		}
	}
	actual := make(map[string][]BackendInventoryRow)
	for _, row := range snapshot.Rows {
		if !networkPolicyXraySelectedTCPRow(row) || row.Tokens[0] == "-N" {
			continue
		}
		if row.Tokens[0] != "-A" {
			return ErrNetworkPolicyConsumers
		}
		actual[row.Tokens[1]] = append(actual[row.Tokens[1]], row)
	}
	for chain, rows := range actual {
		want, present := expected[chain]
		if !present {
			return ErrNetworkPolicyConsumers
		}
		cursor := 0
		for _, row := range rows {
			key, err := xraySelectedTCPNATRuleKey(row)
			if err != nil {
				return err
			}
			for cursor < len(want) && want[cursor].key != key && !want[cursor].required {
				cursor++
			}
			if cursor == len(want) || want[cursor].key != key {
				return ErrNetworkPolicyConsumers
			}
			cursor++
		}
		for _, remaining := range want[cursor:] {
			if remaining.required {
				return ErrNetworkPolicyConsumers
			}
		}
		delete(expected, chain)
	}
	for _, rows := range expected {
		for _, row := range rows {
			if row.required {
				return ErrNetworkPolicyConsumers
			}
		}
	}
	return nil
}
