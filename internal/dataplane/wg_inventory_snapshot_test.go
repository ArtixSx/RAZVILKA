package dataplane

import (
	"context"
	"reflect"
	"slices"
	"testing"
)

// The existing lifecycle fixture writes real COMMON files but models kernel
// commands. Read the stateful firewall model through the production -S parser;
// this is comparison regression coverage, never native network evidence.
func wgInventorySnapshotFixture(t *testing.T) (*WARPWireGuardAdapter, warpWGPolicyReference, wgNetworkEffects, BackendInventorySnapshot) {
	t.Helper()
	a, _, _, ctx, ref, effects, firewall := committedWGNetworkEffectFixture(t)
	var rows []BackendInventoryRow
	for _, family := range []int{4, 6} {
		name := "iptables"
		if family == 6 {
			name = "ip6tables"
		}
		for _, table := range []string{"filter", "nat"} {
			data, err := firewall.Run(ctx, name, "-t", table, "-S")
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := backendXTablesRows(data, &backendClassicBudget{})
			if err != nil {
				t.Fatal(err)
			}
			for _, tokens := range parsed {
				rows = append(rows, BackendInventoryRow{Family: family, Table: table, Tokens: tokens})
			}
		}
	}
	identity, _ := networkPolicyIdentityFixture()
	image := networkPolicyInventoryTestImage(identity.value, rows)
	// Pure helpers must never call this runner, including at closing checks.
	a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("pure snapshot comparison invoked an external command")
		return nil, ErrNetworkPolicyConsumers
	})
	return a, ref, effects, image
}

func TestWGInventorySnapshotCompleteImageAndDetachedRows(t *testing.T) {
	a, ref, effects, image := wgInventorySnapshotFixture(t)
	rows, required, err := a.wgNetworkInventoryAllowance(ref, effects, image)
	if err != nil || len(rows) != len(effects.firewall) || len(rows) != len(required) {
		t.Fatal("complete mixed firewall image refused", len(rows), len(effects.firewall), err)
	}
	for _, need := range required {
		if !need {
			t.Fatal("complete effect was made optional")
		}
	}
	before := cloneNetworkPolicyInventoryTestRows(image.Rows)
	rows[0].Tokens[1] = "changed"
	if !reflect.DeepEqual(before, image.Rows) {
		t.Fatal("returned row aliases the whole snapshot")
	}
	for _, row := range before {
		if row.Tokens[0] == "-A" && row.Tokens[1] == ref.Policy.Forwarding.Chain && row.Table == "nat" && wgNetworkInventoryRowKey(row) == "" {
			t.Fatal("exact SNAT row has no union key")
		}
	}
}

func TestWGInventorySnapshotRejectsMissingDuplicateForeignAndShadowedRows(t *testing.T) {
	a, ref, effects, original := wgInventorySnapshotFixture(t)
	chain := ref.Policy.Forwarding.Chain
	own := slices.IndexFunc(original.Rows, func(row BackendInventoryRow) bool {
		return row.Table == "nat" && row.Tokens[0] == "-A" && row.Tokens[1] == chain
	})
	jump := slices.IndexFunc(original.Rows, func(row BackendInventoryRow) bool {
		return row.Family == 4 && row.Table == "nat" && row.Tokens[0] == "-A" && row.Tokens[1] == "POSTROUTING" && wgNetworkInventoryReferencesChain(row.Tokens, chain)
	})
	if own < 0 || jump < 0 {
		t.Fatal("model lacks own SNAT and parent attachment")
	}
	for _, cut := range []string{"missing", "duplicate", "foreign-SNAT", "foreign-reference", "unknown-body", "foreign-chain", "wrong-table", "wrong-family", "duplicate-selector", "shadowed-NAT", "body-order", "missing-v6", "incomplete", "native-NFT"} {
		t.Run(cut, func(t *testing.T) {
			image := original
			image.Rows = cloneNetworkPolicyInventoryTestRows(original.Rows)
			switch cut {
			case "missing":
				image.Rows = slices.Delete(image.Rows, own, own+1)
			case "duplicate":
				image.Rows = append(image.Rows, image.Rows[own])
			case "foreign-SNAT":
				image.Rows[own].Tokens[len(image.Rows[own].Tokens)-1] = "10.66.0.3"
			case "foreign-reference":
				image.Rows = append(image.Rows, BackendInventoryRow{Family: 4, Table: "custom", Tokens: []string{"-A", "OTHER", "-j", chain}})
			case "unknown-body":
				image.Rows = append(image.Rows, BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", chain, "-j", "RETURN"}})
			case "foreign-chain":
				image.Rows = append(image.Rows, BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-N", chain + "_other"}})
			case "wrong-table":
				image.Rows[own].Table = "filter"
			case "wrong-family":
				image.Rows[own].Family = 6
			case "duplicate-selector":
				image.Rows[own].Tokens = append(image.Rows[own].Tokens, "-s", "0.0.0.0/0")
			case "shadowed-NAT":
				firmware := BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "POSTROUTING", "-j", "MASQUERADE"}}
				image.Rows = slices.Insert(image.Rows, jump, firmware)
			case "body-order":
				var positions []int
				for i, row := range image.Rows {
					if row.Family == 4 && row.Table == "filter" && row.Tokens[0] == "-A" && row.Tokens[1] == chain {
						positions = append(positions, i)
					}
				}
				if len(positions) < 2 {
					t.Fatal("missing forward/return model pair")
				}
				image.Rows[positions[0]], image.Rows[positions[1]] = image.Rows[positions[1]], image.Rows[positions[0]]
			case "missing-v6":
				image.Rows = slices.DeleteFunc(image.Rows, func(row BackendInventoryRow) bool { return row.Family == 6 })
			case "incomplete":
				image.Coverage.RegisteredTablesComplete = false
			case "native-NFT":
				image.NFTState = BackendNFTPresent
			}
			if rows, needs, err := a.wgNetworkInventoryAllowance(ref, effects, image); err == nil || rows != nil || needs != nil {
				t.Fatal("changed complete image admitted", cut, rows, needs, err)
			}
		})
	}
}

func TestWGInventorySnapshotBorrowedStatesUseOnlySameImage(t *testing.T) {
	a, ref, effects, image := wgInventorySnapshotFixture(t)
	states := make([]string, len(effects.plan.Effects))
	for i := range states {
		states[i] = "added"
	}
	index := -1
	for i, effect := range effects.firewall {
		if !effect.creation && !effect.attachment && effect.table.table == "nat" && !effect.table.v6 {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("no SNAT effect")
	}
	effect := effects.firewall[index]
	key := wgNetworkInventoryRowKey(BackendInventoryRow{Family: 4, Table: "nat", Tokens: append([]string{"-A", effect.chain}, effect.rule...)})
	for _, state := range []string{"intent", "cleanup-intent"} {
		states[index] = state
		if _, _, err := a.wgNetworkInventoryReceiptAllowance(ref, effects, states, false, image); err == nil {
			t.Fatal("unborrowed unsettled receipt admitted", state)
		}
		for _, present := range []bool{false, true} {
			copy := image
			copy.Rows = cloneNetworkPolicyInventoryTestRows(image.Rows)
			if !present {
				copy.Rows = slices.DeleteFunc(copy.Rows, func(row BackendInventoryRow) bool { return wgNetworkInventoryRowKey(row) == key })
			}
			rows, required, err := a.wgNetworkInventoryReceiptAllowance(ref, effects, states, true, copy)
			if err != nil {
				t.Fatal("borrowed optional intent refused", state, present, err)
			}
			found := false
			for i, row := range rows {
				if wgNetworkInventoryRowKey(row) == key {
					found = true
					if required[i] {
						t.Fatal("intent row became required")
					}
				}
			}
			if found != present {
				t.Fatal("allowance manufactured a row absent from this image")
			}
		}
	}
	for _, state := range []string{"planned", "removed", "unknown", ""} {
		states[index] = state
		if _, _, err := a.wgNetworkInventoryReceiptAllowance(ref, effects, states, true, image); err == nil {
			t.Fatal("receipt state explains opposed existing row", state)
		}
	}
	states[index] = "added"
	if _, _, err := a.wgNetworkInventoryReceiptAllowance(ref, effects, states[:len(states)-1], true, image); err == nil {
		t.Fatal("incomplete receipt admitted")
	}
	changed := effects
	changed.routing++
	if _, _, err := a.wgNetworkInventoryAllowance(ref, changed, image); err == nil {
		t.Fatal("different mixed effect plan admitted")
	}
	ref.Checksum = "changed"
	if _, _, err := a.wgNetworkInventoryAllowance(ref, effects, image); err == nil {
		t.Fatal("corrupt policy reference admitted")
	}
}

func TestWGInventorySnapshotPlannedAbsenceAndInertFirmwareComment(t *testing.T) {
	a, ref, effects, image := wgInventorySnapshotFixture(t)
	states := make([]string, len(effects.plan.Effects))
	for i := range states {
		states[i] = "planned"
	}
	chain := ref.Policy.Forwarding.Chain
	image.Rows = slices.DeleteFunc(image.Rows, func(row BackendInventoryRow) bool {
		return row.Tokens[1] == chain || wgNetworkInventoryReferencesChain(row.Tokens, chain)
	})
	image.Rows = append(image.Rows, BackendInventoryRow{Family: 4, Table: "custom", Tokens: []string{"-A", "OTHER", "-m", "comment", "--comment", "-j " + chain, "-j", "ACCEPT"}})
	rows, required, err := a.wgNetworkInventoryReceiptAllowance(ref, effects, states, true, image)
	if err != nil || len(rows) != 0 || len(required) != 0 {
		t.Fatal("planned absence manufactured allowance or parsed inert comment", rows, required, err)
	}
	for i := range states {
		states[i] = "removed"
	}
	if _, _, err := a.wgNetworkInventoryReceiptAllowance(ref, effects, states, false, image); err != nil {
		t.Fatal("complete removed receipt rejected absent tuples", err)
	}
}
