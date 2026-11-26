package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Actual original COMMON writer/strict receipt and complete observation
// predicate, with explicit queue/kernel models. No native NFQ/App claim.
func TestNetworkPolicyNFQInventoryReadsActualCOMMONPartialAndComplete(t *testing.T) {
	b, m, root := nfqwsScopedBindingFixture(t)
	identity, _ := networkPolicyIdentityFixture()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reads := 0
	lanCheck := b.VerifyLAN
	b.VerifyLAN = func(c context.Context, lan *LANPolicyRuntimePlan) error {
		if err := lanCheck(c, lan); err != nil {
			return err
		}
		borrow, present, err := observeBorrowedPolicyEffects(c, m.p.mixed, root)
		if err != nil {
			return errors.Join(ErrPolicyAdditionReceipt, err)
		}
		defer borrow.close()
		observation := networkPolicyNFQObservation{absent: present && borrow.absent}
		states := borrow.states
		var complete networkPolicyReceiptObservation
		defer func() { complete.close() }()
		if !present {
			complete, err = observeNetworkPolicyEffects(c, m.p.mixed, root, b.options)
			if err != nil || !complete.status.Complete {
				return errors.Join(ErrPolicyAdditionReceipt, err)
			}
			states = make([]string, len(m.p.mixed.Effects))
			for i := range states {
				states[i] = "added"
			}
		}
		if !observation.absent {
			observation.rows, observation.required, err = networkPolicyNFQReceiptRows(m.p, states, present)
			if err != nil {
				return err
			}
		}
		rows := networkPolicyInventoryLANRows(lan)
		for _, tool := range []string{"iptables", "ip6tables"} {
			family := 4
			if tool == "ip6tables" {
				family = 6
			}
			out, err := m.Run(c, tool, "-t", "mangle", "-S")
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(out), "\n") {
				if line == "" {
					continue
				}
				tokens, err := backendXTablesRowTokens(line)
				if err != nil {
					return err
				}
				rows = append(rows, BackendInventoryRow{Family: family, Table: "mangle", Tokens: tokens})
			}
		}
		reads++
		if err := checkNetworkPolicyInventory(networkPolicyInventoryTestImage(identity.value, rows), identity.value, lan, nil, observation); err != nil {
			return err
		}
		if present {
			return borrow.current(c)
		}
		return complete.current()
	}
	if err := b.Apply(ctx, m.p, root); err != nil {
		t.Fatal("actual COMMON prefix failed shared predicate", err)
	}
	if reads < 4 || len(m.calls) != len(m.p.mixed.Effects) {
		t.Fatal("partial/full phase reads missing", reads, m.calls)
	}
	o, err := observeNetworkPolicyEffects(ctx, m.p.mixed, root, b.options)
	if err != nil || !o.status.Complete || o.status.Unknown {
		t.Fatal("strict original complete receipt refused", o.status, err)
	}
	defer o.close()
	if err := o.current(); err != nil {
		t.Fatal("original complete file/marker bookends", err)
	}
	data, err := os.ReadFile(filepath.Join(root, policyAdditionFile))
	if err != nil {
		t.Fatal(err)
	}
	var changed policyAdditionDocument
	if json.Unmarshal(data, &changed) != nil {
		t.Fatal("invalid actual original receipt")
	}
	changed.ID = strings.Repeat("8", 32)
	changed.Checksum = policyAdditionChecksum(changed)
	data, _ = json.Marshal(changed)
	if err := os.WriteFile(filepath.Join(root, policyAdditionFile), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := o.current(); !errors.Is(err, ErrPolicyAdditionReceipt) {
		t.Fatal("in-place canonical receipt identity change adopted", err)
	}
}

func TestNetworkPolicyNFQInventoryRefusesMissingDuplicateForeignAndPendingReplay(t *testing.T) {
	_, _, p := nfqwsScopedFixture(t)
	identity, _ := networkPolicyIdentityFixture()
	states := make([]string, len(p.mixed.Effects))
	for i := range states {
		states[i] = "added"
	}
	rows, required, err := networkPolicyNFQReceiptRows(p, states, false)
	if err != nil {
		t.Fatal(err)
	}
	observation := networkPolicyNFQObservation{rows: rows, required: required}
	whole := append(networkPolicyInventoryLANRows(p.lan), cloneNetworkPolicyInventoryTestRows(rows)...)
	if err := checkNetworkPolicyInventory(networkPolicyInventoryTestImage(identity.value, whole), identity.value, p.lan, nil, observation); err != nil {
		t.Fatal("full exact compiled rows refused", err)
	}
	for _, fault := range []string{"missing", "duplicate", "queue", "transport", "family", "table", "foreign-reference"} {
		t.Run(fault, func(t *testing.T) {
			copy := cloneNetworkPolicyInventoryTestRows(whole)
			i := len(copy) - 1
			switch fault {
			case "missing":
				copy = copy[:i]
			case "duplicate":
				copy = append(copy, copy[i])
			case "queue":
				copy = append(copy, BackendInventoryRow{Family: 4, Table: "raw", Tokens: []string{"-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "1"}})
			case "transport":
				copy[i].Tokens = append(copy[i].Tokens, "-p", "udp")
			case "family":
				copy[i].Family = 4
			case "table":
				copy[i].Table = "nat"
			case "foreign-reference":
				copy = append(copy, BackendInventoryRow{Family: 6, Table: "filter", Tokens: []string{"-A", "OUTPUT", "-j", p.chains[0].name}})
			}
			if err := checkNetworkPolicyInventory(networkPolicyInventoryTestImage(identity.value, copy), identity.value, p.lan, nil, observation); err == nil {
				t.Fatal("foreign/incomplete capture accepted", fault)
			}
		})
	}
	states[len(states)-1] = "intent"
	if _, _, err := networkPolicyNFQReceiptRows(p, states, false); err == nil {
		t.Fatal("ordinary reader promoted pending intent")
	}
	states[0] = "planned"
	if _, _, err := networkPolicyNFQReceiptRows(p, states, true); err == nil {
		t.Fatal("broken original prefix accepted")
	}
}

func TestNetworkPolicyNFQInventoryMissingReceiptNeverCreatesMarker(t *testing.T) {
	_, _, p := nfqwsScopedFixture(t)
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if o, err := observeNetworkPolicyEffects(ctx, p.mixed, root, policyAdditionOptions{}); err == nil {
		o.close()
		t.Fatal("missing original receipt accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("readonly observer created permanent lock", entries, err)
	}
}
