package dataplane

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func networkPolicyInventoryTestImage(identity netidentity.Identity, rows []BackendInventoryRow) BackendInventorySnapshot {
	return BackendInventorySnapshot{Schema: 1, Scope: backendInventoryScope{Network: identity, ToolReviewID: strings.Repeat("a", 64)},
		Coverage: BackendInventoryCoverage{LegacyRegisteredBothFamilies: true, NativeNFTAllFamilies: true, RegisteredTablesComplete: true}, NFTState: BackendNFTEmpty, NFTGeneration: 7, Rows: rows}
}

func networkPolicyInventoryLANRows(lan *LANPolicyRuntimePlan) []BackendInventoryRow {
	var rows []BackendInventoryRow
	for _, chain := range lanPolicyChains(lan) {
		rows = append(rows, BackendInventoryRow{Family: chain.family, Table: "mangle", Tokens: []string{"-N", chain.name}})
		for _, rule := range chain.rules {
			rows = append(rows, BackendInventoryRow{Family: chain.family, Table: "mangle", Tokens: append([]string{"-A", chain.name}, slices.Clone(rule)...)})
		}
		rows = append(rows, BackendInventoryRow{Family: chain.family, Table: "mangle", Tokens: append([]string{"-A", "PREROUTING"}, slices.Clone(chain.jump)...)})
	}
	return rows
}

func cloneNetworkPolicyInventoryTestRows(rows []BackendInventoryRow) []BackendInventoryRow {
	rows = slices.Clone(rows)
	for i := range rows {
		rows[i].Tokens = slices.Clone(rows[i].Tokens)
	}
	return rows
}

func TestNetworkPolicyInventoryExactPartialGateAndInertComments(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	lan := lanRuntimeFixture(t)
	rows := networkPolicyInventoryLANRows(lan)
	rows = append(rows, BackendInventoryRow{Family: 6, Table: "custom", Tokens: []string{"-A", "OUTPUT", "-m", "comment", "--comment", "RZG_foreign CONNMARK --mark 0x20000000/0x28000000", "-j", "ACCEPT"}})
	for _, partial := range []bool{false, true} {
		image := cloneNetworkPolicyInventoryTestRows(rows)
		if partial {
			image = append(image[:3], image[5:]...)
		}
		if err := CheckLANPolicyInventory(networkPolicyInventoryTestImage(identity.value, image), identity.value, lan); err != nil {
			t.Fatal("exact full/partial body rejected", partial, err)
		}
		if err := CheckLANPolicyInventory(networkPolicyInventoryTestImage(identity.value, image), identity.value, nil); !errors.Is(err, ErrLANPolicyRuntime) {
			t.Fatal("absent owner adopted an existing gate", partial, err)
		}
	}
	if err := CheckLANPolicyInventory(networkPolicyInventoryTestImage(identity.value, rows[len(rows)-1:]), identity.value, nil); err != nil {
		t.Fatal("quoted comment was interpreted as rule authority", err)
	}
}

func TestNetworkPolicyInventoryRejectsEveryTableFamilyAndForeignMarkForms(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	lan := lanRuntimeFixture(t)
	for _, family := range []int{4, 6} {
		for _, table := range []string{"mangle", "nat", "filter", "raw", "security", "custom_table"} {
			for _, tokens := range [][]string{
				{"-N", "RZG_orphan"}, {"-A", "OUTPUT", "-g", lanPolicyChains(lan)[0].name},
				{"-A", "OUTPUT", "-m", "mark", "--mark", LANPolicyGateMatch, "-j", "ACCEPT"},
				{"-A", "OUTPUT", "-j", "MARK", "--set-xmark", "0x20000000/0x28000000"},
				{"-A", "OUTPUT", "-j", "TPROXY", "--tproxy-mark=0x20000000/0x28000000"},
				{"-A", "OUTPUT", "-j", "CONNMARK", "--restore-mark"},
				{"-A", "OUTPUT", "-j", "HMARK", "--hmark-mod", "8"},
				{"-A", "OUTPUT", "-j", "MARK", "--and-mark", "0xffffffff"},
				{"-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "71"},
				{"-A", "OUTPUT", "-m", "mark", "--mark", "invalid", "-j", "ACCEPT"},
			} {
				rows := networkPolicyInventoryLANRows(lan)
				rows = append(rows, BackendInventoryRow{Family: family, Table: table, Tokens: tokens})
				if err := CheckLANPolicyInventory(networkPolicyInventoryTestImage(identity.value, rows), identity.value, lan); err == nil {
					t.Fatal("foreign row accepted", family, table, tokens)
				}
			}
		}
	}
}

func TestNetworkPolicyInventoryRejectsDuplicateOrderMaskAndIncompleteCoverage(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	lan := lanRuntimeFixture(t)
	for _, fault := range []string{"duplicate", "order", "mask", "table", "family", "incomplete", "nft", "identity"} {
		t.Run(fault, func(t *testing.T) {
			rows := cloneNetworkPolicyInventoryTestRows(networkPolicyInventoryLANRows(lan))
			image := networkPolicyInventoryTestImage(identity.value, rows)
			switch fault {
			case "duplicate":
				image.Rows = append(image.Rows, rows[1])
			case "order":
				image.Rows[1], image.Rows[2] = image.Rows[2], image.Rows[1]
			case "mask":
				image.Rows[1].Tokens[len(image.Rows[1].Tokens)-1] = "0x0/0x20000000"
			case "table":
				image.Rows[0].Table = "custom"
			case "family":
				image.Rows[0].Family = 6
			case "incomplete":
				image.Coverage.RegisteredTablesComplete = false
			case "nft":
				image.NFTState = BackendNFTPresent
				image.NFTTables = []BackendNFTTable{{Family: 7, Name: "foreign"}}
			case "identity":
				image.Scope.Network.Inode++
			}
			if err := CheckLANPolicyInventory(image, identity.value, lan); err == nil {
				t.Fatal("changed/unknown image accepted", fault)
			}
		})
	}
}

func TestNetworkPolicyInventoryPositiveMarkAloneNeverAllowsConsumer(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	lan := lanRuntimeFixture(t)
	row := BackendInventoryRow{Family: 4, Table: "filter", Tokens: []string{"-A", "FORWARD", "-i", "br0", "-o", "rz-xray", "-s", "192.168.1.25/32", "-d", "8.8.8.8/32", "-m", "mark", "--mark", LANPolicyGateMatch, "-j", "RZP_unreceipted"}}
	if err := CheckLANPolicyInventory(networkPolicyInventoryTestImage(identity.value, []BackendInventoryRow{row}), identity.value, lan); err == nil {
		t.Fatal("positive mark/name manufactured receipt authority")
	}
}
