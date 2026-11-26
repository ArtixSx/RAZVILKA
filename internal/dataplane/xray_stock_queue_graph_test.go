package dataplane

import (
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Complete pure graph models, never original Xray runtime/owner authority.
func TestXrayStockOutputQueueNoOwnedQueueAndDetachedComparison(t *testing.T) {
	for _, queues := range [][2]uint16{{0, 65535}, {64511, 64512}, {40321, 40322}} {
		t.Run(strconv.Itoa(int(queues[0])), func(t *testing.T) {
			snapshot := nfqwsDirectStockReviewedVendorFixture()
			var expected []BackendInventoryRow
			for i, family := range []int{4, 6} {
				index := nfqwsDirectStockTestQueueIndex(snapshot, family)
				snapshot.Rows[index].Tokens[len(snapshot.Rows[index].Tokens)-1] = strconv.Itoa(int(queues[i]))
				expected = append(expected, snapshot.Rows[index])
			}
			// The accepted selected-TCP consumer has only local NAT effects.
			// Their ownership and exact receipt counts remain caller checks.
			snapshot.Rows = append(snapshot.Rows,
				nfqwsDirectStockTestRow(4, "nat", "-N", "RZX_123456789abc"),
				nfqwsDirectStockTestRow(4, "nat", "-A", "RZX_123456789abc", "-d", "192.0.2.1/32", "-j", "RETURN"),
				nfqwsDirectStockTestRow(4, "nat", "-A", "RZX_123456789abc", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "12345"),
				nfqwsDirectStockTestRow(4, "nat", "-A", "PREROUTING", "-i", "br0", "-s", "192.0.2.0/24", "-p", "tcp", "-j", "RZX_123456789abc"),
			)
			before := nfqwsDirectStockTestClone(snapshot)
			got, err := inspectXrayStockOutputQueues(snapshot)
			if err != nil || !reflect.DeepEqual(got, expected) || !reflect.DeepEqual(snapshot, before) {
				t.Fatal("no-queue comparison refused or changed actual image", err)
			}
			got[0].Tokens[1] = "changed"
			if !reflect.DeepEqual(snapshot, before) {
				t.Fatal("comparison aliases original capture")
			}
		})
	}
}

func TestXrayStockOutputQueueCannotRelaxNFQReservationCollision(t *testing.T) {
	snapshot := nfqwsDirectStockQueueFixture()
	index := nfqwsDirectStockTestQueueIndex(snapshot, 4)
	snapshot.Rows[index].Tokens[len(snapshot.Rows[index].Tokens)-1] = "40321"
	if rows, err := inspectXrayStockOutputQueues(snapshot); err != nil || len(rows) != 2 {
		t.Fatal("Xray invented an owned queue collision", err)
	}
	nfqwsDirectStockTestRefused(t, snapshot, 40321)
	nfqwsDirectStockTestRefused(t, snapshot, 0)
	ownedSnapshot, managed, owned := nfqwsDirectStockOwnedFixture(t, "ipv4")
	if rows, err := inspectNFQWSDirectStockQueuesWithOwned(ownedSnapshot, managed, owned); err != nil || len(rows) != 2 {
		t.Fatal("original NFQ owned comparison changed", err)
	}
	if rows, err := inspectXrayStockOutputQueues(ownedSnapshot); rows != nil || !errors.Is(err, errXrayStockOutputQueue) {
		t.Fatal("Xray adopted another consumer's owned NFQ graph")
	}
	if rows, err := inspectStockOutputQueueGraph(ownedSnapshot, nil, owned); rows != nil || err == nil {
		t.Fatal("no reservation accepted an owned NFQ exemption")
	}
}

func TestXrayStockOutputQueueKeepsCompleteConservativeGraph(t *testing.T) {
	for _, cut := range []string{"other-hook", "goto-other-hook", "predicate-edge", "terminating-prefix", "orphan", "cycle", "dangling", "unknown-target", "unknown-option", "unreviewed-vendor", "raw-queue", "unknown-queue-mode", "reserved-mangle", "xray-mangle", "incomplete", "missing-family", "missing-hook"} {
		t.Run(cut, func(t *testing.T) {
			snapshot := nfqwsDirectStockReviewedVendorFixture()
			switch cut {
			case "other-hook":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "local_bridge"))
			case "goto-other-hook":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(6, "mangle", "-A", "INPUT", "-g", "local_delay"))
			case "predicate-edge":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-m", "connskip", "--connskip", "0", "-m", "set", "--match-set", "empty_set", "src", "!", "--update-counters", "-p", "tcp", "-m", "tls", "--tls-sni", "never.invalid", "-j", "local_bridge"))
			case "terminating-prefix":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "RETURN"), nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "local_bridge"))
			case "orphan":
				snapshot.Rows[nfqwsDirectStockTestQueueIndex(snapshot, 4)-2].Tokens = []string{"-A", "OUTPUT", "-j", "RETURN"}
			case "cycle":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "local_delay", "-g", "local_bridge"))
			case "dangling":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(6, "mangle", "-A", "OUTPUT", "-j", "missing"))
			case "unknown-target":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-j", "UNREVIEWED_NDM"))
			case "unknown-option":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "--unknown", "value", "-j", "RETURN"))
			case "unreviewed-vendor":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-m", "tls", "--tls-sni", "example.invalid", "-j", "RETURN"))
				snapshot.Scope.Network = nfqwsDirectStockQueueFixture().Scope.Network
				snapshot.NFTState, snapshot.NFTGeneration = BackendNFTEmpty, 7
			case "raw-queue":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "raw", "-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "64511"))
			case "unknown-queue-mode":
				snapshot.Rows[nfqwsDirectStockTestQueueIndex(snapshot, 4)].Tokens = append(snapshot.Rows[nfqwsDirectStockTestQueueIndex(snapshot, 4)].Tokens, "--queue-bypass")
			case "reserved-mangle":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-N", "RZG_123456789abc_0_4"))
			case "xray-mangle":
				snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-N", "RZX_123456789abc"), nfqwsDirectStockTestRow(4, "mangle", "-A", "PREROUTING", "-j", "RZX_123456789abc"))
			case "incomplete":
				snapshot.Coverage.RegisteredTablesComplete = false
			case "missing-family":
				snapshot.Rows = slices.DeleteFunc(snapshot.Rows, func(r BackendInventoryRow) bool { return r.Family == 6 })
			case "missing-hook":
				snapshot.Rows = slices.DeleteFunc(snapshot.Rows, func(r BackendInventoryRow) bool {
					return r.Family == 4 && r.Tokens[0] == "-P" && r.Tokens[1] == "POSTROUTING"
				})
			}
			before := nfqwsDirectStockTestClone(snapshot)
			if rows, err := inspectXrayStockOutputQueues(snapshot); rows != nil || !errors.Is(err, errXrayStockOutputQueue) {
				t.Fatal("unsafe no-owner graph accepted", cut, err)
			}
			if !reflect.DeepEqual(snapshot, before) {
				t.Fatal("refusal changed actual whole graph")
			}
		})
	}
}

func TestXrayStockOutputQueueNoQueueAndReviewedVocabulary(t *testing.T) {
	snapshot := nfqwsDirectStockReviewedVendorFixture()
	snapshot.Rows = slices.DeleteFunc(snapshot.Rows, func(r BackendInventoryRow) bool { return r.Table == "mangle" && slices.Contains(r.Tokens, "NFQUEUE") })
	if rows, err := inspectXrayStockOutputQueues(snapshot); err != nil || len(rows) != 0 {
		t.Fatal("complete no-queue image refused", err)
	}
	for _, family := range []int{4, 6} {
		snapshot.Rows = append(snapshot.Rows,
			nfqwsDirectStockTestRow(family, "mangle", "-A", "OUTPUT", "-m", "connskip", "--connskip", "1", "-m", "set", "--match-set", "stock_set", "src,dst", "--return-nomatch", "!", "--update-counters", "!", "--update-subcounters", "-p", "tcp", "-m", "tls", "!", "--tls-sni", "*.example.invalid", "-j", "NDMMARK", "--set-xndmmark", "0x20/0x20"),
			nfqwsDirectStockTestRow(family, "mangle", "-A", "OUTPUT", "-j", "CONNNDMMARK", "--restore-mark", "--nfmask", "0xffffffff", "--ctmask", "0xffffffff", "-m", "comment", "--comment", "inert NFQUEUE RZQ_ --queue-num 40321"),
		)
	}
	if rows, err := inspectXrayStockOutputQueues(snapshot); err != nil || len(rows) != 0 {
		t.Fatal("reviewed closed grammar changed no-queue comparison", err)
	}
	// New unknown spellings still refuse, even though no queue exists here.
	snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "--"+strings.Repeat("x", 8), "1", "-j", "RETURN"))
	if _, err := inspectXrayStockOutputQueues(snapshot); !errors.Is(err, errXrayStockOutputQueue) {
		t.Fatal("unknown syntax accepted", err)
	}
}
