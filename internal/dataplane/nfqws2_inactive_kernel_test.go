package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

const nfqws2InactiveTestSockets = "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0 12 99 00000000 0 0 0 0 0 991\n"

// Complete owner fixtures only. None is exposed by the production constructor
// or establishes kernel ownership, native inactivity or packet behavior.
func TestNFQWSIndependentInactiveKernelRequiresCompleteBothFamilies(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	empty := networkPolicyInventoryTestImage(identity.value, nil)
	if rows, err := nfqws2InactiveKernelRows(empty); err != nil || len(rows) != 0 {
		t.Fatal("complete registered-table absence needed fabricated hooks", err)
	}
	for _, change := range []func(*BackendInventorySnapshot){
		func(s *BackendInventorySnapshot) { s.Coverage.LegacyRegisteredBothFamilies = false },
		func(s *BackendInventorySnapshot) { s.Coverage.RegisteredTablesComplete = false },
		func(s *BackendInventorySnapshot) { s.Coverage.NativeNFTAllFamilies = false },
		func(s *BackendInventorySnapshot) { s.NFTState = BackendNFTUnknown },
		func(s *BackendInventorySnapshot) { s.NFTTables = []BackendNFTTable{{Family: 2, Name: "foreign"}} },
		func(s *BackendInventorySnapshot) { s.Scope.Network.Inode = 0 },
	} {
		image := empty
		change(&image)
		if _, err := nfqws2InactiveKernelRows(image); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
			t.Fatal("partial or wrong-scope empty image became proof", err)
		}
	}
}

func TestNFQWSIndependentInactiveKernelOwnedRowsAndSharedHooksHold(t *testing.T) {
	stock := nfqwsDirectStockQueueFixture()
	if rows, err := nfqws2InactiveKernelRows(stock); err != nil || len(rows) != 2 {
		t.Fatal("exact complete OUTPUT stock graph lost", err)
	}
	for name, row := range map[string]BackendInventoryRow{
		"owned declaration":    nfqwsDirectStockTestRow(4, "mangle", "-N", "RZQ_unused"),
		"owned reference":      nfqwsDirectStockTestRow(6, "nat", "-A", "OUTPUT", "-j", "RZQ_unused"),
		"legacy chain":         nfqwsDirectStockTestRow(4, "mangle", "-N", "nfqws_post"),
		"legacy reference":     nfqwsDirectStockTestRow(6, "filter", "-A", "FORWARD", "-j", "nfqws2"),
		"shared forward":       nfqwsDirectStockTestRow(6, "mangle", "-A", "FORWARD", "-j", "local_delay"),
		"nat queue":            nfqwsDirectStockTestRow(4, "nat", "-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "1104"),
		"unknown queue option": nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "--queue-balance", "1104:1106", "-j", "NFQUEUE"),
	} {
		t.Run(name, func(t *testing.T) {
			image := nfqwsDirectStockTestClone(stock)
			image.Rows = append(image.Rows, row)
			if _, err := nfqws2InactiveKernelRows(image); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
				t.Fatal("owned/unknown/shared queue became foreign absence", err)
			}
		})
	}
}

func TestNFQWSIndependentInactiveKernelBracketsWholeGraphAndRegistration(t *testing.T) {
	for _, change := range []string{"none", "rules", "inode", "port", "mode", "range", "appeared", "missing-queue-proc", "empty-socket-proc", "scope"} {
		t.Run(change, func(t *testing.T) {
			stock := nfqwsDirectStockQueueFixture()
			reads, queues, sockets := 0, 0, 0
			reader := nfqws2InactiveKernelReader{
				read: func(_ context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					image := nfqwsDirectStockTestClone(stock)
					if reads == 2 && change == "rules" {
						image.Rows = append(image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-j", "RETURN"))
					}
					if change == "scope" {
						image.Scope.Network.Inode++
					}
					return image, nil
				},
				queues: func(context.Context) ([]nfqwsScopedQueue, error) {
					queues++
					if change == "missing-queue-proc" {
						return nil, ErrNFQWSScopedQueueInventory
					}
					q := nfqwsScopedQueue{number: 1104, portID: 99, copyMode: 2, copyRange: 65531}
					if queues == 2 {
						switch change {
						case "port":
							q.portID++
						case "mode":
							q.copyMode = 1
						case "range":
							q.copyRange--
						case "appeared":
							q.number = 40000
						}
					}
					return []nfqwsScopedQueue{q}, nil
				},
				sockets: func(context.Context) (string, error) {
					sockets++
					if change == "empty-socket-proc" {
						return "", nil
					}
					if sockets == 2 && change == "inode" {
						return strings.Replace(nfqws2InactiveTestSockets, "991", "992", 1), nil
					}
					return nfqws2InactiveTestSockets, nil
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := reader.check(ctx, stock.Scope.Network)
			if change == "none" {
				if err != nil || reads != 2 || queues != 2 || sockets != 2 {
					t.Fatal("original source was not fully bracketed", err)
				}
			} else if !errors.Is(err, ErrNFQWSManagedKernelOwner) {
				t.Fatal("changed/missing frame became inactivity", change, err)
			}
		})
	}
}

func TestNFQWSIndependentInactiveEmptyFramesNeedPositiveReadback(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	image := networkPolicyInventoryTestImage(identity.value, nil)
	before := nfqwsDirectStockTestClone(image)
	reads := 0
	reader := nfqws2InactiveKernelReader{
		read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
			reads++
			return image, nil
		},
		queues: func(context.Context) ([]nfqwsScopedQueue, error) { return nil, nil },
		sockets: func(context.Context) (string, error) {
			return "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n", nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := reader.check(ctx, identity.value); err != nil || reads != 2 || !reflect.DeepEqual(image, before) {
		t.Fatal("positive empty capture did not remain read-only", err)
	}
	for _, invalid := range []string{"", "broken\n", nfqws2InactiveTestSockets + "0 12 99 00000000 0 0 0 0 0 992\n", "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0 12 99 0 0 0 0 0 0 0\n"} {
		reader.sockets = func(context.Context) (string, error) { return invalid, nil }
		if err := reader.check(ctx, identity.value); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
			t.Fatal("missing/ambiguous socket read became proof")
		}
	}
}
