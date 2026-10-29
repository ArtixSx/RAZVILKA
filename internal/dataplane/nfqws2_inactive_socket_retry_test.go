package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNFQWSInactiveDuplicateRetriesWholeObservationOnly(t *testing.T) {
	duplicate := nfqws2InactiveTestSockets + "0 12 99 00000000 0 0 0 0 0 992\n"
	for _, closing := range []bool{false, true} {
		t.Run(fmt.Sprint("closing=", closing), func(t *testing.T) {
			stock := nfqwsDirectStockQueueFixture()
			reads, queues, sockets := 0, 0, 0
			reader := nfqws2InactiveKernelReader{
				read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					return nfqwsDirectStockTestClone(stock), nil
				},
				queues: func(context.Context) ([]nfqwsScopedQueue, error) {
					queues++
					return []nfqwsScopedQueue{{number: 1104, portID: 99, copyMode: 2, copyRange: 65531}}, nil
				},
				sockets: func(context.Context) (string, error) {
					sockets++
					if !closing && sockets == 1 || closing && sockets == 2 {
						return duplicate, nil
					}
					return nfqws2InactiveTestSockets, nil
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			want := 3
			if closing {
				want = 4
			}
			if err := reader.check(ctx, stock.Scope.Network); err != nil || reads != want || queues != want || sockets != want {
				t.Fatal("did not replace whole ambiguous attempt with fresh complete frames", err, reads, queues, sockets)
			}
		})
	}
}

func TestNFQWSInactiveDuplicateRetryRebuildsOpeningRuleComparison(t *testing.T) {
	stock := nfqwsDirectStockQueueFixture()
	reads, sockets := 0, 0
	reader := nfqws2InactiveKernelReader{
		read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
			reads++
			image := nfqwsDirectStockTestClone(stock)
			if reads > 1 {
				for i := range image.Rows {
					for j, token := range image.Rows[i].Tokens {
						if token == "1104" {
							image.Rows[i].Tokens[j] = "1105"
						}
					}
				}
			}
			return image, nil
		},
		queues: func(context.Context) ([]nfqwsScopedQueue, error) {
			number := uint16(1104)
			if reads > 1 {
				number = 1105
			}
			return []nfqwsScopedQueue{{number: number, portID: 99, copyMode: 2, copyRange: 65531}}, nil
		},
		sockets: func(context.Context) (string, error) {
			sockets++
			if sockets == 1 {
				return nfqws2InactiveTestSockets + nfqws2InactiveTestSockets[strings.Index(nfqws2InactiveTestSockets, "\n")+1:], nil
			}
			return nfqws2InactiveTestSockets, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := reader.check(ctx, stock.Scope.Network); err != nil || reads != 3 || sockets != 3 {
		t.Fatal("reused failed-attempt comparison or frame", err, reads, sockets)
	}
}

func TestNFQWSInactiveDuplicateRetryIsBoundedAndPreservesRefusals(t *testing.T) {
	duplicate := nfqws2InactiveTestSockets + "0 12 99 00000000 0 0 0 0 0 992\n"
	for _, mode := range []string{"persistent-open", "persistent-close", "header", "cancel", "scope-after-duplicate", "rules-after-duplicate", "queue-after-duplicate", "inode-after-duplicate", "source-after-duplicate"} {
		t.Run(mode, func(t *testing.T) {
			stock := nfqwsDirectStockQueueFixture()
			reads, queues, sockets := 0, 0, 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			reader := nfqws2InactiveKernelReader{
				read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					image := nfqwsDirectStockTestClone(stock)
					if reads > 1 {
						switch mode {
						case "scope-after-duplicate":
							image.Scope.Network.Inode++
						case "rules-after-duplicate":
							image.Rows = append(image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-N", "RZQ_unknown"))
						case "source-after-duplicate":
							return BackendInventorySnapshot{}, errors.New("closed read refusal")
						}
					}
					return image, nil
				},
				queues: func(context.Context) ([]nfqwsScopedQueue, error) {
					queues++
					q := nfqwsScopedQueue{number: 1104, portID: 99, copyMode: 2, copyRange: 65531}
					if queues > 1 && mode == "queue-after-duplicate" {
						q.number = 40000
					}
					return []nfqwsScopedQueue{q}, nil
				},
				sockets: func(context.Context) (string, error) {
					sockets++
					if mode == "header" {
						return "invalid", nil
					}
					if mode == "persistent-open" || mode == "persistent-close" && sockets%2 == 0 {
						return duplicate, nil
					}
					if sockets == 1 && mode != "persistent-close" {
						if mode == "cancel" {
							cancel()
						}
						return duplicate, nil
					}
					if mode == "inode-after-duplicate" && sockets == 3 {
						return strings.Replace(nfqws2InactiveTestSockets, "991", "992", 1), nil
					}
					return nfqws2InactiveTestSockets, nil
				},
			}
			err := reader.check(ctx, stock.Scope.Network)
			if !errors.Is(err, ErrNFQWSManagedKernelOwner) {
				t.Fatal("ambiguous/changed frame became inactivity", err)
			}
			switch mode {
			case "persistent-open":
				if reads != 3 || sockets != 3 {
					t.Fatal("retry limit", reads, sockets)
				}
			case "persistent-close":
				if reads != 6 || sockets != 6 {
					t.Fatal("whole closing retry limit", reads, sockets)
				}
			case "header", "cancel":
				if reads != 1 || sockets != 1 {
					t.Fatal("nonretry/canceled observation was repeated", reads, sockets)
				}
			case "scope-after-duplicate", "rules-after-duplicate", "source-after-duplicate":
				if reads != 2 || sockets != 1 {
					t.Fatal("invalid fresh source was retried", reads, sockets)
				}
			case "queue-after-duplicate":
				if reads != 2 || queues != 2 || sockets != 2 {
					t.Fatal("foreign queue observation was repeated", reads, queues, sockets)
				}
			case "inode-after-duplicate":
				if reads != 3 || sockets != 3 {
					t.Fatal("changed valid frame was retried", reads, sockets)
				}
			}
		})
	}
}

func TestNFQWSInactiveDuplicateRetryDoesNotHideAnotherRefusal(t *testing.T) {
	duplicate := nfqws2InactiveKernelAt("socket.table", nfqws2InactiveKernelAt("socket.table.duplicate", ErrNFQWSManagedKernelOwner))
	closing := nfqws2InactiveKernelAt("frame.changed", errors.Join(ErrNFQWSManagedKernelOwner, duplicate))
	if !nfqws2InactiveDuplicateRead(duplicate) || !nfqws2InactiveDuplicateRead(closing) {
		t.Fatal("canonical duplicate refused retry")
	}
	for _, err := range []error{
		errors.Join(duplicate, context.Canceled), errors.Join(duplicate, errors.New("other ownership")),
		nfqws2InactiveKernelAt("socket.inventory", duplicate), fmt.Errorf("unknown wrapper: %w", duplicate),
		nfqws2InactiveKernelAt("socket.table.header", ErrNFQWSManagedKernelOwner),
		errors.Join(duplicate, duplicate),
	} {
		if nfqws2InactiveDuplicateRead(err) {
			t.Fatal("unreviewed compound error became retry authority", err)
		}
	}
}
