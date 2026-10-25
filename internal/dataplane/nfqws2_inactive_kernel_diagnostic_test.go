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

func TestNFQWSInactiveKernelDiagnosticsPreserveRefusalAndRedactCapture(t *testing.T) {
	private := errors.New("private-path-address-process-778")
	for _, stage := range []string{"inventory.open", "inventory.close", "inventory.changed", "rules.open", "queue.inventory", "socket.inventory", "socket.table", "queue.registration", "socket.owner", "frame.changed"} {
		t.Run(stage, func(t *testing.T) {
			stock := nfqwsDirectStockQueueFixture()
			reads, sockets := 0, 0
			reader := nfqws2InactiveKernelReader{
				read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					image := nfqwsDirectStockTestClone(stock)
					if stage == "inventory.open" || stage == "inventory.close" && reads == 2 {
						return BackendInventorySnapshot{}, private
					}
					if stage == "inventory.changed" && reads == 2 {
						image.Rows = append(image.Rows, nfqwsDirectStockTestRow(4, "nat", "-N", "other"))
					}
					if stage == "rules.open" {
						image.Rows = append(image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-N", "nfqws_post"))
					}
					return image, nil
				},
				queues: func(context.Context) ([]nfqwsScopedQueue, error) {
					if stage == "queue.inventory" {
						return nil, private
					}
					q := nfqwsScopedQueue{number: 1104, portID: 99, copyMode: 2, copyRange: 65531}
					if stage == "queue.registration" {
						q.number = 40000
					}
					return []nfqwsScopedQueue{q}, nil
				},
				sockets: func(context.Context) (string, error) {
					sockets++
					if stage == "socket.inventory" {
						return "", private
					}
					if stage == "socket.table" {
						return "private bad table", nil
					}
					if stage == "socket.owner" {
						return "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n", nil
					}
					if stage == "frame.changed" && sockets == 2 {
						return strings.ReplaceAll(nfqws2InactiveTestSockets, "991", "992"), nil
					}
					return nfqws2InactiveTestSockets, nil
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := reader.check(ctx, stock.Scope.Network)
			outer := nfqws2InactiveAt("observation", nfqws2InactiveAt("kernel", fmt.Errorf("private wrapper: %w", err)))
			if !errors.Is(err, ErrNFQWSManagedKernelOwner) || outer.Error() != "NFQWS runtime inactivity: observation/kernel/kernel."+stage || strings.Contains(outer.Error(), private.Error()) || NFQWSRuntimeInactiveStage(outer) != "kernel" {
				t.Fatal("unsafe or missing fixed kernel branch", outer)
			}
			if (stage == "inventory.open" || stage == "inventory.close" || stage == "queue.inventory" || stage == "socket.inventory") && !errors.Is(outer, private) {
				t.Fatal("original source refusal was lost")
			}
		})
	}
	var nested error = private
	for i := 0; i < 1000; i++ {
		nested = nfqws2InactiveKernelAt("inventory.changed", nested)
	}
	if got := nfqws2InactiveAt("kernel", nested).Error(); got != "NFQWS runtime inactivity: kernel/kernel.inventory.changed" {
		t.Fatal("diagnostic traversal lost its bound", got)
	}
	unknown := nfqws2InactiveAt("kernel", nfqws2InactiveKernelAt(private.Error(), private))
	if unknown.Error() != "NFQWS runtime inactivity: kernel/kernel.unknown" {
		t.Fatal("untrusted label exposed", unknown)
	}
	foreign := nfqws2InactiveAt("kernel", errors.New("NFQWS kernel inactivity refused at inventory.changed: "+private.Error()))
	if foreign.Error() != "NFQWS runtime inactivity: kernel" {
		t.Fatal("foreign error forged kernel branch", foreign)
	}
}
