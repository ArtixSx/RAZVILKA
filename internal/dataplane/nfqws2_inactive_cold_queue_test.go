package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Private source models only. Complete classic/NFT coverage, including the
// reviewed NFT subsystem absence state, does not establish queue registration
// absence when the independent queue proc read is unavailable.
func TestNFQWSIndependentInactiveColdMissingQueueInventoryHolds(t *testing.T) {
	for _, backend := range []string{"complete-empty", "reviewed-no-nft-subsystem"} {
		for _, missing := range []int{1, 2} {
			name := "opening"
			if missing == 2 {
				name = "closing"
			}
			t.Run(backend+"/"+name, func(t *testing.T) {
				f := newNFQWS2InactiveFixture(t)
				if backend == "reviewed-no-nft-subsystem" {
					stock := nfqwsDirectStockReviewedVendorFixture()
					f.image.Scope.Network = stock.Scope.Network
					f.image.NFTState, f.image.NFTGeneration = BackendNFTNoRegisteredSubsystemAtCapture, 0
					f.source.identity = stock.Scope.Network
					f.source.inventory.reader.NFTABI = backendNFTABIStockNC1812
					f.source.frozen.reader.NFTABI = backendNFTABIStockNC1812
				}
				if f.image.RequireComplete() != nil || len(f.image.Rows) != 0 {
					t.Fatal("test did not establish an independently complete empty kernel image")
				}
				ctx := nfqws2InactiveTestContext(t)
				before, err := nfqws2ReadInactiveFiles(ctx, f.a, f.proof)
				if err != nil {
					t.Fatal(err)
				}
				queues, sockets := 0, 0
				f.proof.queues = func(context.Context) ([]nfqwsScopedQueue, error) {
					queues++
					if queues == missing {
						// Same error identity retained by the actual Linux wrapper.
						return nil, errors.Join(ErrNFQWSScopedQueueInventory, os.ErrNotExist)
					}
					return nil, nil
				}
				f.proof.sockets = func(context.Context) (string, error) {
					sockets++
					return "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n", nil
				}
				err = f.verify(ctx)
				if !errors.Is(err, ErrNFQWSManagedKernelOwner) || !errors.Is(err, ErrNFQWSScopedQueueInventory) ||
					!errors.Is(err, os.ErrNotExist) || NFQWSRuntimeInactiveStage(err) != "kernel" {
					t.Fatal("missing cold queue inventory became empty or lost its fixed stage/cause", err)
				}
				if queues != missing || sockets != missing-1 || f.reads != missing || f.uses != 1 {
					t.Fatal("missing queue read reached additional observations or a replacement source")
				}
				after, err := nfqws2ReadInactiveFiles(ctx, f.a, f.proof)
				if err != nil || !before.same(after) {
					t.Fatal("unknown queue inventory changed cold runtime state", err)
				}
				if _, err := os.Stat(f.a.StateRoot); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unknown queue inventory created a cold runtime directory")
				}
			})
		}
	}
}
