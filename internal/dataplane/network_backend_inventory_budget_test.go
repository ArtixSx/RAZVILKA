package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type backendInventoryBudgetKey struct{}
type backendInventoryBudgetNFT struct {
	*backendInventoryTestNFT
	check func(context.Context)
}

func (s *backendInventoryBudgetNFT) Registration(ctx context.Context, abi backendNFTABI) (backendNFTRegistration, error) {
	s.check(ctx)
	return s.backendInventoryTestNFT.Registration(ctx, abi)
}
func (s *backendInventoryBudgetNFT) Tables(ctx context.Context, generation uint32) ([]backendNFTTable, error) {
	s.check(ctx)
	return s.backendInventoryTestNFT.Tables(ctx, generation)
}

func TestBackendInventoryAggregateAndLeafBudgets(t *testing.T) {
	for _, mode := range []string{"generic", "stock", "stock-earlier", "stock-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			r, scope, p, nft, _ := backendInventoryTestFixture(t)
			budget := backendInventoryTimeout
			if mode != "generic" {
				r.NFTABI = backendNFTABIStockNC1812
				scope.Network = netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet,
					BootID: scope.Network.BootID, PlatformReviewSHA256: backendNFTStockScopeSHA256}
				budget = backendInventoryStockTimeout
			}
			ctx := context.WithValue(context.Background(), backendInventoryBudgetKey{}, "original")
			var cancel context.CancelFunc
			if mode == "stock-earlier" {
				ctx, cancel = context.WithTimeout(ctx, 250*time.Millisecond)
				defer cancel()
				budget = 250 * time.Millisecond
			}
			if mode == "stock-cancelled" {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			leafCalls := 0
			check := func(c context.Context) {
				leafCalls++
				d, ok := c.Deadline()
				if !ok || time.Until(d) > min(budget, backendInventoryTimeout) || c.Value(backendInventoryBudgetKey{}) != "original" || c.Err() != nil {
					t.Fatal("leaf lost original scope or exceeded its finite budget")
				}
			}
			r.CheckTools = func(c context.Context, actual backendInventoryScope) error {
				check(c)
				if actual != scope {
					return errBackendInventory
				}
				return nil
			}
			r.Runner = backendInventoryTestRunner(func(c context.Context, _ string, _ ...string) ([]byte, error) {
				check(c)
				return []byte("-P OUTPUT ACCEPT\n"), nil
			})
			p.registeredTables = func(c context.Context, _ int) ([]byte, error) {
				check(c)
				return []byte("filter\n"), nil
			}
			p.openNFT = func(c context.Context) (backendNFTSession, error) {
				check(c)
				return &backendInventoryBudgetNFT{nft, check}, nil
			}
			p.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				d, ok := c.Deadline()
				if !ok || time.Until(d) > budget || mode == "stock" && time.Until(d) <= backendInventoryTimeout {
					t.Fatal("wrong profile aggregate budget")
				}
				return use(c, scope.Network)
			}
			got, err := r.read(ctx, scope, p)
			if mode == "stock-cancelled" {
				if !errors.Is(err, context.Canceled) || leafCalls != 0 || nft.closed != 0 {
					t.Fatal("cancelled request reached a leaf")
				}
			} else if err != nil || got.requireLANBackendCoverage() != nil || leafCalls < 10 || nft.closed != 1 {
				t.Fatal("bounded full capture failed")
			}
		})
	}
}

func TestBackendInventoryStockAggregateCanExceedOneLeaf(t *testing.T) {
	r, scope, p, _, _ := backendInventoryTestFixture(t)
	r.NFTABI = backendNFTABIStockNC1812
	scope.Network = netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet,
		BootID: scope.Network.BootID, PlatformReviewSHA256: backendNFTStockScopeSHA256}
	r.CheckTools = func(ctx context.Context, _ backendInventoryScope) error {
		select {
		case <-time.After(1050 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		return use(ctx, scope.Network)
	}
	start := time.Now()
	got, err := r.read(context.Background(), scope, p)
	if err != nil || got.requireLANBackendCoverage() != nil || time.Since(start) <= backendInventoryTimeout {
		t.Fatal("individually bounded stock leaves could not complete a full multi-leaf capture")
	}
}

func TestBackendInventoryExpiredLeafDiscardsOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	value, err := backendInventoryLeaf(ctx, func(context.Context) (int, error) { cancel(); return 7, nil })
	if value != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled leaf output escaped")
	}
}
