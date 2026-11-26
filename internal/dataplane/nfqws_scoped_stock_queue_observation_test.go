package dataplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Pure queue/socket-frame models. This representation cannot supply a real
// concrete provider, original capture or ownership of a native process.
func nfqwsScopedStockQueueModel(t *testing.T) *nfqwsScopedStockQueueProof {
	t.Helper()
	b, plan, image := nfqwsScopedStockImageFixture(t, false)
	rows, err := b.stockComparisonRows(plan, image)
	if err != nil {
		t.Fatal(err)
	}
	return &nfqwsScopedStockQueueProof{inventory: &b.network.inventory, provider: b.network.provider, expected: *plan.spec.NetworkIdentity,
		queue: plan.resources.Queue, opening: image.capture.snapshot, stockRows: rows, binding: b, plan: plan}
}

func TestNFQWSScopedStockQueueObservationStableStatesAndTransition(t *testing.T) {
	stock4 := "1104 4104 0 1 64 0 0 0 1\n"
	stock6 := "1106 4106 0 0 0 0 0 0 1\n"
	owned := "40321 4294967000 0 2 65531 0 0 0 1\n"
	stock := stock4 + stock6
	changedCounters := "1106 4106 7 0 0 12 13 4294967295 1\n1104 4104 19 1 64 21 22 23 1\n"
	for _, tc := range []struct {
		name   string
		frames []string
		ready  bool
		owners int
	}{
		{"pre-start-stock", []string{stock, stock}, false, 0},
		{"active-stock-owned", []string{stock + owned, stock + owned}, true, 2},
		{"own-readiness-transition", []string{stock, stock + owned, stock + owned}, true, 2},
		{"post-stop-stock", []string{stock, stock}, false, 0},
		{"counter-and-order-change", []string{stock + owned, owned + changedCounters}, true, 2},
		{"no-registered-stock", []string{"", ""}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := nfqwsScopedStockQueueModel(t)
			if err := proof.consume(context.Background()); err != nil {
				t.Fatal(err)
			}
			reads, owners, identities, foreign := 0, 0, 0, 0
			o := nfqwsScopedQueueReadinessObserver{stock: proof,
				identity: func() error { identities++; return nil },
				read: func(context.Context) ([]nfqwsScopedQueue, error) {
					if reads == len(tc.frames) {
						t.Fatal("unexpected retry")
					}
					frame := tc.frames[reads]
					reads++
					return nfqwsScopedQueues(frame)
				},
				owner: func(_ context.Context, q nfqwsScopedQueue) (string, error) {
					if q.number != proof.queue {
						t.Fatal("foreign registration entered child ownership path")
					}
					owners++
					return "9000", nil
				},
				foreignSocket: func(_ context.Context, q nfqwsScopedQueue) (string, error) {
					if q.number == proof.queue {
						t.Fatal("own queue used foreign comparison")
					}
					foreign++
					return fmt.Sprint(q.portID), nil
				},
			}
			ready, err := nfqwsScopedQueueReadinessObserve(context.Background(), proof.queue, o)
			if err != nil || ready != tc.ready || reads != len(tc.frames) || owners != tc.owners || identities != 2 {
				t.Fatal("original queue phase changed", ready, err, reads, owners, identities)
			}
			if tc.name != "no-registered-stock" && foreign != 2*len(tc.frames) {
				t.Fatal("foreign socket bracket missing")
			}
		})
	}
}

func TestNFQWSScopedStockQueueObservationUnknownsRemainClosed(t *testing.T) {
	stock := "1104 4104 0 1 64 0 0 0 1\n1106 4106 0 0 0 0 0 0 1\n"
	owned := "40321 4294967000 0 2 65531 0 0 0 1\n"
	for _, cut := range []string{"unknown-registration", "stock-disappears", "stock-appears", "stock-port-changes", "stock-mode-changes", "stock-range-changes", "stock-inode-changes", "stock-inode-empty", "stock-netlink-error", "malformed-counter", "duplicate-registration", "owned-port-changes", "owned-inode-changes", "owned-owner-error", "owned-disappears", "transition-stock-change", "closing-child-change", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			proof := nfqwsScopedStockQueueModel(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := proof.consume(ctx); err != nil {
				t.Fatal(err)
			}
			frames := []string{stock + owned, stock + owned}
			switch cut {
			case "unknown-registration":
				frames[0] += "64511 5100 0 2 65531 0 0 0 1\n"
			case "stock-disappears":
				frames[1] = owned
			case "stock-appears":
				frames[0] = owned
			case "stock-port-changes":
				frames[1] = strings.Replace(frames[1], "4104", "4105", 1)
			case "stock-mode-changes":
				frames[1] = strings.Replace(frames[1], "0 1 64", "0 2 64", 1)
			case "stock-range-changes":
				frames[1] = strings.Replace(frames[1], "0 1 64", "0 1 65", 1)
			case "malformed-counter":
				frames[0] = strings.Replace(frames[0], "4104 0", "4104 nope", 1)
			case "duplicate-registration":
				frames[0] += "1104 4104 0 1 64 0 0 0 1\n"
			case "owned-port-changes":
				frames[1] = strings.Replace(frames[1], "4294967000", "4294967001", 1)
			case "owned-disappears":
				frames[1] = stock
			case "transition-stock-change":
				frames = []string{stock, stock + owned, owned}
			}
			reads, identities, owners := 0, 0, 0
			o := nfqwsScopedQueueReadinessObserver{stock: proof,
				identity: func() error {
					identities++
					if cut == "closing-child-change" && identities == 2 {
						return ErrNFQWSScopedOwner
					}
					return nil
				},
				read: func(context.Context) ([]nfqwsScopedQueue, error) {
					if reads == len(frames) {
						t.Fatal("unknown state retried")
					}
					frame := frames[reads]
					reads++
					return nfqwsScopedQueues(frame)
				},
				owner: func(context.Context, nfqwsScopedQueue) (string, error) {
					owners++
					if cut == "owned-owner-error" {
						return "", ErrNFQWSScopedOwner
					}
					if cut == "owned-inode-changes" && owners == 2 {
						return "9001", nil
					}
					return "9000", nil
				},
				foreignSocket: func(_ context.Context, q nfqwsScopedQueue) (string, error) {
					if cut == "stock-inode-empty" {
						return "", nil
					}
					if cut == "stock-netlink-error" {
						return "", ErrNFQWSScopedOwner
					}
					if cut == "cancel" {
						cancel()
					}
					if cut == "stock-inode-changes" && reads == 2 {
						return "changed", nil
					}
					return fmt.Sprint(q.portID), nil
				},
			}
			if ready, err := nfqwsScopedQueueReadinessObserve(ctx, proof.queue, o); ready || err == nil {
				t.Fatal("unknown queue/socket state granted readiness")
			}
		})
	}
}

func TestNFQWSScopedStockQueueProofSingleUseAndSourceChecks(t *testing.T) {
	for _, cut := range []string{"nil", "queue", "network", "coverage", "review", "path", "provider", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			proof := nfqwsScopedStockQueueModel(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch cut {
			case "nil":
				proof = nil
			case "queue":
				proof.queue = 0
			case "network":
				proof.expected.BootID = "different"
			case "coverage":
				proof.opening.Coverage.RegisteredTablesComplete = false
			case "review":
				proof.inventory.review = strings.Repeat("b", 64)
			case "path":
				proof.inventory.reader.IPTables += "-changed"
			case "provider":
				proof.inventory.reader.Provider = &netidentity.Provider{}
			case "cancel":
				cancel()
			}
			if err := proof.consume(ctx); !errors.Is(err, ErrNFQWSScopedOwner) {
				t.Fatal("unknown source consumed proof", err)
			}
		})
	}
	proof := nfqwsScopedStockQueueModel(t)
	if err := proof.consume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proof.consume(context.Background()) == nil {
		t.Fatal("proof reused")
	}
	if !proof.contains(1104) || !proof.contains(1106) || proof.contains(64511) || proof.contains(proof.queue) {
		t.Fatal("comparison borrowed a preset or own queue")
	}
	if proof.close(context.Background()) == nil {
		t.Fatal("model source supplied a concrete closing capture")
	}
}

func TestNFQWSScopedStockQueueClosingRequiresUntouchedWholeImage(t *testing.T) {
	proof := nfqwsScopedStockQueueModel(t)
	if err := proof.consume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !proof.sameClosing(proof.opening, proof.stockRows) {
		t.Fatal("unchanged model did not match")
	}
	for _, cut := range []string{"network", "coverage", "tool", "review", "NFT", "other-table", "order", "comparison"} {
		t.Run(cut, func(t *testing.T) {
			closing := nfqwsDirectStockTestClone(proof.opening)
			rows := cloneNetworkPolicyInventoryTestRows(proof.stockRows)
			switch cut {
			case "network":
				closing.Scope.Network.BootID = "changed"
			case "coverage":
				closing.Coverage.NativeNFTAllFamilies = false
			case "tool":
				closing.IP6Tables += "-changed"
			case "review":
				closing.Scope.ToolReviewID = strings.Repeat("b", 64)
			case "NFT":
				closing.NFTGeneration++
			case "other-table":
				closing.Rows[len(closing.Rows)-1].Tokens = append(closing.Rows[len(closing.Rows)-1].Tokens, "extra")
			case "order":
				closing.Rows[0], closing.Rows[1] = closing.Rows[1], closing.Rows[0]
			case "comparison":
				rows[0].Tokens = slices.Clone(rows[0].Tokens)
				rows[0].Tokens[1] = "changed"
			}
			if proof.sameClosing(closing, rows) {
				t.Fatal("changed complete closing image borrowed opening proof")
			}
		})
	}
}

func TestNFQWSScopedStockQueueConstructorCannotAcceptModelCapture(t *testing.T) {
	proof := nfqwsScopedStockQueueModel(t)
	if p, err := nfqwsScopedPrecompiledStockQueueProof(context.Background(), proof.inventory, proof.expected, proof.queue); p != nil || err == nil {
		t.Fatal("zero concrete provider minted a precompiled proof")
	}
	if p, err := proof.binding.stockQueueProof(context.Background(), proof.plan); p != nil || err == nil {
		t.Fatal("zero concrete provider minted a compiled proof")
	}
	proof = nfqwsScopedStockQueueModel(t)
	if _, err := nfqwsScopedTypedStockQueueObserve(context.Background(), proof, nil); err == nil {
		t.Fatal("model proof ran a native queue observation")
	}
	if CheckTypedNFQWSScopedQueue(context.Background(), proof.provider, proof.expected, proof.queue, nil) == nil {
		t.Fatal("exported strict check accepted a model provider")
	}
}
