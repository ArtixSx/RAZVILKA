package dataplane

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Collector seam model only; no protected source or native effect is issued.
type backendInventoryBatchModel struct {
	backendInventoryTestRunner
	batch func(context.Context, netidentity.Identity, string, [2]string, int, [2][]string) ([2][][]byte, error)
}

func (m backendInventoryBatchModel) ReadBoundedClassicTables(c context.Context, id netidentity.Identity, review string, paths [2]string, limit int, tables [2][]string) ([2][][]byte, error) {
	return m.batch(c, id, review, paths, limit, tables)
}

func TestBackendInventoryBatchRetainsCompleteCollectorBookends(t *testing.T) {
	r, scope, p, nft, order := backendInventoryTestFixture(t)
	base := r.Runner.(backendInventoryTestRunner)
	calls := 0
	r.Runner = backendInventoryBatchModel{backendInventoryTestRunner: base, batch: func(ctx context.Context, id netidentity.Identity, review string, paths [2]string, limit int, tables [2][]string) (result [2][][]byte, err error) {
		calls++
		if id != scope.Network || review != scope.ToolReviewID || paths != [2]string{r.IPTables, r.IP6Tables} || limit <= 0 || limit > backendClassicBytes {
			t.Fatal("batch changed original source/bounds")
		}
		for family := range tables {
			if !slices.Equal(tables[family], []string{"filter", "mangle", "nat", "raw", "security"}) {
				t.Fatal("incomplete tables", tables)
			}
			for _, table := range tables[family] {
				body, e := base.RunBounded(ctx, paths[family], limit, "-t", table, "-S")
				if e != nil {
					return result, e
				}
				result[family] = append(result[family], body)
			}
			// A runner cannot corrupt the collector's registered-name image.
			tables[family][0] = "changed-detached-input"
		}
		return result, nil
	}}
	got, err := r.read(context.Background(), scope, p)
	if err != nil || got.requireLANBackendCoverage() != nil || len(got.Rows) != 10 || calls != 2 || nft.generationCalls != 2 || nft.closed != 1 {
		t.Fatal("complete bracket lost", calls, nft.generationCalls, nft.closed, err)
	}
	toolChecks, names := 0, 0
	for _, event := range *order {
		if event == "tools" {
			toolChecks++
		}
		if strings.HasPrefix(event, "names") {
			names++
		}
	}
	if toolChecks != 2 || names != 8 {
		t.Fatal("tool or registration bookend skipped", toolChecks, names)
	}
}

func TestBackendInventoryBatchRejectsDriftPartialAndCancelledOutput(t *testing.T) {
	for _, mode := range []string{"body-drift", "registration-drift", "partial", "oversize", "cancelled", "producer-error"} {
		t.Run(mode, func(t *testing.T) {
			r, scope, p, nft, _ := backendInventoryTestFixture(t)
			base := r.Runner.(backendInventoryTestRunner)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			producerError := errors.New("original protected batch failure")
			r.Runner = backendInventoryBatchModel{backendInventoryTestRunner: base, batch: func(_ context.Context, _ netidentity.Identity, _ string, _ [2]string, _ int, tables [2][]string) (result [2][][]byte, err error) {
				calls++
				for family := range tables {
					for range tables[family] {
						result[family] = append(result[family], []byte("-P OUTPUT ACCEPT\n"))
					}
				}
				switch mode {
				case "body-drift":
					if calls == 2 {
						result[0][0] = []byte("-P OUTPUT DROP\n")
					}
				case "partial":
					result[0] = result[0][:len(result[0])-1]
				case "oversize":
					result[0][0] = make([]byte, backendClassicBytes+1)
				case "cancelled":
					cancel()
				case "producer-error":
					return result, producerError
				}
				return result, nil
			}}
			if mode == "registration-drift" {
				p.registeredTables = func(context.Context, int) ([]byte, error) {
					if calls > 0 {
						return []byte("filter\n"), nil
					}
					return []byte("filter\nmangle\n"), nil
				}
			}
			got, err := r.read(ctx, scope, p)
			if err == nil || got.requireLANBackendCoverage() == nil || nft.closed != 1 {
				t.Fatal("invalid observation escaped", mode, err)
			}
			if mode == "producer-error" && !errors.Is(err, producerError) {
				t.Fatal("original producer exception lost", err)
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
		})
	}
}
