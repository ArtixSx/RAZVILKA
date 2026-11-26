package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestBackendInventoryRegisteredTablesBeyondFixedFive(t *testing.T) {
	r, scope, p, _, _ := backendInventoryTestFixture(t)
	names := map[int]string{4: "filter\nvendor4\nraw\n", 6: "vendor6\n"}
	calls := map[string]int{}
	p.registeredTables = func(_ context.Context, family int) ([]byte, error) { return []byte(names[family]), nil }
	r.Runner = backendInventoryTestRunner(func(_ context.Context, path string, args ...string) ([]byte, error) {
		calls[path+":"+args[1]]++
		return []byte("-P OUTPUT ACCEPT\n-A OUTPUT -m opaque --private-value x -j ACCEPT\n"), nil
	})
	got, err := r.read(context.Background(), scope, p)
	if err != nil || got.requireLANBackendCoverage() != nil || len(got.Rows) != 8 || len(calls) != 4 {
		t.Fatal("full dynamic inventory failed")
	}
	for _, n := range calls {
		if n != 2 {
			t.Fatal("registered table was not read in both images")
		}
	}
	for _, key := range []string{r.IPTables + ":vendor4", r.IP6Tables + ":vendor6"} {
		if calls[key] != 2 {
			t.Fatal("non-fixed table omitted")
		}
	}
	for _, row := range got.Rows {
		if !slices.Contains([]string{"filter", "raw", "vendor4", "vendor6"}, row.Table) {
			t.Fatal("invented unregistered table")
		}
	}
}

func TestBackendInventoryEmptyRegisteredFamilyDoesNotInventTables(t *testing.T) {
	r, scope, p, _, _ := backendInventoryTestFixture(t)
	p.registeredTables = func(_ context.Context, family int) ([]byte, error) {
		if family == 6 {
			return nil, nil
		}
		return []byte("vendor\n"), nil
	}
	r.Runner = backendInventoryTestRunner(func(_ context.Context, path string, _ ...string) ([]byte, error) {
		if path != r.IPTables {
			t.Fatal("empty family triggered guessed CLI read")
		}
		return []byte("-P OUTPUT ACCEPT\n"), nil
	})
	got, err := r.read(context.Background(), scope, p)
	if err != nil || len(got.Rows) != 1 || got.Rows[0].Family != 4 || got.requireLANBackendCoverage() != nil {
		t.Fatal("successful empty EOF was not covered")
	}
}

func TestBackendInventoryRegisteredClosingFailuresSealUnknown(t *testing.T) {
	for _, which := range []string{"missing-names", "truncated-names", "duplicate-names", "names-overflow", "new-table", "changed-image", "closing-tools-mutates-image", "wrong-opening-identity", "closing-scope", "cancel-closing"} {
		t.Run(which, func(t *testing.T) {
			r, scope, p, nft, _ := backendInventoryTestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			namesCalls := 0
			oldNames := p.registeredTables
			p.registeredTables = func(c context.Context, f int) ([]byte, error) {
				namesCalls++
				switch which {
				case "missing-names":
					return nil, os.ErrNotExist
				case "truncated-names":
					return []byte("filter"), nil
				case "duplicate-names":
					return []byte("filter\nfilter\n"), nil
				case "names-overflow":
					return []byte(strings.Repeat("x", backendClassicNamesBytes+1)), nil
				case "new-table":
					if namesCalls >= 3 {
						return []byte("filter\nlate\n"), nil
					}
				}
				return oldNames(c, f)
			}
			ruleCalls := 0
			changed := false
			r.Runner = backendInventoryTestRunner(func(context.Context, string, ...string) ([]byte, error) {
				ruleCalls++
				if changed || which == "changed-image" && ruleCalls > 10 {
					return []byte("-P OUTPUT DROP\n"), nil
				}
				return []byte("-P OUTPUT ACCEPT\n"), nil
			})
			if which == "closing-tools-mutates-image" {
				count := 0
				r.CheckTools = func(context.Context, backendInventoryScope) error {
					count++
					if count == 2 {
						changed = true
					}
					return nil
				}
			}
			if which == "wrong-opening-identity" {
				p.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					other := scope.Network
					other.Inode++
					return use(c, other)
				}
			}
			if which == "closing-scope" || which == "cancel-closing" {
				p.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					if err := use(c, scope.Network); err != nil {
						return err
					}
					if which == "cancel-closing" {
						cancel()
					}
					return netidentity.ErrUnknown
				}
			}
			got, err := r.read(ctx, scope, p)
			if !errors.Is(err, errBackendInventory) || !reflect.DeepEqual(got, backendInventorySnapshot{}) {
				t.Fatal("failed closure leaked inventory")
			}
			if which == "wrong-opening-identity" {
				if nft.closed != 0 {
					t.Fatal("wrong scope opened socket")
				}
			} else if nft.closed != 1 {
				t.Fatal("failed capture did not close once")
			}
		})
	}
}

func TestBackendInventoryStockSoleNegativeRequiresExactFreshScope(t *testing.T) {
	for _, which := range []string{"accepted", "proc-kind", "generic-mode", "unsealed", "closing-normal"} {
		t.Run(which, func(t *testing.T) {
			r, scope, p, first, order := backendInventoryTestFixture(t)
			r.NFTABI = backendNFTABIStockNC1812
			scope.Network.Kind, scope.Network.Inode, scope.Network.PlatformReviewSHA256 = netidentity.ReviewedSingleInitNet, 0, backendNFTStockScopeSHA256
			r.CheckTools = func(ctx context.Context, got backendInventoryScope) error {
				if got != scope || ctx.Err() != nil {
					return errBackendInventory
				}
				return nil
			}
			first.noRegistered = true
			last := &backendInventoryTestNFT{noRegistered: true, order: order}
			if which == "proc-kind" {
				scope.Network.Kind, scope.Network.Inode, scope.Network.PlatformReviewSHA256 = netidentity.ProcNetInode, 123456, ""
			}
			if which == "generic-mode" {
				r.NFTABI = backendNFTABILinux70
			}
			if which == "unsealed" {
				first.onRegistration = func(_ int, r *backendNFTRegistration) { r.sealed = false }
			}
			if which == "closing-normal" {
				last.noRegistered = false
				last.first = 23
			}
			p.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				return use(c, scope.Network)
			}
			opened := 0
			p.openNFT = func(context.Context) (backendNFTSession, error) {
				opened++
				if opened == 1 {
					return first, nil
				}
				if opened == 2 {
					return last, nil
				}
				t.Fatal("replayed negative capture")
				return nil, errBackendInventory
			}
			got, err := r.read(context.Background(), scope, p)
			if which == "accepted" {
				if err != nil || got.NFTState != backendNFTNoRegisteredSubsystemAtCapture || got.NFTGeneration != 0 || got.requireLANBackendCoverage() != nil || opened != 2 || first.closed != 1 || last.closed != 1 || slices.Contains(*order, "tables") {
					t.Fatal("exact negative bracket did not use two fresh closed sockets")
				}
			} else if !errors.Is(err, errBackendInventory) || !reflect.DeepEqual(got, backendInventorySnapshot{}) {
				t.Fatal("unreviewed or mixed negative became absence")
			}
		})
	}
}

func TestBackendInventoryNamesAndMountIDBoundedParsing(t *testing.T) {
	for _, data := range []string{"\n", "bad name\n", "-option\n", "a\na\n", "a\r\n", "unterminated", strings.Repeat("a", 32) + "\n", strings.Repeat("a\n", 65)} {
		if _, err := backendClassicNames([]byte(data)); err == nil {
			t.Fatal("malformed names accepted")
		}
	}
	names, err := backendClassicNames([]byte("vendor-z\nfilter\n"))
	if err != nil || !slices.Equal(names, []string{"filter", "vendor-z"}) {
		t.Fatal("valid registered names rejected")
	}
	for _, data := range []string{"", "mnt_id:\t0\n", "mnt_id:\t01\n", "mnt_id:\t7", "mnt_id:\t7\nmnt_id:\t7\n", "mnt_id: 7\n", "mnt_id:\t+7\n", "mnt_id:\t7\nprivate:\x00\n"} {
		if _, err := backendInventoryProcMountID([]byte(data)); err == nil {
			t.Fatal("malformed mount identity accepted")
		}
	}
	if id, err := backendInventoryProcMountID([]byte("pos:\t0\nflags:\t0100000\nmnt_id:\t7\nino:\t1\n")); err != nil || id != "7" {
		t.Fatal("canonical fdinfo rejected")
	}
}

func TestBackendInventoryCoverageRejectsMixedSnapshotSchema(t *testing.T) {
	for _, which := range []string{"schema", "scope", "partial-classic", "partial-nft", "table-present", "stock-state-on-proc-scope"} {
		t.Run(which, func(t *testing.T) {
			r, scope, p, _, _ := backendInventoryTestFixture(t)
			s, err := r.read(context.Background(), scope, p)
			if err != nil {
				t.Fatal("control capture failed")
			}
			switch which {
			case "schema":
				s.Schema = 0
			case "scope":
				s.Scope.Network.Inode = 0
			case "partial-classic":
				s.Coverage.RegisteredTablesComplete = false
			case "partial-nft":
				s.Coverage.NativeNFTAllFamilies = false
			case "table-present":
				s.NFTTables = []backendNFTTable{{Family: 2, Name: "foreign"}}
			case "stock-state-on-proc-scope":
				s.NFTState = backendNFTNoRegisteredSubsystemAtCapture
				s.NFTGeneration = 0
			}
			if !errors.Is(s.RequireComplete(), ErrBackendInventoryUnknown) {
				t.Fatal("mixed snapshot passed coverage predicate")
			}
		})
	}
}
