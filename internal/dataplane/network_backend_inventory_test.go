package dataplane

import (
	"context"
	"errors"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type backendInventoryTestRunner func(context.Context, string, ...string) ([]byte, error)

func (run backendInventoryTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return run(ctx, name, args...)
}
func (run backendInventoryTestRunner) RunBounded(ctx context.Context, name string, limit int, args ...string) ([]byte, error) {
	data, err := run(ctx, name, args...)
	if limit <= 0 || len(data) > limit {
		return nil, errBackendInventory
	}
	return data, err
}

type backendInventoryTestNFT struct {
	generationCalls int
	first, last     uint32
	tables          []backendNFTTable
	err, closeErr   error
	closed          int
	onLast          func()
	order           *[]string
	noRegistered    bool
	onRegistration  func(int, *backendNFTRegistration)
}

func (s *backendInventoryTestNFT) Registration(ctx context.Context, _ backendNFTABI) (backendNFTRegistration, error) {
	generation, err := s.Generation(ctx)
	r := backendNFTRegistration{generation: generation, noRegistered: s.noRegistered, sealed: err == nil}
	if s.noRegistered {
		r.generation = 0
	}
	if s.onRegistration != nil {
		s.onRegistration(s.generationCalls, &r)
	}
	return r, err
}

func (s *backendInventoryTestNFT) Generation(context.Context) (uint32, error) {
	s.generationCalls++
	*s.order = append(*s.order, "gen")
	if s.err != nil {
		return 0, s.err
	}
	if s.generationCalls == 1 {
		return s.first, nil
	}
	if s.onLast != nil {
		s.onLast()
	}
	return s.last, nil
}
func (s *backendInventoryTestNFT) Tables(context.Context, uint32) ([]backendNFTTable, error) {
	*s.order = append(*s.order, "tables")
	return s.tables, s.err
}
func (s *backendInventoryTestNFT) Close() error { s.closed++; return s.closeErr }

func backendInventoryTestFixture(t *testing.T) (*backendInventoryReader, backendInventoryScope, backendInventoryPlatform, *backendInventoryTestNFT, *[]string) {
	t.Helper()
	scope := backendInventoryScope{Network: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 123456}, ToolReviewID: strings.Repeat("a", 64)}
	order := []string{}
	nft := &backendInventoryTestNFT{first: 23, last: 23, order: &order}
	r := &backendInventoryReader{NFTABI: backendNFTABILinux70, IPTables: "/review/iptables", IP6Tables: "/review/ip6tables"}
	r.CheckTools = func(ctx context.Context, got backendInventoryScope) error {
		order = append(order, "tools")
		if got != scope {
			return errors.New("wrong review")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > backendInventoryTimeout {
			return errors.New("unbounded read")
		}
		return nil
	}
	r.Runner = backendInventoryTestRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != r.IPTables && name != r.IP6Tables || len(args) != 3 || args[0] != "-t" || args[2] != "-S" {
			return nil, errors.New("not a fixed readonly command")
		}
		order = append(order, name+":"+args[1])
		return []byte("-P OUTPUT ACCEPT\n"), nil
	})
	p := backendInventoryPlatform{
		withCurrent: func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
			order = append(order, "scope-open")
			if err := use(ctx, scope.Network); err != nil {
				return err
			}
			order = append(order, "scope-close")
			return ctx.Err()
		},
		registeredTables: func(_ context.Context, family int) ([]byte, error) {
			order = append(order, fmt.Sprint("names", family))
			return []byte("raw\nmangle\nnat\nfilter\nsecurity\n"), nil
		},
		openNFT: func(context.Context) (backendNFTSession, error) { order = append(order, "open"); return nft, nil },
	}
	return r, scope, p, nft, &order
}

func TestBackendInventoryBracketsClassicAndPreservesMixedRows(t *testing.T) {
	r, scope, p, nft, order := backendInventoryTestFixture(t)
	r.Runner = backendInventoryTestRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		*order = append(*order, name+":"+args[1])
		if name == r.IP6Tables && args[1] == "security" {
			return []byte("-P OUTPUT ACCEPT\n-A OUTPUT -m unknown_ext --opaque abc -j NFQUEUE --queue-num 71\n"), nil
		}
		return []byte("-P OUTPUT ACCEPT\n-A OUTPUT -m comment --comment \"literal -j NFQUEUE --mark 0x20000000\" -j ACCEPT\n"), nil
	})
	s, err := r.read(context.Background(), scope, p)
	if err != nil {
		t.Fatal(err)
	}
	if s.NFTState != backendNFTEmpty || s.NFTGeneration != 23 || !s.Coverage.LegacyRegisteredBothFamilies || !s.Coverage.NativeNFTAllFamilies || !s.Coverage.RegisteredTablesComplete || len(s.Rows) != 20 || nft.closed != 1 {
		t.Fatalf("incomplete result: %+v, close=%d", s, nft.closed)
	}
	if s.requireLANBackendCoverage() != nil {
		t.Fatal("complete empty inventory lost coverage")
	}
	wantOrder := []string{"scope-open", "tools", "open", "gen", "tables"}
	for pass := range 2 {
		if pass == 1 {
			wantOrder = append(wantOrder, "tools")
		}
		wantOrder = append(wantOrder, "names4", "names6")
		for _, path := range []string{r.IPTables, r.IP6Tables} {
			for _, table := range []string{"filter", "mangle", "nat", "raw", "security"} {
				wantOrder = append(wantOrder, path+":"+table)
			}
		}
		wantOrder = append(wantOrder, "names4", "names6")
	}
	wantOrder = append(wantOrder, "gen", "scope-close")
	if !reflect.DeepEqual(*order, wantOrder) {
		t.Fatalf("generation did not bracket whole batch: %v", *order)
	}
	quoted := s.Rows[1].Tokens
	if !reflect.DeepEqual(quoted, []string{"-A", "OUTPUT", "-m", "comment", "--comment", "literal -j NFQUEUE --mark 0x20000000", "-j", "ACCEPT"}) {
		t.Fatalf("comment was reinterpreted: %v", quoted)
	}
	last := s.Rows[len(s.Rows)-1]
	if last.Family != 6 || last.Table != "security" || !strings.Contains(strings.Join(last.Tokens, " "), "unknown_ext") {
		t.Fatalf("foreign extension/security lost: %+v", last)
	}
	// Snapshot tokens are detached from subsequent reads.
	s.Rows[0].Tokens[1] = "changed"
	next, err := r.read(context.Background(), scope, p)
	if err != nil || next.Rows[0].Tokens[1] != "OUTPUT" {
		t.Fatalf("aliased snapshot: %+v %v", next, err)
	}
}

func TestBackendInventoryNativeForeignFamilyPresent(t *testing.T) {
	for _, family := range []uint8{1, 2, 3, 5, 7, 10} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			r, scope, p, nft, _ := backendInventoryTestFixture(t)
			nft.tables = []backendNFTTable{{Family: family, Name: "foreign", Flags: 1}}
			s, err := r.read(context.Background(), scope, p)
			if err != nil || s.NFTState != backendNFTPresent || len(s.Rows) != 10 || len(s.NFTTables) != 1 || s.requireLANBackendCoverage() == nil {
				t.Fatalf("foreign/dormant table granted absence: %+v %v", s, err)
			}
			nft.tables[0].Name = "changed"
			if s.NFTTables[0].Name != "foreign" {
				t.Fatal("aliased tables")
			}
		})
	}
}

func TestBackendInventoryUnknownCannotLeakPartialSnapshot(t *testing.T) {
	for _, which := range []string{"kernel-einval", "missing-transport", "changed-generation", "changed-boot", "changed-namespace", "changed-tool-review", "cancel-after-gen", "cancel-after-tool-check", "failed-table", "truncated-table", "close-error"} {
		t.Run(which, func(t *testing.T) {
			r, scope, p, nft, _ := backendInventoryTestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch which {
			case "kernel-einval":
				nft.err = &backendNFTKernelError{Code: 22}
			case "missing-transport":
				p.openNFT = func(context.Context) (backendNFTSession, error) { return nil, os.ErrNotExist }
			case "changed-generation":
				nft.last++
			case "changed-boot", "changed-namespace":
				p.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
					if err := use(ctx, scope.Network); err != nil {
						return err
					}
					got := scope.Network
					if which == "changed-boot" {
						got.BootID = "22345678-1234-1234-1234-123456789abc"
					} else {
						got.Inode++
					}
					if got != scope.Network {
						return netidentity.ErrUnknown
					}
					return nil
				}
			case "changed-tool-review", "cancel-after-tool-check":
				count := 0
				r.CheckTools = func(context.Context, backendInventoryScope) error {
					count++
					if count == 2 {
						if which == "changed-tool-review" {
							return errors.New("stale tools")
						}
						cancel()
					}
					return nil
				}
			case "cancel-after-gen":
				nft.onLast = cancel
			case "failed-table":
				r.Runner = backendInventoryTestRunner(func(context.Context, string, ...string) ([]byte, error) {
					return nil, errors.New("security unavailable")
				})
			case "truncated-table":
				r.Runner = backendInventoryTestRunner(func(context.Context, string, ...string) ([]byte, error) { return []byte("-P OUTPUT ACCEPT"), nil })
			case "close-error":
				nft.closeErr = errors.New("close unknown")
			}
			s, err := r.read(ctx, scope, p)
			if err == nil || !errors.Is(err, errBackendInventory) || !reflect.DeepEqual(s, backendInventorySnapshot{}) {
				t.Fatalf("unknown retained proof: %+v %v", s, err)
			}
			if which != "missing-transport" && nft.closed != 1 {
				t.Fatalf("close count %d", nft.closed)
			}
		})
	}
}

func TestBackendInventoryRequiresToolCheckAndSupportedPlatform(t *testing.T) {
	r, scope, p, _, _ := backendInventoryTestFixture(t)
	r.CheckTools = nil
	if _, err := r.read(context.Background(), scope, p); err == nil {
		t.Fatal("nil checker granted read")
	}
	if _, err := r.read(nil, scope, p); err == nil {
		t.Fatal("nil context granted read")
	}
	r.CheckTools = func(context.Context, backendInventoryScope) error { return nil }
	r.Runner = nfqws2RunFunc(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("unbounded runner was called")
		return nil, nil
	})
	if _, err := r.read(context.Background(), scope, p); err == nil {
		t.Fatal("unbounded output seam granted read")
	}
}

func TestBackendInventoryOutputCapsBeforeAllocation(t *testing.T) {
	overflows := 0
	w := &backendInventoryOutput{limit: 17, onOverflow: func() { overflows++ }}
	for range 17 {
		if n, err := w.Write([]byte("x")); err != nil || n != 1 || cap(w.data) > w.limit {
			t.Fatalf("invalid bounded capture n=%d cap=%d err=%v", n, cap(w.data), err)
		}
	}
	if n, err := w.Write([]byte("overflow")); err == nil || n != 0 || len(w.data) != 17 || cap(w.data) > 17 {
		t.Fatal("overflow allocated or appended")
	}
	if overflows != 1 {
		t.Fatal("overflow did not stop subprocess")
	}
	w = &backendInventoryOutput{limit: 17}
	if _, err := w.Write(make([]byte, 18)); err == nil || len(w.data) != 0 || cap(w.data) != 0 {
		t.Fatal("oversize first write allocated")
	}
}

func TestBackendXTablesRejectsMalformedAndAggregateLimits(t *testing.T) {
	bad := []string{"", "\n", "-P OUTPUT ACCEPT", "-C OUTPUT -j ACCEPT\n", "-N chain extra\n", "-P OUTPUT ACCEPT extra\n", "-A OUTPUT -j\n", "-A OUTPUT -m comment --comment \"unterminated\n", "-A OUTPUT -m comment --comment \"control\x01\" -j ACCEPT\n", "-P OUTPUT ACCEPT\r\n", "-P OUTPUT \xff\n", "-A OUTPUT " + strings.Repeat("x", 16384) + "\n", "-A OUTPUT " + strings.Repeat("x ", 127) + "\n"}
	for i, data := range bad {
		if _, err := backendXTablesRows([]byte(data), &backendClassicBudget{}); err == nil {
			t.Fatalf("malformed %d accepted", i)
		}
	}
	for _, budget := range []backendClassicBudget{{bytes: backendClassicBytes - 1}, {rows: backendClassicRows}, {tokens: backendClassicTokens - 2}} {
		if _, err := backendXTablesRows([]byte("-P OUTPUT ACCEPT\n"), &budget); err == nil {
			t.Fatalf("aggregate limit ignored: %+v", budget)
		}
	}
	budget := &backendClassicBudget{}
	line := []byte("-P OUTPUT ACCEPT\n")
	for range backendClassicRows {
		if _, err := backendXTablesRows(line, budget); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := backendXTablesRows(line, budget); err == nil {
		t.Fatal("per-call budget reset")
	}
}
