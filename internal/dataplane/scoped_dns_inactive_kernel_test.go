package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestScopedDNSInactiveSharedCollectorReadsEveryRegisteredRow(t *testing.T) {
	for _, shape := range []string{"empty", "literal-comment", "ipv4-custom-chain", "ipv6-custom-reference", "opaque-reference"} {
		t.Run(shape, func(t *testing.T) {
			r, scope, platform, _, _ := backendInventoryTestFixture(t)
			platform.registeredTables = func(context.Context, int) ([]byte, error) { return []byte("vendor\n"), nil }
			commands := 0
			r.Runner = backendInventoryTestRunner(func(_ context.Context, command string, args ...string) ([]byte, error) {
				commands++
				if len(args) != 3 || args[0] != "-t" || args[1] != "vendor" || args[2] != "-S" {
					t.Fatal("consumer invented a collector command")
				}
				row := "-P OUTPUT ACCEPT\n"
				switch shape {
				case "literal-comment":
					row += "-A OUTPUT -m comment --comment \"RZD_literal -j RZD_literal\" -j RETURN\n"
				case "ipv4-custom-chain":
					if command == r.IPTables {
						row += "-N RZD_orphan\n"
					}
				case "ipv6-custom-reference":
					if command == r.IP6Tables {
						row += "-A OUTPUT -g RZD_orphan\n"
					}
				case "opaque-reference":
					row += "-A OUTPUT -m opaque --private-value RZD_orphan -j RETURN\n"
				}
				return []byte(row), nil
			})
			reads := 0
			check := scopedDNSInactiveBackendCheck(func(ctx context.Context, expected netidentity.Identity) (BackendInventorySnapshot, error) {
				reads++
				if expected != scope.Network || ctx.Value(scopedDNSInactiveTestKey{}) != "retained" {
					t.Fatal("identity/context lost")
				}
				return r.read(ctx, scope, platform)
			})
			ctx := context.WithValue(context.Background(), scopedDNSInactiveTestKey{}, "retained")
			for pass := 0; pass < 2; pass++ {
				err := check(ctx, scope.Network)
				wantPass := shape == "empty" || shape == "literal-comment"
				if (err == nil) != wantPass {
					t.Fatalf("wrong consumer result: %v", err)
				}
			}
			if reads != 2 || commands != 8 {
				t.Fatal("consumer cached inventory or omitted a family/image")
			}
		})
	}
}

func TestScopedDNSInactiveSharedCollectorUnknownCoverageAndScope(t *testing.T) {
	for _, kind := range []string{"collector-error", "fixed-five-only", "native-present", "foreign-scope", "unknown-schema", "late-cancel", "old-unqualified-negative"} {
		t.Run(kind, func(t *testing.T) {
			r, scope, platform, _, _ := backendInventoryTestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			check := scopedDNSInactiveBackendCheck(func(c context.Context, _ netidentity.Identity) (BackendInventorySnapshot, error) {
				snapshot, err := r.read(c, scope, platform)
				if err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "collector-error":
					return snapshot, errors.New("unknown registered table")
				case "fixed-five-only":
					snapshot.Coverage.RegisteredTablesComplete = false
				case "native-present":
					snapshot.NFTState = BackendNFTPresent
				case "foreign-scope":
					snapshot.Scope.Network.Inode++
				case "unknown-schema":
					snapshot.Schema++
				case "late-cancel":
					cancel()
				case "old-unqualified-negative":
					snapshot.NFTState = BackendNFTNoRegisteredSubsystemAtCapture
					snapshot.NFTGeneration = 0
				}
				return snapshot, nil
			})
			if err := check(ctx, scope.Network); !errors.Is(err, ErrScopedDNSRuntimeInactive) {
				t.Fatalf("unknown inventory accepted: %v", err)
			}
		})
	}
	identity := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 123456}
	for _, inventory := range []*BackendInventory{nil, {}} {
		if err := NewScopedDNSInactivityKernelCheck(inventory)(context.Background(), identity); err == nil {
			t.Fatal("missing concrete producer accepted")
		}
	}
}

func TestScopedDNSInactiveUsesSharedCollectorUnderHeldIdentity(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	r, scope, platform, _, _ := backendInventoryTestFixture(t)
	reads := 0
	held := false
	f.proof.threadNetRoot = func() string {
		if !held {
			t.Fatal("thread socket path resolved outside held identity")
		}
		return f.proof.netRoot
	}
	f.proof.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		held = true
		defer func() { held = false }()
		return use(ctx, scope.Network)
	}
	f.a.InactivityKernelCheck = scopedDNSInactiveBackendCheck(func(ctx context.Context, expected netidentity.Identity) (BackendInventorySnapshot, error) {
		reads++
		if expected != scope.Network {
			t.Fatal("observer changed producer scope")
		}
		return r.read(ctx, scope, platform)
	})
	if err := f.verify(); err != nil {
		t.Fatal(err)
	}
	r.Runner = backendInventoryTestRunner(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("-P OUTPUT ACCEPT\n-A OUTPUT -j RZD_orphan\n"), nil
	})
	if err := f.verify(); err == nil || reads != 2 {
		t.Fatal("observer bypassed fresh shared consumer")
	}
	// Keep a last-row attachment from becoming hidden behind inert comments.
	if err := CheckScopedDNSInactiveRule(6, "vendor", []string{"-A", "OUTPUT", "--comment", strings.Repeat("literal ", 3), "-j", "RZD_orphan"}); err == nil {
		t.Fatal("last-row reference ignored")
	}
}
