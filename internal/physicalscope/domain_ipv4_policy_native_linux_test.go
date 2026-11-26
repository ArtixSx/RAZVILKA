//go:build linux

package physicalscope

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// This separate gate proves only the real kernel transport/parser. It is not
// a fallback in the public API when the Provider refuses an unusual proc mount.
func TestNativeDomainIPv4PolicyKernelOnly(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_POLICY_KERNEL_READ") != "1" {
		t.Skip("explicit kernel-only read gate; no Provider or Apply proof")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	rules, err := platformDomainIPv4PolicyDump(ctx, 34, 2)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := platformDomainIPv4PolicyDump(ctx, 26, 2)
	if err != nil {
		t.Fatal(err)
	}
	links, err := platformDomainIPv4PolicyDump(ctx, 18, 0)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := decodeDomainIPv4PolicyInventory(rules, routes, links)
	if err != nil || len(observed.Rules) == 0 || len(observed.Links) == 0 {
		t.Fatal("kernel-only complete dump", err)
	}
	if os.Getenv("RAZVILKA_DOMAIN_POLICY_LOOKUP_FIXTURE") == "1" {
		if len(observed.Rules) != 7 {
			t.Fatalf("seven-rule fixture: count=%d", len(observed.Rules))
		}
		ingress, err := net.InterfaceByName("rz-domain-in")
		if err != nil {
			t.Fatal(err)
		}
		egress, err := net.InterfaceByName("rz-domain-out")
		if err != nil {
			t.Fatal(err)
		}
		for _, mark := range []uint32{0, 42} {
			query := DomainIPv4PolicyLookupQuery{Source: netip.MustParseAddr("192.168.71.2"), Destination: netip.MustParseAddr("93.184.216.34"), IngressIndex: ingress.Index, Mark: mark}
			path, err := platformDomainIPv4PolicyRoute(ctx, query)
			wantTable := uint32(254)
			if mark == 42 {
				wantTable = 10037
			}
			if err != nil || path.Table != wantTable || path.Mark != mark || path.IngressIndex != ingress.Index || path.EgressIndex != egress.Index {
				t.Fatalf("kernel-only marked lookup: mark=%d table=%d err=%v", mark, path.Table, err)
			}
		}
	}
	t.Logf("kernel-only transport/parser: rules=%d routes=%d links=%d; Provider, packet semantics and Apply are unproven", len(observed.Rules), len(observed.Routes), len(observed.Links))
}

// Opt-in, read-only: no network resources or test packets are created here.
func TestNativeDomainIPv4PolicyInventory(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_POLICY_READ") != "1" {
		t.Skip("explicit read-only kernel inventory gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider := netidentity.NewProcProvider()
	if os.Getenv("RAZVILKA_DOMAIN_POLICY_STOCK") == "1" {
		var err error
		provider, err = netidentity.NewReviewedStockNC1812Provider(ctx)
		if err != nil {
			t.Fatal("reviewed stock provider unavailable", err)
		}
	}
	id, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ReadDomainIPv4PolicySnapshot(ctx, provider, id)
	if err != nil || len(first.Links) == 0 || len(first.Rules) == 0 {
		t.Fatal("complete read-only policy observation failed", err)
	}
	loopback := false
	for _, link := range first.Links {
		loopback = loopback || link.Name == "lo"
	}
	if !loopback {
		t.Fatal("whole link dump omitted loopback")
	}
	other := id
	other.BootID = "12345678-1234-1234-1234-123456789abc"
	if other.BootID == id.BootID {
		other.BootID = "23456789-1234-1234-1234-123456789abc"
	}
	if _, err := ReadDomainIPv4PolicySnapshot(ctx, provider, other); err == nil {
		t.Fatal("foreign identity supplied a snapshot")
	}
	cancel()
	if _, err := ReadDomainIPv4PolicySnapshot(ctx, provider, id); err == nil {
		t.Fatal("cancelled capture supplied a snapshot")
	}
	t.Logf("kernel-only readonly dumps: rules=%d routes=%d links=%d; no ip executable, packet or Apply authority", len(first.Rules), len(first.Routes), len(first.Links))
}

// The coordinator prepares an isolated namespace containing seven RPDB rules,
// rz-domain-in/out and table10037 for mark42. The test itself only reads.
func TestNativeDomainIPv4PolicyMarkedLookup(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_POLICY_LOOKUP_FIXTURE") != "1" {
		t.Skip("explicit isolated marked-route fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider := netidentity.NewProcProvider()
	id, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := net.InterfaceByName("rz-domain-in")
	if err != nil {
		t.Fatal(err)
	}
	egress, err := net.InterfaceByName("rz-domain-out")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadDomainIPv4PolicySnapshot(ctx, provider, id)
	if err != nil || len(snapshot.Rules) != 7 {
		t.Fatalf("seven-rule namespace: count=%d err=%v", len(snapshot.Rules), err)
	}
	for _, mark := range []uint32{0, 42} {
		query := DomainIPv4PolicyLookupQuery{Source: netip.MustParseAddr("192.168.71.2"), Destination: netip.MustParseAddr("93.184.216.34"), IngressIndex: ingress.Index, Mark: mark}
		got, err := ReadDomainIPv4PolicyRoute(ctx, provider, id, query)
		wantTable := uint32(254)
		if mark == 42 {
			wantTable = 10037
		}
		if err != nil || got.Table != wantTable || got.Mark != mark || got.EgressIndex != egress.Index || got.IngressIndex != ingress.Index {
			t.Fatalf("explicit marked FIB lookup: mark=%d table=%d err=%v", mark, got.Table, err)
		}
		window, err := ReadDomainIPv4ForwardedPolicyWindow(ctx, provider, id, query)
		if err != nil || window.Identity != id || len(window.Inventory.Rules) != 7 || window.Lookup.Table != wantTable || window.Lookup.EgressIndex != egress.Index {
			t.Fatalf("original forwarded policy window: mark=%d table=%d err=%v", mark, window.Lookup.Table, err)
		}
	}
	t.Log("actual kernel selected main and alternate table inside a read-only notification window from the explicit mark; no application traffic or packet-policy admission")
}
