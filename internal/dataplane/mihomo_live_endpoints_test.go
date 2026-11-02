package dataplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netresolve"
)

func TestMihomoLiveEndpointActualLiteralResolverRepresentation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// The stdlib resolves a literal locally: no DNS server/network fixture.
	addresses, err := netresolve.LookupNetIP(ctx, "ip", "1.1.1.1")
	if err != nil || len(addresses) != 1 {
		t.Fatal(addresses, err)
	}
	canonical, err := mihomoLiveResolvedIPv4(addresses)
	if err != nil || len(canonical) != 1 || canonical[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatal("actual stdlib IPv4 representation refused", addresses, canonical, err)
	}
	t.Logf("actual literal representation Is4=%v Is4In6=%v normalized=%s", addresses[0].Is4(), addresses[0].Is4In6(), canonical[0])
	if canonical[0].Is4In6() {
		t.Fatal("mapped comparison persisted")
	}
}

func TestMihomoLiveEndpointNormalizationRetainsStrictAllAnswerBoundary(t *testing.T) {
	valid := []netip.Addr{netip.MustParseAddr("::ffff:1.1.1.1"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")}
	got, err := mihomoLiveResolvedIPv4(valid)
	if err != nil || len(got) != len(valid) || got[0] != got[1] || got[2] != valid[2] || !valid[0].Is4In6() {
		t.Fatal("answer loss or caller mutation", got, err)
	}
	for _, raw := range []string{"::ffff:192.168.1.1", "::ffff:127.0.0.1", "::ffff:100.64.0.1", "::ffff:192.0.2.1", "2606:4700::1111", "fe80::1%eth0", "::ffff:1.1.1.1%eth0"} {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = mihomoLiveResolvedIPv4([]netip.Addr{valid[0], address}); err == nil {
			t.Fatal("unsafe second answer accepted", raw)
		}
	}
	if _, err = mihomoLiveResolvedIPv4(nil); err == nil {
		t.Fatal("empty set accepted")
	}
	if _, err = mihomoLiveResolvedIPv4(make([]netip.Addr, 65)); err == nil {
		t.Fatal("unbounded set accepted")
	}
}
