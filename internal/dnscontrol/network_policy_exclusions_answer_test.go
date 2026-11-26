package dnscontrol

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

// A filtering upstream answers blocked names with 0.0.0.0/:: (or loopback),
// and AAAA may carry an IPv4-mapped address. Before this change every such
// address became a target the exclusion set refuses as an unknown identity,
// which failed the publication of the whole answer.
func TestNetworkPolicyDNSAnswerTargetsNormalizeAddresses(t *testing.T) {
	f := &NetworkPolicyDNSExclusions{identities: func(context.Context, string) ([]string, error) { return nil, nil }}
	f.self = f
	var addresses []netip.Addr
	for _, raw := range []string{"0.0.0.0", "::", "127.0.0.1", "::1", "fe80::1", "169.254.1.1", "224.0.0.1", "ff02::1", "::ffff:203.0.113.7", "203.0.113.8", "2001:db8::8"} {
		addresses = append(addresses, netip.MustParseAddr(raw))
	}
	targets, err := f.targets(context.Background(), "", []string{"blocked.example"}, addresses)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, target := range targets {
		if target.Address.IsValid() {
			got = append(got, target.Address.String())
		}
	}
	want := []string{"203.0.113.7", "203.0.113.8", "2001:db8::8"}
	if len(got) != len(want) {
		t.Fatalf("address targets %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("address targets %v, want %v", got, want)
		}
	}
	// Every produced target is classifiable, and the mapped address is now
	// matched by its IPv4 exclusion instead of failing the answer.
	set := config.EffectiveExclusionSet{Manual: []config.ResourceMatch{{Kind: "ip", Value: "203.0.113.7"}}, Russian: []config.ResourceMatch{}}
	excluded := false
	for _, target := range targets {
		match, err := set.Matches(target)
		if err != nil {
			t.Fatalf("produced target %+v is unclassifiable: %v", target, err)
		}
		excluded = excluded || match
	}
	if !excluded {
		t.Fatal("IPv4-mapped answer escaped its IPv4 exclusion")
	}
}
