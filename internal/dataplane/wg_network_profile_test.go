package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func wgNetworkDualStackProfile() string {
	profile := strings.Replace(testOwnWireGuardProfile(""), "Address = 10.66.0.2/32", "Address = 10.66.0.2/32, fd66::2/128", 1)
	return strings.Replace(profile, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0", 1)
}

func TestWGNetworkProfileCoverageRequiresEverySelectedFamily(t *testing.T) {
	for _, tc := range []struct {
		name, profile string
		valid         bool
	}{
		{"complete", wgNetworkDualStackProfile(), true},
		{"missing IPv6 peer coverage", strings.Replace(wgNetworkDualStackProfile(), ", ::/0", "", 1), false},
		{"missing IPv6 health source", strings.Replace(wgNetworkDualStackProfile(), ", fd66::2/128", "", 1), false},
		{"one host is not full IPv4", strings.Replace(wgNetworkDualStackProfile(), "0.0.0.0/0", "1.1.1.1/32", 1), false},
		{"complete union", strings.Replace(wgNetworkDualStackProfile(), "0.0.0.0/0, ::/0", "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1", 1), true},
		{"union has a hole", strings.Replace(wgNetworkDualStackProfile(), "0.0.0.0/0, ::/0", "0.0.0.0/1, 128.0.0.0/2, ::/0", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources, err := wgNetworkProfileSources(context.Background(), tc.profile, []string{"0.0.0.0/0", "::/0"})
			if (err == nil) != tc.valid {
				t.Fatal("peer or health family coverage", err)
			}
			if tc.valid && (len(sources) != 2 || sources[0] != netip.MustParseAddr("10.66.0.2") || sources[1] != netip.MustParseAddr("fd66::2")) {
				t.Fatal("health borrowed a LAN source", sources)
			}
		})
	}
}

func TestWGNetworkProfileCoverageCancellationAndSingleFamily(t *testing.T) {
	sources, err := wgNetworkProfileSources(context.Background(), testOwnWireGuardProfile(""), []string{"93.0.0.0/8"})
	if err != nil || len(sources) != 1 || !sources[0].Is4() {
		t.Fatal("single family network", sources, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := wgNetworkProfileSources(ctx, wgNetworkDualStackProfile(), []string{"0.0.0.0/0", "::/0"}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled network admission accepted", err)
	}
}
