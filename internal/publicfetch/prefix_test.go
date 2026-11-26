package publicfetch

import (
	"net/netip"
	"testing"
)

func TestPublicPrefixChecksWholeRange(t *testing.T) {
	if PublicPrefix(netip.Prefix{}) {
		t.Fatal("invalid prefix accepted")
	}
	for _, raw := range []string{"172.0.0.0/8", "100.0.0.0/8", "192.0.0.0/8", "198.0.0.0/8", "2000::/3", "::ffff:8.8.8.0/120"} {
		if PublicPrefix(netip.MustParsePrefix(raw)) {
			t.Errorf("range containing private/special-use addresses accepted: %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.0/24", "91.108.56.1/22", "149.154.160.0/20", "2001:b28:f23d::/48", "2606:4700:4700::/48"} {
		if !PublicPrefix(netip.MustParsePrefix(raw)) {
			t.Errorf("public prefix rejected: %s", raw)
		}
	}
}
