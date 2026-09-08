package sources

import "testing"

func TestAuditCIDRRejectsPrivateAndSpecialUseOverlaps(t *testing.T) {
	for _, raw := range []string{"172.0.0.0/8", "192.0.0.0/8", "100.0.0.0/8", "198.0.0.0/8", "192.0.2.0/24", "198.18.0.0/15", "2001::/16", "2001:db8::/32", "::ffff:8.8.8.0/120"} {
		if _, err := normalizeCIDR(raw); err == nil {
			t.Errorf("accepted CIDR containing non-public or mapped addresses: %s", raw)
		}
	}
}
