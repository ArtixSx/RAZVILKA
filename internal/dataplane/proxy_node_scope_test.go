package dataplane

import (
	"errors"
	"strings"
	"testing"
)

func TestScopedXrayRefusesAmbiguousDestinationOwnership(t *testing.T) {
	for _, scope := range []struct {
		name, broad, narrow string
		domain              bool
	}{
		{"ipv4", "8.0.0.0/8", "8.8.8.8/32", false},
		{"ipv6", "2001:db8::/32", "2001:db8:1234::/48", false},
		{"domain", "example.com", "api.example.com", true},
	} {
		t.Run(scope.name, func(t *testing.T) {
			requests := []NodeRouteRequest{{NodeID: "node-" + strings.Repeat("a", 64)}, {NodeID: "node-" + strings.Repeat("b", 64)}}
			if scope.domain {
				requests[0].Domains, requests[1].Domains = []string{scope.broad}, []string{scope.narrow}
			} else {
				requests[0].Destinations, requests[1].Destinations = []string{scope.broad}, []string{scope.narrow}
			}
			for _, reversed := range []bool{false, true} {
				if reversed {
					requests[0], requests[1] = requests[1], requests[0]
				}
				if _, err := scopedXrayRules(requests); !errors.Is(err, ErrNodeDestinationScope) {
					t.Fatal("overlapping exits accepted through destination-only SOCKS hop", reversed, err)
				}
			}
			requests[1].NodeID = requests[0].NodeID
			if _, err := scopedXrayRules(requests); err != nil {
				t.Fatal("same exit unnecessarily rejected", err)
			}
		})
	}
}
