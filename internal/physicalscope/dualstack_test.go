package physicalscope

import (
	"context"
	"slices"
	"testing"
)

func TestPhysicalStockCorroboratesIPv4AndRetainsActualIPv6(t *testing.T) {
	native, err := parseNDM([]byte(ndmFixture()))
	if err != nil {
		t.Fatal(err)
	}
	l, a, r := kernelFixture()
	a = append(a, addressFrame(9, "2001:db8:1::1/64"))
	segments, err := assembleSegments(Selection{SegmentIDs: []string{"Bridge0"}}, native, true, l, a, r)
	if err != nil || len(segments) != 1 {
		t.Fatal(err)
	}
	if !slices.Equal(segments[0].Prefixes, []string{"192.0.2.0/24", "2001:db8:1::/64"}) || !slices.Equal(segments[0].LinkAddresses, []string{"192.0.2.1/24", "2001:db8:1::1/64", "fe80::1/64"}) {
		t.Fatal("actual complete address families were dropped or inferred")
	}
	for _, kind := range []string{"extra-ipv4-network", "missing-native-host", "dad-failed-ipv6", "ambiguous-bridge", "native-ipv6-dialect"} {
		t.Run(kind, func(t *testing.T) {
			l, a, r := kernelFixture()
			a = append(a, addressFrame(9, "2001:db8:1::1/64"))
			n, err := parseNDM([]byte(ndmFixture()))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "extra-ipv4-network":
				a = append(a, addressFrame(9, "198.51.100.1/24"))
			case "missing-native-host":
				a[0] = addressFrame(9, "192.0.2.2/24")
			case "dad-failed-ipv6":
				a[len(a)-1].data[2] = 0x40
			case "ambiguous-bridge":
				l = append(l, linkFrame(10, "br-other", "bridge", "02:00:00:00:00:01", 0))
				a = append(a, addressFrame(10, "192.0.2.1/24"), addressFrame(10, "2001:db8:2::1/64"))
			case "native-ipv6-dialect":
				n[0].fields["ipv6-subtree"] = "unsupported"
			}
			if _, err := assembleSegments(Selection{SegmentIDs: []string{"Bridge0"}}, n, true, l, a, r); err == nil {
				t.Fatal("IPv6 compatibility widened IPv4/bridge/dialect acceptance")
			}
		})
	}
}

func TestPhysicalStockDualStackMutationRevokesOriginalReview(t *testing.T) {
	for _, kind := range []string{"v6-prefix", "v6-host", "v6-removal", "v4-secondary-host"} {
		t.Run(kind, func(t *testing.T) {
			o, m, ctx := newModel(t)
			m.selection = Selection{Revision: 7, PolicyRevision: 3, SegmentIDs: []string{"Bridge0"}}
			native, err := parseNDM([]byte(ndmFixture()))
			if err != nil {
				t.Fatal(err)
			}
			l, original, r := kernelFixture()
			original = append(original, addressFrame(9, "2001:db8:1::1/64"))
			current := original
			o.source.capture = func(context.Context, Selection) ([]Segment, []Device, error) {
				segments, err := assembleSegments(m.selection, native, true, l, current, r)
				return segments, nil, err
			}
			review, err := o.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			current = slices.Clone(original)
			switch kind {
			case "v6-prefix":
				current[2] = addressFrame(9, "2001:db8:2::1/64")
			case "v6-host":
				current[2] = addressFrame(9, "2001:db8:1::2/64")
			case "v6-removal":
				current = current[:2]
			case "v4-secondary-host":
				current = append(current, addressFrame(9, "192.0.2.2/24"))
			}
			if o.Verify(ctx, review) == nil {
				t.Fatal("changed actual address set refreshed the held Review")
			}
			current = original
			if o.Verify(ctx, review) == nil {
				t.Fatal("restored dual-stack tuple revived an invalid Review")
			}
		})
	}
}
