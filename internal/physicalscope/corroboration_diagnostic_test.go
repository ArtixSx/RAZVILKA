package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestPhysicalCorroborationClosedDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		branch string
		change func(*[]message, *[]message, *[]message, []nativeSegment)
	}{
		{"link.decode", func(l, a, r *[]message, n []nativeSegment) { (*l)[0].data = nil }},
		{"link.duplicate-index", func(l, a, r *[]message, n []nativeSegment) { *l = append(*l, (*l)[0]) }},
		{"route.decode", func(l, a, r *[]message, n []nativeSegment) { (*r)[0].data = nil }},
		{"native.bridge.required-mask", func(l, a, r *[]message, n []nativeSegment) { delete(n[0].fields, "mask") }},
		{"native.bridge.ipv6-value", func(l, a, r *[]message, n []nativeSegment) { n[0].fields["ipv6"] = "private-input" }},
		{"native.bridge.address", func(l, a, r *[]message, n []nativeSegment) { n[0].fields["address"] = "private-input" }},
		{"native.connected", func(l, a, r *[]message, n []nativeSegment) { n[0].connected = "no" }},
		{"bridge.match.mac", func(l, a, r *[]message, n []nativeSegment) {
			(*l)[0] = linkFrame(9, "Home", "bridge", "02:00:00:00:00:09", 0)
		}},
		{"bridge.match.kind", func(l, a, r *[]message, n []nativeSegment) {
			(*l)[0] = linkFrame(9, "Home", "tun", "02:00:00:00:00:01", 0)
		}},
		{"bridge.match.link-type", func(l, a, r *[]message, n []nativeSegment) { binary.NativeEndian.PutUint16((*l)[0].data[2:4], 772) }},
		{"bridge.match.prefixes", func(l, a, r *[]message, n []nativeSegment) { (*a)[0] = addressFrame(9, "192.0.3.1/24") }},
		{"bridge.match.host-address", func(l, a, r *[]message, n []nativeSegment) { (*a)[0] = addressFrame(9, "192.0.2.2/24") }},
		{"bridge.match.address-decode", func(l, a, r *[]message, n []nativeSegment) { (*a)[0].data[2] = 0x40 }},
		{"bridge.match.ambiguous", func(l, a, r *[]message, n []nativeSegment) {
			*l = append(*l, linkFrame(10, "br-other", "bridge", "02:00:00:00:00:01", 0))
			*a = append(*a, addressFrame(10, "192.0.2.1/24"))
		}},
		{"bridge.wan", func(l, a, r *[]message, n []nativeSegment) { *r = append(*r, routeFrame(9)) }},
		{"member.wan", func(l, a, r *[]message, n []nativeSegment) { *r = append(*r, routeFrame(4)) }},
		{"member.count", func(l, a, r *[]message, n []nativeSegment) { *l = append((*l)[:1], (*l)[2:]...) }},
		{"member.native-match.missing", func(l, a, r *[]message, n []nativeSegment) {
			(*l)[1] = linkFrame(4, "eth0", "", "02:00:00:00:00:09", 9)
		}},
		{"member.native-match.ambiguous", func(l, a, r *[]message, n []nativeSegment) {
			*l = append(*l, linkFrame(6, "eth2", "", "02:00:00:00:00:02", 9))
		}},
		{"member.native-match.reused", func(l, a, r *[]message, n []nativeSegment) { n[0].members = append(n[0].members, "1") }},
		{"member.kernel-unmatched", func(l, a, r *[]message, n []nativeSegment) {
			*l = append(*l, linkFrame(6, "eth2", "", "02:00:00:00:00:06", 9))
		}},
		{"address.duplicate", func(l, a, r *[]message, n []nativeSegment) { *a = append(*a, (*a)[0]) }},
	} {
		t.Run(tc.branch, func(t *testing.T) {
			n, err := parseNDM([]byte(ndmFixture()))
			if err != nil {
				t.Fatal(err)
			}
			l, a, r := kernelFixture()
			tc.change(&l, &a, &r, n)
			_, err = assembleSegments(Selection{HomeSegmentID: "Home"}, n, true, l, a, r)
			want := "physical LAN: kernel.corroboration." + tc.branch
			if !errors.Is(err, ErrUnknown) || err.Error() != want {
				t.Fatalf("closed refusal mismatch: got %v, want %s", err, want)
			}
			for _, private := range []string{"192.0.", "02:00:", "Home", "eth0", "private-input"} {
				if strings.Contains(err.Error(), private) {
					t.Fatal("diagnostic contains input data")
				}
			}
		})
	}
}

func TestPhysicalCorroborationDiagnosticSurvivesObserveAndClosesFence(t *testing.T) {
	o, m, ctx := newModel(t)
	m.selection.GuestSegmentIDs = nil
	n, err := parseNDM([]byte(ndmFixture()))
	if err != nil {
		t.Fatal(err)
	}
	l, a, r := kernelFixture()
	l[1] = linkFrame(4, "eth0", "", "02:00:00:00:00:09", 9)
	o.source.capture = func(context.Context, Selection) ([]Segment, []Device, error) {
		segments, err := assembleSegments(m.selection, n, true, l, a, r)
		return segments, nil, err
	}
	review, err := o.Observe(ctx)
	var diagnostic *failure
	if review != nil || !errors.Is(err, ErrUnknown) || !errors.As(err, &diagnostic) || diagnostic.stage != "kernel.corroboration.member.native-match.missing" || !m.fence.closed {
		t.Fatal("failed observation lost its closed branch or retained a live review", err)
	}
}
