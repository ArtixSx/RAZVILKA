package dataplane

import (
	"net/netip"
	"testing"
)

func TestXraySelectedTCPRuntimeAbsenceBothFamiliesAndOverlap(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.168.1.1:23456")
	for _, text := range []string{"192.168.2.1:23456", "[2001:db8::1]:23456", "192.168.1.1:23457"} {
		if err := xraySelectedTCPListenerAbsent([]xraySelectedTCPSocketRow{{local: netip.MustParseAddrPort(text), state: 10, inode: 5}}, nil, endpoint); err != nil {
			t.Fatal("disjoint listener refused", err)
		}
	}
	for _, text := range []string{"192.168.1.1:23456", "0.0.0.0:23456", "[::]:23456", "[::ffff:192.168.1.1]:23456"} {
		row := xraySelectedTCPSocketRow{local: netip.MustParseAddrPort(text), state: 10, inode: 5}
		if err := xraySelectedTCPListenerAbsent(nil, []xraySelectedTCPSocketRow{row}, endpoint); err == nil {
			t.Fatal("overlap accepted", text)
		}
	}
	if err := xraySelectedTCPListenerAbsent(nil, nil, endpoint); err != nil {
		t.Fatal("complete empty tables refused")
	}
}
