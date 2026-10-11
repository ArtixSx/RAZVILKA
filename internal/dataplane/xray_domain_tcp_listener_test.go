package dataplane

import (
	"errors"
	"net/netip"
	"testing"
)

// Complete-table comparison fixtures only, not native listener/FD proof.
func TestXrayDomainTCPListenerKeepsLoopbackPredicateSeparate(t *testing.T) {
	endpoint := netip.MustParseAddrPort("127.0.0.1:16444")
	original := xraySelectedTCPSocketRow{local: endpoint, state: 10, inode: 91}
	if got, err := xrayDomainTCPListenerInode([]xraySelectedTCPSocketRow{original}, nil, endpoint); err != nil || got != original.inode {
		t.Fatal("private exact loopback comparison failed", got, err)
	}
	if _, err := xraySelectedTCPListenerInode([]xraySelectedTCPSocketRow{original}, nil, endpoint); err == nil {
		t.Fatal("domain mode widened literal LAN listener admission")
	}
	for _, conflict := range []xraySelectedTCPSocketRow{
		{local: netip.MustParseAddrPort("0.0.0.0:16444"), state: 10, inode: 92},
		{local: endpoint, state: 10, inode: 92},
		{local: netip.MustParseAddrPort("[::]:16444"), state: 10, inode: 92},
		{local: netip.MustParseAddrPort("[::ffff:127.0.0.1]:16444"), state: 10, inode: 92},
	} {
		v4, v6 := []xraySelectedTCPSocketRow{original}, []xraySelectedTCPSocketRow(nil)
		if conflict.local.Addr().Is4() {
			v4 = append(v4, conflict)
		} else {
			v6 = append(v6, conflict)
		}
		if _, err := xrayDomainTCPListenerInode(v4, v6, endpoint); !errors.Is(err, ErrXrayDomainTCPOriginal) {
			t.Fatal("ambiguous/overlapping listener supplied a sole inode", err)
		}
	}
	if _, err := xrayDomainTCPListenerInode(nil, nil, endpoint); !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("missing original listener supplied presence", err)
	}
}
