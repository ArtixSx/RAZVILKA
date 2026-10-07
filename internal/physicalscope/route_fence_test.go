package physicalscope

import "testing"

func TestPhysicalWANExclusionHasContinuousRouteFence(t *testing.T) {
	segments := []Segment{{Interface: "Home", IfIndex: 9, Members: []Link{{Interface: "eth0", IfIndex: 4}}}}
	for _, index := range []int{9, 4} {
		for _, family := range []byte{2, 10} {
			added := routeFrame(index)
			added.data[0] = family
			added.flags = 0x400
			added.seq, added.pid = 51, 73
			removed := added
			removed.kind = 25
			removed.flags = 0
			if checkNotifications([]message{added, removed}, segments, nil) == nil {
				t.Fatal("restored Home/member WAN tuple refreshed original review")
			}
		}
	}
	foreign := routeFrame(20)
	foreign.flags = 0x400
	if err := checkNotifications([]message{foreign}, segments, nil); err != nil {
		t.Fatal("unrelated TUN default route poisoned LAN", err)
	}
	ownedTable := routeFrame(9)
	ownedTable.data[4] = 99
	ownedTable.flags = 0x400
	if err := checkNotifications([]message{ownedTable}, segments, nil); err != nil {
		t.Fatal("non-main owned policy route poisoned LAN", err)
	}
	nondefault := routeFrame(9)
	nondefault.data[1] = 24
	if err := checkNotifications([]message{nondefault}, segments, nil); err != nil {
		t.Fatal("connected route invented WAN", err)
	}
	unknown := routeFrame(20)
	unknown.data = append(unknown.data, attr(9, make([]byte, 8))...)
	if checkNotifications([]message{unknown}, segments, nil) == nil {
		t.Fatal("unknown default multipath ignored")
	}
	dump := foreign
	dump.flags = 2
	if checkNotifications([]message{dump}, segments, nil) == nil {
		t.Fatal("unsolicited route dump treated as notification")
	}
}
