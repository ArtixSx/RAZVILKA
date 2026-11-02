package dataplane

import "testing"

func TestMihomoLiveCoordinatesPreserveEveryHistoricalOwner(t *testing.T) {
	old := []PolicyOwnershipSpec{
		{Adapter: "warp-wg", Interface: "rz-warp", Table: 201, PriorityBase: 18100, PriorityEnd: 19123, SharedPriorityBase: 60, SharedPriorityEnd: 61, EndpointPriority: 50, EndpointMark: 0x01000000, EndpointTable: 211},
		{Adapter: "usque", Interface: "rz-usque", Table: 202, PriorityBase: 20000, PriorityEnd: 21023, SharedPriorityBase: 62, SharedPriorityEnd: 63},
		{Adapter: "sing-box", Interface: "rz-sing", Table: 203, PriorityBase: 22000, PriorityEnd: 23023, SharedPriorityBase: 64, SharedPriorityEnd: 65},
		{Adapter: "xray", Interface: "rz-xray", Table: 204, PriorityBase: 24000, PriorityEnd: 25023, SharedPriorityBase: 66, SharedPriorityEnd: 67},
		{Adapter: "amneziawg", Interface: "rz-awg", Table: 205, PriorityBase: 26000, PriorityEnd: 27023, SharedPriorityBase: 68, SharedPriorityEnd: 69, EndpointPriority: 51, EndpointMark: 0x02000000, EndpointTable: 212},
		{Adapter: "wireguard", Interface: "rz-wg", Table: 206, PriorityBase: 28000, PriorityEnd: 29023, SharedPriorityBase: 70, SharedPriorityEnd: 71, EndpointPriority: 52, EndpointMark: 0x04000000, EndpointTable: 213},
	}
	owners, transit := PolicyOwnershipSpecs(), NodeTransitOwnershipSpecs()
	if len(owners) != len(old)+1 || len(transit) != len(owners) {
		t.Fatal("incomplete closed ownership inventory")
	}
	for i, expected := range old {
		if owners[i] != expected || transit[i] != (NodeTransitOwnershipSpec{Engine: expected.Adapter, Interface: expected.Interface, Table: expected.Table, Priority: 72 + i}) {
			t.Fatal("retained historical identity changed", i, owners[i], transit[i])
		}
	}
	m := owners[len(old)]
	if m.Table != 207 || m.PriorityBase != 31200 || m.PriorityEnd != 32223 || m.SharedPriorityBase != 78 || m.SharedPriorityEnd != 79 || transit[len(old)].Priority != 80 {
		t.Fatal("new reservation drift", m)
	}
	for _, priority := range []int{31000, 32766, 32767} {
		if priority >= m.PriorityBase && priority <= m.PriorityEnd || priority >= m.SharedPriorityBase && priority <= m.SharedPriorityEnd || priority == transit[len(old)].Priority {
			t.Fatal("Mihomo overlaps B baseline or default RPDB", priority)
		}
	}
	for i, a := range owners {
		for j, b := range owners {
			if i != j && (a.Table == b.Table || a.Interface == b.Interface || a.PriorityBase <= b.PriorityEnd && b.PriorityBase <= a.PriorityEnd || a.SharedPriorityBase <= b.SharedPriorityEnd && b.SharedPriorityBase <= a.SharedPriorityEnd) {
				t.Fatal("overlapping ownership", a, b)
			}
		}
	}
}
