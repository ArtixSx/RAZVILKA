package physicalscope

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

// guestPacketTopology adds a guest access point (ra1) in its own Guest
// bridge, outside the selected Home segment, as on the owner's router.
func guestPacketTopology(t *testing.T) (ipv4LANPacketTopology, Link) {
	t.Helper()
	in, _ := scopeOptionsKernelFixture()
	in.links = append(in.links,
		linkFrame(22, "Guest", "bridge", "02:00:00:00:00:22", 0),
		linkFrame(21, "ra1", "", "02:00:00:00:00:21", 22),
	)
	topology, err := packetTopologyFromFacts(in, IPv4LANPacketIntent{SegmentIDs: []string{"Bridge0"}})
	if err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	for _, l := range topology.links {
		if l.Interface == "ra1" {
			return topology, l
		}
	}
	t.Fatal("guest AP missing from the original links")
	return topology, Link{}
}

func packetFenceState(topology ipv4LANPacketTopology) *fenceCollectorState {
	return &fenceCollectorState{packet: &ipv4LANPacketFenceSnapshot{original: topology}, bound: true}
}

// Router probe 491: a station event of a guest AP outside Home reached the
// second pass over boundarySegments(), matched the synthetic member without
// NDM facts and refused with notifications.wireless.role.origin.
func TestPacketForeignWirelessEventKeepsFence(t *testing.T) {
	topology, guest := guestPacketTopology(t)
	s := packetFenceState(topology)
	for _, size := range []int{0, 16, 256} {
		if err := s.checkPurposeNotifications([]message{wirelessFrame(guest, wirelessCustom(make([]byte, size)))}); err != nil {
			t.Fatalf("guest station event revoked the packet fence: %v", DiagnosticStages(err))
		}
	}
	if s.membershipEpoch != 0 {
		t.Fatal("advisory WEXT moved the membership epoch")
	}
}

func TestPacketForeignWirelessEventRefusesChangedOrForgedShapes(t *testing.T) {
	topology, guest := guestPacketTopology(t)
	var home Link
	for _, member := range topology.home.Members {
		if member.Interface == "eth0" {
			home = member
		}
	}
	if home.IfIndex == 0 {
		t.Fatal("fixture has no Home member")
	}
	var bridge Link
	for _, l := range topology.links {
		if l.Interface == "Guest" {
			bridge = l
		}
	}
	for name, c := range map[string]struct {
		event message
		stage string
	}{
		"reused-index":  {wirelessFrame(Link{Interface: "ra9", IfIndex: guest.IfIndex, LinkType: guest.LinkType, Flags: guest.Flags}, wirelessCustom(nil)), "notifications.wireless.foreign.binding"},
		"renamed":       {wirelessFrame(Link{Interface: guest.Interface, IfIndex: 99, LinkType: guest.LinkType, Flags: guest.Flags}, wirelessCustom(nil)), "notifications.wireless.foreign.binding"},
		"flags-changed": {wirelessFrame(Link{Interface: guest.Interface, IfIndex: guest.IfIndex, LinkType: guest.LinkType, Flags: guest.Flags | 0x40}, wirelessCustom(nil)), "notifications.wireless.header"},
		"bridge":        {wirelessFrame(bridge, wirelessCustom(nil)), "notifications.wireless.foreign.link"},
		"home-member":   {wirelessFrame(home, wirelessCustom(nil)), "notifications.wireless.role"},
		"forged-seq": func() struct {
			event message
			stage string
		} {
			m := wirelessFrame(guest, wirelessCustom(nil))
			m.seq = 7
			return struct {
				event message
				stage string
			}{m, "notifications.wireless.header"}
		}(),
		"extra-attribute": func() struct {
			event message
			stage string
		} {
			m := wirelessFrame(guest, wirelessCustom(nil))
			m.data = append(m.data, attr(1, []byte{2, 0, 0, 0, 0, 0x21})...)
			return struct {
				event message
				stage string
			}{m, "notifications.wireless.attributes"}
		}(),
		"payload-command": func() struct {
			event message
			stage string
		} {
			payload := wirelessCustom(nil)
			binary.NativeEndian.PutUint16(payload[2:4], 0x8b1a)
			return struct {
				event message
				stage string
			}{wirelessFrame(guest, payload), "notifications.wireless.payload.command"}
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			err := packetFenceState(topology).checkPurposeNotifications([]message{c.event})
			assertFenceFailure(t, err, c.stage)
		})
	}
	// An interface absent from the original snapshot keeps the old decoder
	// path: a partial notification without MAC/master asserts nothing.
	unknown := wirelessFrame(Link{Interface: "ra7", IfIndex: 77, LinkType: 1, Flags: 1}, wirelessCustom(nil))
	if err := packetFenceState(topology).checkPurposeNotifications([]message{unknown}); err != nil {
		t.Fatal("unknown partial link became a refusal", DiagnosticStages(err))
	}
}

func membershipEvent(kind uint16, address, mac string, state uint16) message {
	m := neighborFrame(9, address, mac, state)
	m.kind = kind
	return m
}

// Router probe 490: ordinary neighbor refreshes (REACHABLE/STALE/DELAY/PROBE
// of the same MAC) moved the membership epoch and invalidated every review.
// Only a change of what packetBindMembership reads may move it.
func TestPacketMembershipEpochCountsOnlyClassChanges(t *testing.T) {
	topology := packetCollectorTopology(t)
	s := packetFenceState(topology)
	home, foreign, err := packetNeighborBoundary(t.Context(), topology, selectedTestNeighbors())
	if err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	if err := s.seedMembership(packetMembershipClasses(home, foreign)); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name  string
		event message
		bump  bool
	}{
		{"stale-refresh", membershipEvent(28, "192.0.2.20", projectionClientMAC, 4), false},
		{"delay-refresh", membershipEvent(28, "192.0.2.20", projectionClientMAC, 8), false},
		{"probe-refresh", membershipEvent(28, "192.0.2.20", projectionClientMAC, 16), false},
		{"ipv6-refresh", membershipEvent(28, "2001:db8::20", projectionClientMAC, 2), false},
		{"mac-change", membershipEvent(28, "192.0.2.20", projectionOtherMAC, 2), true},
		{"mac-restore", membershipEvent(28, "192.0.2.20", projectionClientMAC, 2), true},
		{"failed", membershipEvent(28, "192.0.2.20", projectionClientMAC, 32), true},
		{"failed-again", membershipEvent(28, "192.0.2.20", projectionClientMAC, 32), false},
		{"usable-again", membershipEvent(28, "192.0.2.20", projectionClientMAC, 2), true},
		{"deleted", membershipEvent(29, "192.0.2.20", projectionClientMAC, 4), true},
		{"re-added", membershipEvent(28, "192.0.2.20", projectionClientMAC, 2), true},
		{"new-device", membershipEvent(28, "192.0.2.44", "02:00:00:00:00:44", 2), true},
		{"new-device-refresh", membershipEvent(28, "192.0.2.44", "02:00:00:00:00:44", 4), false},
	}
	for _, step := range steps {
		before := s.membershipEpoch
		if err := s.checkPurposeNotifications([]message{step.event}); err != nil {
			t.Fatalf("%s refused: %v", step.name, DiagnosticStages(err))
		}
		if moved := s.membershipEpoch != before; moved != step.bump {
			t.Fatalf("%s moved the epoch: %t, want %t", step.name, moved, step.bump)
		}
	}
}

func TestPacketMembershipSeedNeverOverridesObservedRowsOrMovesEpoch(t *testing.T) {
	s := packetFenceState(packetCollectorTopology(t))
	if err := s.checkPurposeNotifications([]message{membershipEvent(28, "192.0.2.20", projectionOtherMAC, 2)}); err != nil {
		t.Fatal(err)
	}
	epoch := s.membershipEpoch
	n, _, err := packetDecodeNeighbor(membershipEvent(28, "192.0.2.20", projectionClientMAC, 2), s.packet.original)
	if err != nil {
		t.Fatal(err)
	}
	// An older dump of the same row cannot replace the newer event's class.
	if err := s.seedMembership(map[string]string{packetMembershipKey(n): packetMembershipClass(28, n)}); err != nil || s.membershipEpoch != epoch {
		t.Fatal("seed moved the epoch", err)
	}
	if err := s.checkPurposeNotifications([]message{membershipEvent(28, "192.0.2.20", projectionOtherMAC, 4)}); err != nil || s.membershipEpoch != epoch {
		t.Fatal("seed replaced the observed class")
	}
	if (&fenceCollectorState{}).seedMembership(map[string]string{}) == nil {
		t.Fatal("seed accepted without a bound packet purpose")
	}
}

func TestPacketMembershipClassMemoryIsBounded(t *testing.T) {
	s := packetFenceState(packetCollectorTopology(t))
	s.membershipClasses = make(map[string]string, maxMembershipClasses)
	for i := range maxMembershipClasses {
		s.membershipClasses[fmt.Sprint("row", i)] = "x"
	}
	address := netip.MustParseAddr("192.0.2.77")
	for range 2 {
		before := s.membershipEpoch
		if err := s.checkPurposeNotifications([]message{membershipEvent(28, address.String(), "02:00:00:00:00:77", 2)}); err != nil {
			t.Fatal(err)
		}
		if s.membershipEpoch == before {
			t.Fatal("an untracked row stopped moving the epoch")
		}
	}
	if len(s.membershipClasses) != maxMembershipClasses {
		t.Fatal("class memory grew past its bound")
	}
}

// End to end through the original collector: refreshes keep an existing
// review current, a real change still invalidates it, and refreshes during
// an observation (router probe 490) no longer refuse it.
func TestIPv4LANPacketScopeMembershipSurvivesNeighborRefresh(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	defer b.Close()
	refresh := []message{membershipEvent(28, "192.0.2.20", projectionClientMAC, 4), membershipEvent(28, "192.0.2.30", projectionExcludedMAC, 8), membershipEvent(28, "fe80::20", projectionClientMAC, 2)}
	for _, event := range refresh {
		m.transport.push(fenceTestDatagram{raw: frame(event)})
	}
	waitFenceTestDrained(t, m.transport, len(refresh))
	if err := b.Current(ctx); err != nil {
		t.Fatal("ordinary neighbor refresh invalidated the review", DiagnosticStages(err))
	}
	captures := m.captures
	m.onCapture = func(n int) {
		if n == captures+1 {
			for _, event := range refresh {
				m.transport.push(fenceTestDatagram{raw: frame(event)})
			}
		}
	}
	during, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal("refresh during observation refused it", DiagnosticStages(err))
	}
	during.Close()
	m.onCapture = nil
	m.transport.push(fenceTestDatagram{raw: frame(membershipEvent(28, "192.0.2.20", projectionOtherMAC, 2))})
	if err := b.Current(ctx); err == nil || !slices.Contains(DiagnosticStages(err), "packet.membership.changed") {
		t.Fatal("a real association change kept the old review", DiagnosticStages(err))
	}
}

// Seeding goes through the original collector: after Close it is refused
// like every other checkpoint, and a refused seed never ends a live fence.
func TestPacketMembershipSeedFollowsCollectorLifetime(t *testing.T) {
	f := newFenceTestTransport()
	r := newOriginalFenceCollector(f.source())
	ctx := t.Context()
	if err := r.seedPacketMembership(ctx, nil); err == nil {
		t.Fatal("seed accepted before the packet purpose was bound")
	}
	topology := packetCollectorTopology(t)
	if _, err := r.checkPacket(ctx, topology); err != nil {
		t.Fatal("refused seed ended the original collector", DiagnosticStages(err))
	}
	if err := r.seedPacketMembership(ctx, map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	r.close()
	if err := r.seedPacketMembership(ctx, map[string]string{"k": "v"}); err == nil {
		t.Fatal("closed collector accepted a seed")
	}
}
