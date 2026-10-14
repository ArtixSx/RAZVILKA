package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type packetTestFence struct{ reader *originalFenceCollector }

func (f *packetTestFence) check(ctx context.Context, t ipv4LANPacketTopology) (uint64, error) {
	return f.reader.checkPacket(ctx, t)
}
func (f *packetTestFence) seed(ctx context.Context, rows map[string]string) error {
	return f.reader.seedPacketMembership(ctx, rows)
}
func (f *packetTestFence) close() error { f.reader.close(); return nil }

type packetTestModel struct {
	intent          IPv4LANPacketIntent
	input           scopeOptionsInput
	frames          map[byte][]message
	id              netidentity.Identity
	transport       *fenceTestTransport
	reader          *originalFenceCollector
	control         *operationgate.ControlEpochReview
	controlRoot     string
	opens, captures int
	onCapture       func(int)
	sourceError     error
}

// Model only kernel/provider I/O; use actual typed control review and Gate,
// production topology/boundary/binding and the continuous original collector.
// This is not native hardware/packet/effect attestation.
func packetTestScope(t *testing.T, setup ...func(*packetTestModel)) (*IPv4LANPacketScope, *packetTestModel, context.Context) {
	t.Helper()
	in, frames := scopeOptionsKernelFixture()
	in.native = append(in.native, []byte(ndmObject("Guest", "Bridge1", "Guest", "Bridge")+ndmField("security-level", "protected"))...)
	m := &packetTestModel{input: in, frames: frames, intent: IPv4LANPacketIntent{Revision: 7, PolicyRevision: 3, Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{"Bridge0"}, ExcludedDeviceIDs: []string{physicalDeviceID("02:00:00:00:00:40")}, ExcludedCIDRs: []string{"198.51.100.0/24", "2001:db8:1::/64"}}, id: netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: "12345678-1234-1234-1234-123456789abc", PlatformReviewSHA256: "f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733"}, transport: newFenceTestTransport(), controlRoot: filepath.Join(t.TempDir(), "control")}
	for _, configure := range setup {
		configure(m)
	}
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), m.controlRoot); err != nil {
		t.Fatal(err)
	}
	g := &operationgate.Gate{}
	owned, release, err := g.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	ctx, cancel := context.WithTimeout(owned, 10*time.Second)
	t.Cleanup(cancel)
	m.control, err = g.ReviewControlEpoch(ctx, m.controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.control.Close() })
	source := ipv4LANPacketSource{ref: m.control.Reference(), current: func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
		if m.sourceError != nil {
			return m.sourceError
		}
		return use(c, m.id)
	}, control: func(c context.Context, retained bool) error {
		if retained {
			return m.control.CurrentForCleanup(c)
		}
		return m.control.Current(c)
	}, open: func(context.Context) (ipv4LANPacketFence, error) {
		m.opens++
		if m.opens != 1 {
			t.Fatal("original fence reopened")
		}
		m.reader = newOriginalFenceCollector(m.transport.source())
		return &packetTestFence{m.reader}, nil
	}, capture: func(c context.Context, i IPv4LANPacketIntent) (ipv4LANPacketCapture, error) {
		m.captures++
		if m.onCapture != nil {
			m.onCapture(m.captures)
		}
		topology, err := packetTopologyFromFacts(m.input, i)
		return ipv4LANPacketCapture{topology: topology, frames: m.frames}, err
	}}
	p, err := newIPv4LANPacketScope(ctx, func(context.Context) (IPv4LANPacketIntent, error) { return cloneIPv4LANPacketIntent(m.intent), nil }, source)
	if err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p, m, ctx
}

func TestIPv4LANPacketScopeMembershipChangesKeepOriginalA(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	initial := p.PacketFacts()
	if !reflect.DeepEqual(initial.ExcludedMACs, []string{"02:00:00:00:00:40"}) || !reflect.DeepEqual(initial.Intent.ExcludedCIDRs, m.intent.ExcludedCIDRs) {
		t.Fatal("offline literal negative lost")
	}
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(b.Facts().Devices) != 3 {
		t.Fatal("arbitrary peer router became an implicit exception")
	}
	// Same home prefix/owner, old address now belongs to another actual MAC.
	m.frames[2][0] = neighborFrame(9, "192.0.2.20", projectionOtherMAC, 2)
	m.frames[2] = append(m.frames[2], neighborFrame(9, "192.0.2.45", "02:00:00:00:00:45", 4))
	if err := p.Current(ctx); err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	if err := p.RetainedCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(initial, p.PacketFacts()) || m.opens != 1 {
		t.Fatal("ordinary membership reissued/mutated A")
	}
	assertFenceFailure(t, b.Current(ctx), "packet.membership.changed")
	fresh, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if !slices.ContainsFunc(fresh.Facts().Devices, func(d Device) bool { return d.MAC == projectionOtherMAC && slices.Contains(d.Addresses, "192.0.2.20") }) {
		t.Fatal("fresh tuple not observed")
	}
	m.frames[2] = selectedTestNeighbors()[2]
	if b.Current(ctx) == nil || fresh.Current(ctx) == nil {
		t.Fatal("old B revived after restore")
	}
	if err := p.Current(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIPv4LANPacketScopeUnknownPeerDoesNotGrantIdentityOrLegacyCoverage(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	for _, mac := range []string{"", "02:00:00:00:00:99"} {
		unknown := neighborFrame(9, "fe80::99", mac, 32)
		unknown.data[10] = 128
		m.frames[10] = append(selectedTestNeighbors()[10], unknown)
		if err := p.Current(ctx); err != nil {
			t.Fatal(DiagnosticStages(err))
		}
		b, err := p.ObserveMembership(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Facts().Devices) != 3 || slices.ContainsFunc(b.Facts().Devices, func(d Device) bool { return d.MAC == mac }) {
			t.Fatal("UNKNOWN became positive identity")
		}
		b.Close()
		if _, err := captureSelectedTest(ctx, Selection{SegmentIDs: []string{"Bridge0"}}, m.frames); !slices.Contains(DiagnosticStages(err), "kernel.bindings.neighbor.router-state") {
			t.Fatal("legacy full purpose changed", DiagnosticStages(err))
		}
	}
}

func TestIPv4LANPacketScopeMembershipEpochPreventsTupleABA(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	before := p.PacketFacts()
	events := []message{neighborFrame(9, "192.0.2.20", projectionOtherMAC, 2), neighborFrame(9, "192.0.2.20", projectionClientMAC, 2)}
	for _, event := range events {
		m.transport.push(fenceTestDatagram{raw: frame(event)})
	}
	waitFenceTestDrained(t, m.transport, 2)
	if err := p.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, p.PacketFacts()) {
		t.Fatal("neighbor events mutated A")
	}
	assertFenceFailure(t, b.Current(ctx), "packet.membership.changed")
	fresh, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.Facts().Epoch != b.Facts().Epoch+2 || !reflect.DeepEqual(fresh.Facts().Devices, b.Facts().Devices) {
		t.Fatal("ABA was not distinguished by original epoch")
	}
	if err := fresh.Current(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIPv4LANPacketScopeStopBetweenCapturesRetainsOriginalCleanup(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	cleanup, err := m.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	trigger := m.captures + 1
	m.onCapture = func(n int) {
		if n == trigger {
			if _, err := operationgate.RequestSelfUpdateStop(context.Background(), m.controlRoot, "11111111111141118111111111111111", 7); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := p.Current(ctx); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Fatal("mid-capture Stop missed", err)
	}
	m.onCapture = nil
	fresh, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.RetainedCurrent(fresh); err != nil {
		t.Fatal("Stop discarded physical retained owner", err)
	}
	if err := m.control.CurrentForCleanupOperation(fresh, cleanup); err != nil {
		t.Fatal("separate actual original cleanup participant lost", err)
	}
	if err := m.control.Current(fresh); err == nil {
		t.Fatal("retained comparison manufactured forward operation")
	}
}

func TestIPv4LANPacketScopeMembershipCaptureDriftOnlyInvalidatesB(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	trigger := m.captures + 2
	m.onCapture = func(n int) {
		if n == trigger {
			m.frames[2][0] = neighborFrame(9, "192.0.2.21", projectionClientMAC, 2)
		}
	}
	if _, err := p.ObserveMembership(ctx); err == nil {
		t.Fatal("mixed capture epoch accepted")
	}
	m.onCapture = nil
	if err := p.Current(ctx); err != nil {
		t.Fatal("B drift discarded A", err)
	}
	if err := p.RetainedCurrent(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIPv4LANPacketScopeIntentAndActualStopKeepOnlyOriginalCleanupComparison(t *testing.T) {
	for _, change := range []string{"intent", "stop"} {
		t.Run(change, func(t *testing.T) {
			p, m, ctx := packetTestScope(t)
			old := p.PacketFacts()
			if change == "intent" {
				m.intent.PolicyRevision++
			} else {
				if _, err := operationgate.RequestSelfUpdateStop(context.Background(), m.controlRoot, "11111111111141118111111111111111", 7); err != nil {
					t.Fatal(err)
				}
			}
			if p.Current(ctx) == nil {
				t.Fatal("forward admission survived change")
			}
			fresh, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := p.RetainedCurrent(fresh); err != nil {
				t.Fatal("original retained comparison lost", DiagnosticStages(err))
			}
			if !reflect.DeepEqual(old, p.PacketFacts()) {
				t.Fatal("original facts replaced")
			}
			m.intent = old.Intent
			if p.Current(ctx) == nil {
				t.Fatal("forward owner revived")
			}
		})
	}
}

func TestIPv4LANPacketScopeStructuralDriftIsStickyInBothLanes(t *testing.T) {
	for _, change := range []string{"home", "guest", "owned-link", "owned-address", "identity", "source", "control"} {
		t.Run(change, func(t *testing.T) {
			p, m, ctx := packetTestScope(t)
			in := m.input
			id := m.id
			switch change {
			case "home":
				m.input.native = []byte(strings.Replace(string(in.native), ndmField("security-level", "private"), ndmField("security-level", "protected"), 1))
			case "guest":
				m.input.native = []byte(strings.Replace(string(in.native), ndmField("security-level", "protected"), ndmField("security-level", "public"), 1))
			case "owned-link":
				m.input.links = append(slices.Clone(in.links), linkFrame(12, "Other", "", "02:00:00:00:00:12", 0))
			case "owned-address":
				m.input.addresses = append(slices.Clone(in.addresses), addressFrame(5, "198.51.100.1/24"))
			case "identity":
				m.id.BootID = "12345678-1234-1234-1234-123456789abd"
			case "source":
				m.sourceError = errors.New("original provider unavailable")
			case "control":
				_ = m.control.Close()
			}
			if p.Current(ctx) == nil {
				t.Fatal("drift accepted")
			}
			m.input = in
			m.id = id
			m.sourceError = nil
			if p.Current(ctx) == nil || p.RetainedCurrent(ctx) == nil {
				t.Fatal("original owner revived on restored facts")
			}
		})
	}
}

func TestIPv4LANPacketScopeMalformedMembershipRevokesA(t *testing.T) {
	for _, change := range []string{"missing-family", "duplicate", "bad-state", "own-address", "bad-mac"} {
		t.Run(change, func(t *testing.T) {
			p, m, ctx := packetTestScope(t)
			switch change {
			case "missing-family":
				delete(m.frames, 10)
			case "duplicate":
				m.frames[2] = append(m.frames[2], m.frames[2][0])
			case "bad-state":
				m.frames[2][0] = neighborFrame(9, "192.0.2.20", projectionClientMAC, 3)
			case "own-address":
				m.frames[2][0] = neighborFrame(9, "192.0.2.1", projectionClientMAC, 2)
			case "bad-mac":
				m.frames[2][0] = neighborFrame(9, "192.0.2.20", "ff:ff:ff:ff:ff:ff", 2)
			}
			if _, err := p.ObserveMembership(ctx); err == nil {
				t.Fatal("malformed source accepted")
			}
			m.frames = selectedTestNeighbors()
			if p.Current(ctx) == nil || p.RetainedCurrent(ctx) == nil {
				t.Fatal("malformed original source was refreshed")
			}
		})
	}
}

func TestIPv4LANPacketScopeMembershipConflictDoesNotDiscardA(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	m.frames[2] = append(m.frames[2], neighborFrame(5, "198.51.100.20", projectionClientMAC, 2))
	if _, err := p.ObserveMembership(ctx); err == nil {
		t.Fatal("cross-interface association accepted")
	}
	if err := p.Current(ctx); err != nil {
		t.Fatal("B conflict discarded A", DiagnosticStages(err))
	}
	if err := p.RetainedCurrent(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIPv4LANPacketScopeDetachedCopyCloseAndIntentBounds(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	facts := p.PacketFacts()
	facts.Intent.SegmentIDs[0] = "Other"
	facts.Home.Members[0].IfIndex = 99
	facts.OwnedMACs[0] = "02:00:00:00:00:99"
	facts.Control.Sequence++
	if err := p.Current(ctx); err != nil {
		t.Fatal("detached metadata changed owner", err)
	}
	// Copy private payload without copying a mutex; the original self pointer
	// still refuses the reconstructed object before any resource is touched.
	copy := IPv4LANPacketScope{self: p.self, intent: p.intent, source: p.source, fence: p.fence, facts: p.facts, topology: p.topology}
	if copy.Current(ctx) == nil || copy.RetainedCurrent(ctx) == nil || copy.Close() == nil || copy.PacketFacts().ScopeID != "" {
		t.Fatal("copied owner adopted")
	}
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bc := IPv4LANMembershipReview{self: b.self, parent: b.parent, facts: b.facts}
	if bc.Current(ctx) == nil || bc.Facts().ScopeID != "" {
		t.Fatal("copied membership adopted")
	}
	detached := b.Facts()
	detached.Devices[0].Addresses[0] = "192.0.2.99"
	if err := b.Current(ctx); err != nil {
		t.Fatal("detached B mutated original", err)
	}
	b.Close()
	if b.Current(ctx) == nil {
		t.Fatal("closed B revived")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	waitFenceTest(t, m.reader.done)
	if p.Current(ctx) == nil || p.RetainedCurrent(ctx) == nil || p.Close() != nil || m.opens != 1 {
		t.Fatal("closed A revived/reopened")
	}
	for _, change := range []string{"legacy-id", "multicast", "duplicate", "noncanonical-prefix", "purpose", "multi-home", "bound"} {
		i := cloneIPv4LANPacketIntent(m.intent)
		switch change {
		case "legacy-id":
			i.ExcludedDeviceIDs = []string{"saved-old-id"}
		case "multicast":
			i.ExcludedDeviceIDs = []string{"mac-ff-ff-ff-ff-ff-ff"}
		case "duplicate":
			i.ExcludedDeviceIDs = append(i.ExcludedDeviceIDs, i.ExcludedDeviceIDs[0])
		case "noncanonical-prefix":
			i.ExcludedCIDRs = []string{"198.51.100.1/24"}
		case "purpose":
			i.NewDevices = "exclude"
		case "multi-home":
			i.SegmentIDs = append(i.SegmentIDs, "Bridge1")
		case "bound":
			i.ExcludedCIDRs = make([]string, 257)
		}
		if _, err := validateIPv4LANPacketIntent(i); err == nil {
			t.Fatal(change, "accepted")
		}
	}
	if p.Current(context.Background()) == nil {
		t.Fatal("unbounded operation accepted")
	}
	if _, err := NewReviewedStockNC1812IPv4LANPacketScope(ctx, nil, nil, "", nil); err == nil {
		t.Fatal("detached constructor accepted")
	}
}

func TestIPv4LANPacketScopeOwnOriginFactsAndClosedBounds(t *testing.T) {
	in, frames := scopeOptionsKernelFixture()
	intent := IPv4LANPacketIntent{SegmentIDs: []string{"Bridge0"}}
	// Actual kernel-owned loopback and WAN addresses are structural negative
	// facts, independently of NDM client membership or display candidates.
	lo := linkFrame(1, "lo", "", "00:00:00:00:00:00", 0)
	in.links = append(in.links, lo)
	in.addresses = append(in.addresses, addressFrame(1, "127.0.0.1/8"), addressFrame(1, "::1/128"), addressFrame(5, "198.51.100.1/24"))
	topology, err := packetTopologyFromFacts(in, intent)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"127.0.0.1/8", "::1/128", "198.51.100.1/24"} {
		if !slices.ContainsFunc(topology.addresses, func(a packetOwnedAddress) bool { return a.prefix == prefix }) {
			t.Fatal("own address missing", prefix)
		}
	}
	// Own exact tuple may be bookkeeping, but never a client identity.
	frames[2] = append(frames[2], neighborFrame(9, "192.0.2.1", "02:00:00:00:00:01", 2))
	rows, err := packetBindMembership(context.Background(), topology, frames)
	if err != nil || len(rows) != 3 {
		t.Fatal("own tuple became client", len(rows), err)
	}
	frames[2][len(frames[2])-1] = neighborFrame(5, "192.0.2.1", "02:00:00:00:00:01", 2)
	if _, _, err := packetNeighborBoundary(context.Background(), topology, frames); err == nil {
		t.Fatal("own global address accepted on another interface")
	}
	oversized := neighborFrame(9, "192.0.2.20", projectionClientMAC, 2)
	oversized.data = append(oversized.data, make([]byte, 1<<20)...)
	_, _, err = packetNeighborBoundary(context.Background(), topology, map[byte][]message{2: {oversized}, 10: {}})
	assertFenceFailure(t, err, "kernel.bindings.neighbor.limit")
	in.links = make([]message, 4097)
	_, err = packetTopologyFromFacts(in, intent)
	assertFenceFailure(t, err, "packet.structure.limit")
}

func packetTestNoneLink() message {
	m := linkFrame(12, "modeledNone", "", "", 0)
	binary.NativeEndian.PutUint16(m.data[2:4], 65534)
	return m
}
func packetTestOpaqueNOARP(address string) message {
	m := neighborFrame(12, address, "", 64)
	m.data = append(m.data, attr(2, nil)...)
	return m
}
func packetTestWithOpaque(m *packetTestModel) {
	m.input.links = append(m.input.links, packetTestNoneLink())
	m.frames[10] = append(m.frames[10], packetTestOpaqueNOARP("2001:db8:2::90"))
}

func TestIPv4LANPacketScopeOpaqueForeignNOARPKeepsAddressAndNegatives(t *testing.T) {
	p, m, ctx := packetTestScope(t, packetTestWithOpaque)
	row := m.frames[10][len(m.frames[10])-1]
	n, bookkeeping, err := packetDecodeNeighbor(row, p.topology)
	if err != nil || bookkeeping || n.index != 12 || n.mac != "" || n.address.String() != "2001:db8:2::90" || n.state != 64 || len(p.topology.noneLinks) != 1 {
		t.Fatal("opaque foreign observation was omitted or became an identity")
	}
	assertFenceFailure(t, validateUnicastNeighbor(n), "kernel.bindings.neighbor.mac")
	_, foreign, err := packetNeighborBoundary(ctx, p.topology, m.frames)
	if err != nil || !slices.Contains(foreign, n) {
		t.Fatal("opaque observation lost from foreign boundary")
	}
	facts := p.PacketFacts()
	if !slices.Equal(facts.ExcludedMACs, []string{"02:00:00:00:00:40"}) || !slices.Equal(facts.Intent.ExcludedCIDRs, m.intent.ExcludedCIDRs) || slices.Contains(facts.OwnedMACs, "") {
		t.Fatal("literal negatives changed or a MAC was invented")
	}
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(DiagnosticStages(err))
	}
	defer b.Close()
	if len(b.Facts().Devices) != 3 || slices.ContainsFunc(b.Facts().Devices, func(d Device) bool { return d.IfIndex == 12 || d.MAC == "" }) {
		t.Fatal("opaque observation became a selected client")
	}
	// An opaque global IPv6 observation still conflicts with a Home client's
	// actual association; failure of this B does not discard structural A.
	m.frames[10] = append(m.frames[10], neighborFrame(9, n.address.String(), projectionClientMAC, 2))
	_, err = p.ObserveMembership(ctx)
	assertFenceFailure(t, err, "packet.membership.address-conflict")
	if err := p.Current(ctx); err != nil {
		t.Fatal("opaque B conflict discarded A", DiagnosticStages(err))
	}
}

func TestIPv4LANPacketScopeOpaqueForeignNOARPNarrowAndOwnedGuards(t *testing.T) {
	in, _ := scopeOptionsKernelFixture()
	in.links = append(in.links, packetTestNoneLink())
	topology, err := packetTopologyFromFacts(in, IPv4LANPacketIntent{SegmentIDs: []string{"Bridge0"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"missing-link", "ethernet", "other-type", "loopback", "home", "member", "parent", "known-parent", "master", "link-parent", "foreign-parent", "missing-lladdr", "zero-lladdr", "bad-lladdr", "ipv4", "state", "local-type", "flags", "router", "owned-home-address", "owned-same-address", "message-type"} {
		t.Run(change, func(t *testing.T) {
			top := clonePacketTopology(topology)
			row := packetTestOpaqueNOARP("2001:db8:2::90")
			switch change {
			case "missing-link":
				top.noneLinks = nil
			case "ethernet":
				top.noneLinks[0].LinkType = 1
			case "other-type":
				top.noneLinks[0].LinkType = 512
			case "loopback":
				top.noneLinks[0].LinkType = 772
			case "home":
				binary.NativeEndian.PutUint32(row.data[4:8], uint32(top.home.IfIndex))
			case "member":
				top.home.Members = append(top.home.Members, Link{IfIndex: 12})
			case "parent":
				top.home.Members = append(top.home.Members, Link{IfIndex: 13, ParentIfIndex: 12})
			case "known-parent":
				top.home.Members = append(top.home.Members, Link{IfIndex: 13, Parent: ParentLink{Known: true, IfIndex: 12}})
			case "master":
				top.noneLinks[0].MasterIfIndex = top.home.IfIndex
			case "link-parent":
				top.noneLinks[0].ParentIfIndex = 13
			case "foreign-parent":
				top.noneLinks[0].ForeignParent = true
			case "missing-lladdr":
				row = neighborFrame(12, "2001:db8:2::90", "", 64)
			case "zero-lladdr":
				row = neighborFrame(12, "2001:db8:2::90", "00:00:00:00:00:00", 64)
			case "bad-lladdr":
				row = neighborFrame(12, "2001:db8:2::90", "", 64)
				row.data = append(row.data, attr(2, []byte{1})...)
			case "ipv4":
				row = packetTestOpaqueNOARP("198.51.100.90")
			case "state":
				binary.NativeEndian.PutUint16(row.data[8:10], 4)
			case "local-type":
				row.data[11] = 2
			case "flags":
				row.data[10] = 2
			case "router":
				row.data[10] = 128
			case "owned-home-address":
				row = packetTestOpaqueNOARP("2001:db8::1")
			case "owned-same-address":
				top.addresses = append(top.addresses, packetOwnedAddress{12, "2001:db8:2::90/64"})
			case "message-type":
				row.kind = 30
			}
			if _, _, err := packetDecodeNeighbor(row, top); err == nil {
				t.Fatal("narrow or owned guard accepted drift")
			}
		})
	}
	// Old ordinary unresolved/valid-MAC behavior is independent of this exception.
	for _, row := range []message{neighborFrame(12, "2001:db8:2::90", "", 1), neighborFrame(12, "2001:db8:2::90", "", 32), neighborFrame(12, "2001:db8:2::90", projectionClientMAC, 64)} {
		n, err := parseKernelNeighbor(row)
		if err != nil || packetOpaqueForeignNOARP(row, n, topology) {
			t.Fatal("ordinary row mistaken for the opaque exception")
		}
		if _, _, err := packetDecodeNeighbor(row, topology); err != nil {
			t.Fatal("ordinary grammar changed")
		}
	}
	row := packetTestOpaqueNOARP("2001:db8:2::90")
	_, _, err = packetNeighborBoundary(context.Background(), topology, map[byte][]message{2: {}, 10: {row, row}})
	assertFenceFailure(t, err, "kernel.bindings.neighbor.duplicate")
	// A global RTN_LOCAL near miss remains outside the link-local exception.
	local := neighborFrame(1, "2001:db8:2::91", "00:00:00:00:00:00", 64)
	local.data[11] = 2
	_, _, err = packetDecodeNeighbor(local, topology)
	assertFenceFailure(t, err, "kernel.bindings.neighbor.type")
}

func TestIPv4LANPacketScopeOpaqueForeignNOARPEpochAndStickyLink(t *testing.T) {
	p, m, ctx := packetTestScope(t, packetTestWithOpaque)
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	m.transport.push(fenceTestDatagram{raw: frame(packetTestOpaqueNOARP("2001:db8:2::91"))})
	waitFenceTestDrained(t, m.transport, 1)
	if err := p.Current(ctx); err != nil {
		t.Fatal(err)
	}
	assertFenceFailure(t, b.Current(ctx), "packet.membership.changed")
	fresh, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.Facts().Epoch != b.Facts().Epoch+1 || !reflect.DeepEqual(fresh.Facts().Devices, b.Facts().Devices) {
		t.Fatal("opaque event did not revoke only old B")
	}
	// Original ifindex must remain protected even after a type change with no MAC.
	event := packetTestNoneLink()
	binary.NativeEndian.PutUint16(event.data[2:4], 772)
	m.transport.push(fenceTestDatagram{raw: frame(event)})
	waitFenceTest(t, m.reader.done)
	assertFenceFailure(t, p.Current(ctx), "packet.notifications.owned-link")
	if p.RetainedCurrent(ctx) == nil {
		t.Fatal("original NONE link drift was accepted")
	}
}

func TestIPv4LANPacketScopeOpaqueForeignNOARPCaptureDriftIsSticky(t *testing.T) {
	p, m, ctx := packetTestScope(t, packetTestWithOpaque)
	original := m.input.links[len(m.input.links)-1]
	changed := packetTestNoneLink()
	binary.NativeEndian.PutUint32(changed.data[8:12], 0)
	m.input.links[len(m.input.links)-1] = changed
	if p.Current(ctx) == nil {
		t.Fatal("private NONE structural facts were not compared")
	}
	m.input.links[len(m.input.links)-1] = original
	if p.Current(ctx) == nil || p.RetainedCurrent(ctx) == nil {
		t.Fatal("restoring NONE link revived original A")
	}
}

func packetTestLoopbackLink() message {
	m := linkFrame(1, "lo", "", "00:00:00:00:00:00", 0)
	binary.NativeEndian.PutUint16(m.data[2:4], 772)
	binary.NativeEndian.PutUint32(m.data[8:12], 65609)
	return m
}
func packetTestOpaqueLoopback(address string) message {
	m := neighborFrame(1, address, "00:00:00:00:00:00", 64)
	m.data[11] = 2
	m.data = append(m.data, attr(3, make([]byte, 16))...)
	m.data = append(m.data, attr(4, integer(0))...)
	return m
}
func packetTestWithLoopback(m *packetTestModel) {
	m.input.links = append(m.input.links, packetTestLoopbackLink())
	m.frames[10] = append(m.frames[10], packetTestOpaqueLoopback("fe80::90"))
}

func TestIPv4LANPacketScopeOpaqueLoopbackRetainsScopedAddressAndConflicts(t *testing.T) {
	p, m, ctx := packetTestScope(t, packetTestWithLoopback)
	row := m.frames[10][len(m.frames[10])-1]
	n, bookkeeping, err := packetDecodeNeighbor(row, p.topology)
	if err != nil || bookkeeping || n.mac != "" || n.index != 1 || n.address.String() != "fe80::90" || len(p.topology.loopbackLinks) != 1 {
		t.Fatal("loopback observation became bookkeeping/identity or lost its address/index")
	}
	if _, legacy, err := decodeForeignKernelNeighbor(row, p.topology.boundarySegments()); err != nil || legacy {
		t.Fatal("shared loopback alias grammar changed")
	}
	raw, err := parseKernelNeighbor(row)
	if err != nil {
		t.Fatal(err)
	}
	assertFenceFailure(t, validateUnicastNeighbor(raw), "kernel.bindings.neighbor.type")
	_, foreign, err := packetNeighborBoundary(ctx, p.topology, m.frames)
	if err != nil || !slices.Contains(foreign, n) {
		t.Fatal("opaque loopback address omitted")
	}
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(b.Facts().Devices) != 3 || slices.ContainsFunc(b.Facts().Devices, func(d Device) bool { return d.IfIndex == 1 || d.MAC == "" }) {
		t.Fatal("loopback became a selected client")
	}
	// Link-local equality on another interface is a different scoped address.
	m.frames[10] = append(m.frames[10], neighborFrame(9, "fe80::90", projectionClientMAC, 2))
	if _, err := packetBindMembership(ctx, p.topology, m.frames); err != nil {
		t.Fatal("link-local ifindex was discarded")
	}
	// Same original ifindex/address now collides with actual owned address facts.
	top := clonePacketTopology(p.topology)
	top.addresses = append(top.addresses, packetOwnedAddress{1, "fe80::90/64"})
	_, _, err = packetDecodeNeighbor(row, top)
	assertFenceFailure(t, err, "packet.owned.neighbor.conflict")
	_, err = packetBindMembership(ctx, top, m.frames)
	assertFenceFailure(t, err, "packet.owned.neighbor.conflict")
	m.frames[2] = append(m.frames[2], neighborFrame(5, "198.51.100.20", projectionClientMAC, 2))
	_, err = packetBindMembership(ctx, p.topology, m.frames)
	assertFenceFailure(t, err, "packet.membership.foreign")
	facts := p.PacketFacts()
	if slices.Contains(facts.OwnedAddresses, "fe80::90") || !slices.Equal(facts.ExcludedMACs, []string{"02:00:00:00:00:40"}) || !slices.Equal(facts.Intent.ExcludedCIDRs, m.intent.ExcludedCIDRs) {
		t.Fatal("opaque address promoted or literal negatives changed")
	}
}

func TestIPv4LANPacketScopeOpaqueLoopbackRejectsSpoofAndNearMiss(t *testing.T) {
	in, _ := scopeOptionsKernelFixture()
	in.links = append(in.links, packetTestLoopbackLink())
	topology, err := packetTopologyFromFacts(in, IPv4LANPacketIntent{SegmentIDs: []string{"Bridge0"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"missing-link", "ethernet", "no-loopback-flag", "master", "parent", "foreign-parent", "index", "home", "member", "member-parent", "known-parent", "global", "multicast", "loopback-address", "ipv4", "state", "kind", "flags", "router", "nonzero-lladdr", "empty-lladdr", "extra-attr", "missing-probes", "attr-flags", "message-kind"} {
		t.Run(change, func(t *testing.T) {
			top := clonePacketTopology(topology)
			row := packetTestOpaqueLoopback("fe80::90")
			switch change {
			case "missing-link":
				top.loopbackLinks = nil
			case "ethernet":
				top.loopbackLinks[0].LinkType = 1
			case "no-loopback-flag":
				top.loopbackLinks[0].Flags &^= 8
			case "master":
				top.loopbackLinks[0].MasterIfIndex = 9
			case "parent":
				top.loopbackLinks[0].ParentIfIndex = 5
			case "foreign-parent":
				top.loopbackLinks[0].ForeignParent = true
			case "index":
				binary.NativeEndian.PutUint32(row.data[4:8], 5)
			case "home":
				binary.NativeEndian.PutUint32(row.data[4:8], 9)
			case "member":
				top.home.Members = append(top.home.Members, Link{IfIndex: 1})
			case "member-parent":
				top.home.Members = append(top.home.Members, Link{IfIndex: 13, ParentIfIndex: 1})
			case "known-parent":
				top.home.Members = append(top.home.Members, Link{IfIndex: 13, Parent: ParentLink{Known: true, IfIndex: 1}})
			case "global":
				row = packetTestOpaqueLoopback("2001:db8:2::90")
			case "multicast":
				row = packetTestOpaqueLoopback("ff02::90")
			case "loopback-address":
				row = packetTestOpaqueLoopback("::1")
			case "ipv4":
				row = packetTestOpaqueLoopback("198.51.100.90")
			case "state":
				binary.NativeEndian.PutUint16(row.data[8:10], 4)
			case "kind":
				row.data[11] = 1
			case "flags":
				row.data[10] = 2
			case "router":
				row.data[10] = 128
			case "nonzero-lladdr":
				row = neighborFrame(1, "fe80::90", projectionClientMAC, 64)
				row.data[11] = 2
				row.data = append(row.data, attr(3, make([]byte, 16))...)
				row.data = append(row.data, attr(4, integer(0))...)
			case "empty-lladdr":
				row = neighborFrame(1, "fe80::90", "", 64)
				row.data[11] = 2
				row.data = append(row.data, attr(2, nil)...)
				row.data = append(row.data, attr(3, make([]byte, 16))...)
				row.data = append(row.data, attr(4, integer(0))...)
			case "extra-attr":
				row.data = append(row.data, attr(5, integer(0))...)
			case "missing-probes":
				row.data = row.data[:len(row.data)-8]
			case "attr-flags":
				binary.NativeEndian.PutUint16(row.data[14:16], 0x8001)
			case "message-kind":
				row.kind = 30
			}
			if _, _, err := packetDecodeNeighbor(row, top); err == nil {
				t.Fatal("spoof/near miss accepted")
			}
		})
	}
	row := packetTestOpaqueLoopback("fe80::90")
	_, _, err = packetNeighborBoundary(context.Background(), topology, map[byte][]message{2: {}, 10: {row, row}})
	assertFenceFailure(t, err, "kernel.bindings.neighbor.duplicate")
}

func TestIPv4LANPacketScopeOpaqueLoopbackEpochAndStickyDrift(t *testing.T) {
	for _, change := range []string{"capture", "link-event", "shape-event"} {
		t.Run(change, func(t *testing.T) {
			p, m, ctx := packetTestScope(t, packetTestWithLoopback)
			b, err := p.ObserveMembership(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			m.transport.push(fenceTestDatagram{raw: frame(packetTestOpaqueLoopback("fe80::91"))})
			waitFenceTestDrained(t, m.transport, 1)
			if err := p.Current(ctx); err != nil {
				t.Fatal(err)
			}
			assertFenceFailure(t, b.Current(ctx), "packet.membership.changed")
			original := m.input.links[len(m.input.links)-1]
			if change == "capture" {
				changed := packetTestLoopbackLink()
				binary.NativeEndian.PutUint32(changed.data[8:12], 9)
				m.input.links[len(m.input.links)-1] = changed
			} else {
				event := packetTestLoopbackLink()
				if change == "link-event" {
					binary.NativeEndian.PutUint16(event.data[2:4], 512)
				} else {
					event = packetTestOpaqueLoopback("2001:db8:2::90")
				}
				m.transport.push(fenceTestDatagram{raw: frame(event)})
				waitFenceTest(t, m.reader.done)
			}
			if p.Current(ctx) == nil {
				t.Fatal("loopback drift accepted")
			}
			m.input.links[len(m.input.links)-1] = original
			if p.Current(ctx) == nil || p.RetainedCurrent(ctx) == nil {
				t.Fatal("original A revived after loopback drift")
			}
		})
	}
}
