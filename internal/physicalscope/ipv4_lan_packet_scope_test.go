package physicalscope

import (
	"context"
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
func packetTestScope(t *testing.T) (*IPv4LANPacketScope, *packetTestModel, context.Context) {
	t.Helper()
	in, frames := scopeOptionsKernelFixture()
	in.native = append(in.native, []byte(ndmObject("Guest", "Bridge1", "Guest", "Bridge")+ndmField("security-level", "protected"))...)
	m := &packetTestModel{input: in, frames: frames, intent: IPv4LANPacketIntent{Revision: 7, PolicyRevision: 3, Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{"Bridge0"}, ExcludedDeviceIDs: []string{physicalDeviceID("02:00:00:00:00:40")}, ExcludedCIDRs: []string{"198.51.100.0/24", "2001:db8:1::/64"}}, id: netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: "12345678-1234-1234-1234-123456789abc", PlatformReviewSHA256: "f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733"}, transport: newFenceTestTransport(), controlRoot: filepath.Join(t.TempDir(), "control")}
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
