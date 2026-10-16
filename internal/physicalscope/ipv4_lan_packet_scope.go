package physicalscope

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// IPv4LANPacketIntent is user intent, not a current device/IP observation.
// Canonical MAC-shaped IDs are literal negative selectors, including offline
// devices. An unrepresentable legacy ID refuses this purpose; it is not dropped.
type IPv4LANPacketIntent struct {
	Revision, PolicyRevision uint64
	Mode, NewDevices         string
	SegmentIDs               []string
	ExcludedDeviceIDs        []string
	ExcludedCIDRs            []string
}

type IPv4LANPacketIntentReader func(context.Context) (IPv4LANPacketIntent, error)

// Detached comparison metadata only. A caller needs the SAME live scope and
// its separately bound App/Manager owner; these facts grant no effect/cleanup.
// This purpose covers IPv4 TCP selected-home packets and owned infrastructure,
// not an exhaustive negative MAC classification of arbitrary IPv6 peers.
type IPv4LANPacketFacts struct {
	ScopeID        string
	Identity       netidentity.Identity
	Control        operationgate.ControlEpochReference
	Intent         IPv4LANPacketIntent
	Home           Segment
	IPv4Prefixes   []string
	OwnedMACs      []string
	OwnedAddresses []string
	ExcludedMACs   []string
}

type IPv4LANMembershipFacts struct {
	ScopeID    string
	Epoch      uint64
	Digest     string
	ObservedAt time.Time
	Devices    []Device // Actually observed IPv4 associations, not full coverage.
}

type packetOwnedAddress struct {
	index  int
	prefix string
}
type ipv4LANPacketTopology struct {
	home          Segment
	native        []nativeSegment
	links         []Link
	noneLinks     []Link // Private original ARPHRD_NONE facts, not positive L2 identities.
	loopbackLinks []Link // Private original loopback facts for scoped opaque observations.
	addresses     []packetOwnedAddress
}
type ipv4LANPacketCapture struct {
	topology ipv4LANPacketTopology
	frames   map[byte][]message
}
type ipv4LANPacketFence interface {
	check(context.Context, ipv4LANPacketTopology) (uint64, error)
	// seed records the membership class of neighbor rows from an original
	// dump for rows the collector has not seen yet. It never moves the epoch.
	seed(context.Context, map[string]string) error
	close() error
}
type ipv4LANPacketSource struct {
	current func(context.Context, func(context.Context, netidentity.Identity) error) error
	control func(context.Context, bool) error
	open    func(context.Context) (ipv4LANPacketFence, error)
	capture func(context.Context, IPv4LANPacketIntent) (ipv4LANPacketCapture, error)
	ref     operationgate.ControlEpochReference
}

// IPv4LANPacketScope retains one original provider/control/fence lifetime.
// Ordinary membership has a separate epoch and cannot mutate structural A.
type IPv4LANPacketScope struct {
	self        *IPv4LANPacketScope
	mu          sync.Mutex
	intent      IPv4LANPacketIntentReader
	source      ipv4LANPacketSource
	fence       ipv4LANPacketFence
	facts       IPv4LANPacketFacts
	topology    ipv4LANPacketTopology
	forwardBad  bool
	physicalBad bool
	closed      bool
	closeErr    error
}

func (*IPv4LANPacketScope) String() string   { return "[private original IPv4 LAN packet scope]" }
func (*IPv4LANPacketScope) GoString() string { return "[private original IPv4 LAN packet scope]" }

func NewReviewedStockNC1812IPv4LANPacketScope(ctx context.Context, provider *netidentity.Provider, control *operationgate.ControlEpochReview, controlRoot string, intent IPv4LANPacketIntentReader) (*IPv4LANPacketScope, error) {
	if provider == nil || control == nil || !control.MatchesControlRoot(controlRoot) || intent == nil {
		return nil, at("packet.dependencies", nil)
	}
	return newIPv4LANPacketScope(ctx, intent, reviewedIPv4LANPacketSource(provider, control, controlRoot))
}

// Only this private test seam can model I/O. Production uses the concrete
// original provider/control/kernelFence factory, never caller fact callbacks.
func newIPv4LANPacketScope(ctx context.Context, intent IPv4LANPacketIntentReader, source ipv4LANPacketSource) (*IPv4LANPacketScope, error) {
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if intent == nil || source.current == nil || source.control == nil || source.open == nil || source.capture == nil {
		return nil, at("packet.dependencies", nil)
	}
	p := &IPv4LANPacketScope{intent: intent, source: source}
	p.self = p
	keep := false
	defer func() {
		if !keep {
			_ = p.Close()
		}
	}()
	if err := source.control(c, false); err != nil {
		return nil, boundary("packet.control.initial", err)
	}
	i, err := intent(c)
	if err != nil {
		return nil, boundary("packet.intent.initial", err)
	}
	macs, err := validateIPv4LANPacketIntent(i)
	if err != nil {
		return nil, err
	}
	p.facts.Intent, p.facts.Control, p.facts.ExcludedMACs = cloneIPv4LANPacketIntent(i), source.ref, macs
	err = source.current(c, func(held context.Context, id netidentity.Identity) error {
		if id.Validate() != nil || id.Kind != netidentity.ReviewedSingleInitNet {
			return at("packet.identity.kind", nil)
		}
		p.facts.Identity = id
		var e error
		p.fence, e = source.open(held)
		return e
	})
	if err != nil || p.fence == nil {
		return nil, boundary("packet.fence.open", errOrUnknown(err))
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	p.facts.ScopeID = hex.EncodeToString(nonce[:])
	topology, err := p.capture(c, i, nil, false)
	if err != nil {
		return nil, err
	}
	p.topology = topology
	p.facts.Home = clonePacketSegments([]Segment{topology.home})[0]
	for _, raw := range topology.home.Prefixes {
		prefix, _ := netip.ParsePrefix(raw)
		if prefix.Addr().Is4() {
			p.facts.IPv4Prefixes = append(p.facts.IPv4Prefixes, raw)
		}
	}
	if len(p.facts.IPv4Prefixes) == 0 {
		return nil, at("packet.home.ipv4-missing", nil)
	}
	for _, l := range topology.links {
		p.facts.OwnedMACs = append(p.facts.OwnedMACs, l.MAC)
	}
	slices.Sort(p.facts.OwnedMACs)
	p.facts.OwnedMACs = slices.Compact(p.facts.OwnedMACs)
	for _, a := range topology.addresses {
		prefix, _ := netip.ParsePrefix(a.prefix)
		p.facts.OwnedAddresses = append(p.facts.OwnedAddresses, prefix.Addr().String())
	}
	slices.Sort(p.facts.OwnedAddresses)
	p.facts.OwnedAddresses = slices.Compact(p.facts.OwnedAddresses)
	if err := p.checkIntent(c); err != nil {
		return nil, err
	}
	if err := source.control(c, false); err != nil {
		return nil, boundary("packet.control.closing", err)
	}
	keep = true
	return p, nil
}

func validateIPv4LANPacketIntent(i IPv4LANPacketIntent) ([]string, error) {
	if i.Mode != "lan_except" || i.NewDevices != "inherit" || len(i.SegmentIDs) != 1 || len(i.ExcludedDeviceIDs) > 256 || len(i.ExcludedCIDRs) > 256 {
		return nil, at("packet.intent.purpose", nil)
	}
	if _, err := canonicalSelection(Selection{Revision: i.Revision, PolicyRevision: i.PolicyRevision, SegmentIDs: i.SegmentIDs}); err != nil {
		return nil, at("packet.intent.segment", err)
	}
	macs := []string{}
	seen := map[string]bool{}
	for _, id := range i.ExcludedDeviceIDs {
		mac := strings.ReplaceAll(strings.TrimPrefix(id, "mac-"), "-", ":")
		if !validMAC(mac) || physicalDeviceID(mac) != id || strings.ToLower(mac) != mac || seen[id] {
			return nil, at("packet.intent.exclusion-unmappable", nil)
		}
		seen[id] = true
		macs = append(macs, mac)
	}
	seen = map[string]bool{}
	for _, raw := range i.ExcludedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix.String() != raw || seen[raw] {
			return nil, at("packet.intent.excluded-prefix", err)
		}
		seen[raw] = true
	}
	slices.Sort(macs)
	return macs, nil
}
func cloneIPv4LANPacketIntent(i IPv4LANPacketIntent) IPv4LANPacketIntent {
	i.SegmentIDs = slices.Clone(i.SegmentIDs)
	i.ExcludedDeviceIDs = slices.Clone(i.ExcludedDeviceIDs)
	i.ExcludedCIDRs = slices.Clone(i.ExcludedCIDRs)
	return i
}
func clonePacketSegments(s []Segment) []Segment { return cloneSnapshot(Snapshot{Segments: s}).Segments }
func clonePacketTopology(t ipv4LANPacketTopology) ipv4LANPacketTopology {
	t.home = clonePacketSegments([]Segment{t.home})[0]
	t.links = slices.Clone(t.links)
	t.noneLinks = slices.Clone(t.noneLinks)
	t.loopbackLinks = slices.Clone(t.loopbackLinks)
	t.addresses = slices.Clone(t.addresses)
	t.native = slices.Clone(t.native)
	for i := range t.native {
		t.native[i].members = slices.Clone(t.native[i].members)
		t.native[i].prefixes = slices.Clone(t.native[i].prefixes)
		t.native[i].fields = nil
	}
	return t
}

func (p *IPv4LANPacketScope) PacketFacts() IPv4LANPacketFacts {
	if p == nil || p.self != p {
		return IPv4LANPacketFacts{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.facts
	r.Intent = cloneIPv4LANPacketIntent(r.Intent)
	r.Home = clonePacketSegments([]Segment{r.Home})[0]
	r.IPv4Prefixes = slices.Clone(r.IPv4Prefixes)
	r.OwnedMACs = slices.Clone(r.OwnedMACs)
	r.OwnedAddresses = slices.Clone(r.OwnedAddresses)
	r.ExcludedMACs = slices.Clone(r.ExcludedMACs)
	return r
}
func (p *IPv4LANPacketScope) checkIntent(ctx context.Context) error {
	i, err := p.intent(ctx)
	if err != nil || !reflect.DeepEqual(i, p.facts.Intent) {
		p.forwardBad = true
		return boundary("packet.intent.changed", errOrUnknown(err))
	}
	return nil
}
func (p *IPv4LANPacketScope) control(ctx context.Context, retained bool) error {
	if err := p.source.control(ctx, retained); err != nil {
		p.forwardBad = true
		if !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
			p.physicalBad = true
		}
		return boundary("packet.control.changed", err)
	}
	return nil
}
func (p *IPv4LANPacketScope) ready(retained bool) bool {
	return p != nil && p.self == p && p.fence != nil && !p.closed && !p.physicalBad && (retained || !p.forwardBad)
}

// Current is a physical/current-intent check, not executable policy admission.
func (p *IPv4LANPacketScope) Current(ctx context.Context) error { return p.current(ctx, false) }

// RetainedCurrent preserves the original structural/control identity without
// consulting fresh Store/intent or ordinary membership. Exact old artifacts
// and a pre-issued cleanup operation remain mandatory at the actual owner.
func (p *IPv4LANPacketScope) RetainedCurrent(ctx context.Context) error { return p.current(ctx, true) }
func (p *IPv4LANPacketScope) current(ctx context.Context, retained bool) error {
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if p == nil || p.self != p {
		return at("packet.owner", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready(retained) {
		return at("packet.unavailable", nil)
	}
	if err := p.control(c, retained); err != nil {
		return err
	}
	if !retained {
		if err := p.checkIntent(c); err != nil {
			return err
		}
	}
	if _, err := p.capture(c, p.facts.Intent, &p.topology, retained); err != nil {
		if !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
			p.physicalBad = true
		}
		p.forwardBad = true
		return err
	}
	if !retained {
		if err := p.checkIntent(c); err != nil {
			return err
		}
	}
	return p.control(c, retained)
}

func (p *IPv4LANPacketScope) capture(ctx context.Context, intent IPv4LANPacketIntent, baseline *ipv4LANPacketTopology, retained bool) (ipv4LANPacketTopology, error) {
	var result ipv4LANPacketTopology
	for pass := 0; pass < 2; pass++ {
		original := baseline
		if original == nil && pass == 1 {
			original = &result
		}
		err := p.source.current(ctx, func(c context.Context, id netidentity.Identity) error {
			if id != p.facts.Identity || id.Validate() != nil {
				return at("packet.identity.changed", nil)
			}
			if original != nil {
				if _, err := p.fence.check(c, *original); err != nil {
					return err
				}
			}
			read, err := p.source.capture(c, intent)
			if err != nil {
				return err
			}
			home, foreign, err := packetNeighborBoundary(c, read.topology, read.frames)
			if err != nil {
				return err
			}
			if original != nil && !reflect.DeepEqual(*original, read.topology) {
				return at("packet.structure.changed", nil)
			}
			if pass == 0 {
				result = clonePacketTopology(read.topology)
			}
			if original == nil {
				original = &result
			}
			if _, err = p.fence.check(c, *original); err != nil {
				return err
			}
			// The first bound check above drained every queued event, so a row
			// the collector still has not seen is exactly as dumped.
			return p.fence.seed(c, packetMembershipClasses(home, foreign))
		})
		if err != nil {
			return ipv4LANPacketTopology{}, boundary("packet.capture", err)
		}
		if err := p.control(ctx, retained); err != nil {
			return ipv4LANPacketTopology{}, err
		}
	}
	return result, nil
}

func (p *IPv4LANPacketScope) Close() error {
	if p == nil {
		return nil
	}
	if p.self != p {
		return at("packet.owner", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		if p.fence != nil {
			p.closeErr = p.fence.close()
		}
	}
	return p.closeErr
}

// IPv4LANMembershipReview binds observed IPv4/MAC/iif associations to this
// SAME original A and event epoch. It is not exhaustive LAN coverage or an
// executable DNS/flow grant; those owners must separately bind and recheck it.
type IPv4LANMembershipReview struct {
	self            *IPv4LANMembershipReview
	mu              sync.Mutex
	parent          *IPv4LANPacketScope
	facts           IPv4LANMembershipFacts
	invalid, closed bool
}

func (*IPv4LANMembershipReview) String() string   { return "[private IPv4 LAN membership epoch]" }
func (*IPv4LANMembershipReview) GoString() string { return "[private IPv4 LAN membership epoch]" }
func (b *IPv4LANMembershipReview) Facts() IPv4LANMembershipFacts {
	if b == nil || b.self != b {
		return IPv4LANMembershipFacts{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.facts
	r.Devices = cloneSnapshot(Snapshot{Devices: r.Devices}).Devices
	return r
}
func (b *IPv4LANMembershipReview) Close() {
	if b != nil && b.self == b {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
	}
}
func (b *IPv4LANMembershipReview) Current(ctx context.Context) error {
	if b == nil || b.self != b || b.parent == nil {
		return at("packet.membership.owner", nil)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.invalid {
		return at("packet.membership.unavailable", nil)
	}
	r, err := b.parent.ObserveMembership(ctx)
	if err != nil {
		b.invalid = true
		return err
	}
	defer r.Close()
	if r.facts.Epoch != b.facts.Epoch || r.facts.Digest != b.facts.Digest {
		b.invalid = true
		return at("packet.membership.changed", nil)
	}
	return nil
}
func (p *IPv4LANPacketScope) ObserveMembership(ctx context.Context) (*IPv4LANMembershipReview, error) {
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if p == nil || p.self != p {
		return nil, at("packet.owner", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready(false) {
		return nil, at("packet.unavailable", nil)
	}
	if err := p.control(c, false); err != nil {
		return nil, err
	}
	if err := p.checkIntent(c); err != nil {
		return nil, err
	}
	opening, err := p.fence.check(c, p.topology)
	if err != nil {
		p.physicalBad = true
		return nil, err
	}
	var members []Device
	for pass := 0; pass < 2; pass++ {
		var callbackErr error
		invoked := false
		err = p.source.current(c, func(held context.Context, id netidentity.Identity) error {
			invoked = true
			if id != p.facts.Identity {
				p.physicalBad = true
				return at("packet.identity.changed", nil)
			}
			read, e := p.source.capture(held, p.facts.Intent)
			if e != nil {
				p.physicalBad = true
				return e
			}
			if !reflect.DeepEqual(read.topology, p.topology) {
				p.physicalBad = true
				return at("packet.structure.changed", nil)
			}
			// Malformed/lost source observations revoke A. Association conflicts
			// in the separately decoded membership below revoke only this B.
			home, foreign, e := packetNeighborBoundary(held, read.topology, read.frames)
			if e != nil {
				p.physicalBad = true
				return e
			}
			if e := p.fence.seed(held, packetMembershipClasses(home, foreign)); e != nil {
				p.physicalBad = true
				return e
			}
			rows, e := packetBindMembership(held, read.topology, read.frames)
			if e != nil {
				callbackErr = e
				return e
			}
			if pass == 0 {
				members = rows
			} else if !reflect.DeepEqual(members, rows) {
				callbackErr = at("packet.membership.capture.changed", nil)
				return callbackErr
			}
			closing, e := p.fence.check(held, p.topology)
			if e != nil {
				p.physicalBad = true
				return e
			}
			if closing != opening {
				callbackErr = at("packet.membership.epoch.changed", nil)
				return callbackErr
			}
			return nil
		})
		if err != nil {
			if !invoked || callbackErr == nil || err != callbackErr {
				p.physicalBad = true
			}
			return nil, err
		}
		if err := p.control(c, false); err != nil {
			return nil, err
		}
	}
	if err := p.checkIntent(c); err != nil {
		return nil, err
	}
	closing, err := p.fence.check(c, p.topology)
	if err != nil {
		p.physicalBad = true
		return nil, err
	}
	if closing != opening {
		return nil, at("packet.membership.epoch.changed", nil)
	}
	if err := p.control(c, false); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(struct {
		ScopeID string
		Epoch   uint64
		Devices []Device
	}{p.facts.ScopeID, opening, members})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	b := &IPv4LANMembershipReview{parent: p, facts: IPv4LANMembershipFacts{ScopeID: p.facts.ScopeID, Epoch: opening, Digest: hex.EncodeToString(digest[:]), ObservedAt: time.Now().UTC(), Devices: members}}
	b.self = b
	return b, nil
}

func packetTopologyFromFacts(in scopeOptionsInput, intent IPv4LANPacketIntent) (ipv4LANPacketTopology, error) {
	var t ipv4LANPacketTopology
	if len(in.links) > 4096 || len(in.addresses) > 4096 || len(in.routes) > 4096 {
		return t, at("packet.structure.limit", nil)
	}
	total := len(in.native)
	for _, rows := range [][]message{in.links, in.addresses, in.routes} {
		for _, m := range rows {
			total += len(m.data)
			if total > 4<<20 {
				return t, at("packet.structure.limit", nil)
			}
		}
	}
	native, err := parseNDM(in.native)
	if err != nil {
		return t, err
	}
	if len(native) > 4096 {
		return t, at("packet.structure.limit", nil)
	}
	segments, err := assembleSegments(Selection{Revision: intent.Revision, PolicyRevision: intent.PolicyRevision, SegmentIDs: slices.Clone(intent.SegmentIDs)}, native, true, in.links, in.addresses, in.routes)
	if err != nil || len(segments) != 1 || !segments[0].Home || segments[0].Guest {
		return t, at("packet.home", errOrUnknown(err))
	}
	t.home = segments[0]
	for _, n := range native {
		n.fields = nil
		n.members = slices.Clone(n.members)
		n.prefixes = slices.Clone(n.prefixes)
		t.native = append(t.native, n)
	}
	slices.SortFunc(t.native, func(a, b nativeSegment) int { return strings.Compare(a.id, b.id) })
	indexes := map[int]bool{}
	for _, m := range in.links {
		l, e := decodeLink(m)
		if e != nil {
			return t, e
		}
		indexes[l.IfIndex] = true
		if validMAC(l.MAC) {
			t.links = append(t.links, l.Link)
		}
		if l.LinkType == 65534 {
			t.noneLinks = append(t.noneLinks, l.Link)
		}
		if l.LinkType == 772 {
			t.loopbackLinks = append(t.loopbackLinks, l.Link)
		}
	}
	slices.SortFunc(t.links, func(a, b Link) int { return a.IfIndex - b.IfIndex })
	slices.SortFunc(t.noneLinks, func(a, b Link) int { return a.IfIndex - b.IfIndex })
	slices.SortFunc(t.loopbackLinks, func(a, b Link) int { return a.IfIndex - b.IfIndex })
	for _, m := range in.addresses {
		a, e := packetDecodeOwnedAddress(m)
		if e != nil || !indexes[a.index] {
			return t, at("packet.owned.address", errOrUnknown(e))
		}
		prefix, _ := netip.ParsePrefix(a.prefix)
		if prefix.Addr().Is4() && a.index != t.home.IfIndex {
			for _, own := range t.home.Prefixes {
				p, _ := netip.ParsePrefix(own)
				if p.Addr().Is4() && p.Overlaps(prefix.Masked()) {
					return t, at("packet.foreign.prefix.overlap", nil)
				}
			}
		}
		t.addresses = append(t.addresses, a)
	}
	slices.SortFunc(t.addresses, func(a, b packetOwnedAddress) int {
		if a.index != b.index {
			return a.index - b.index
		}
		return strings.Compare(a.prefix, b.prefix)
	})
	for i := 1; i < len(t.addresses); i++ {
		if t.addresses[i] == t.addresses[i-1] {
			return t, at("packet.owned.address.duplicate", nil)
		}
	}
	return t, nil
}
func packetDecodeOwnedAddress(m message) (packetOwnedAddress, error) {
	if len(m.data) < 8 || m.data[0] != 2 && m.data[0] != 10 {
		return packetOwnedAddress{}, ErrUnknown
	}
	a, err := attrs(m.data[8:])
	if err != nil {
		return packetOwnedAddress{}, err
	}
	flags := uint32(m.data[2])
	if a[8] != nil {
		flags, err = u32(a, 8)
		if err != nil {
			return packetOwnedAddress{}, err
		}
	}
	if flags&(8|64) != 0 {
		return packetOwnedAddress{}, ErrUnknown
	}
	raw := a[2]
	if raw == nil {
		raw = a[1]
	}
	if a[1] != nil && a[2] != nil && !bytes.Equal(a[1], a[2]) {
		return packetOwnedAddress{}, ErrUnknown
	}
	ip, ok := netip.AddrFromSlice(raw)
	bits := int(m.data[1])
	index := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	if !ok || ip.Is4In6() || ip.Is4() != (m.data[0] == 2) || ip.IsUnspecified() || ip.IsMulticast() || bits <= 0 || bits > ip.BitLen() || index <= 0 {
		return packetOwnedAddress{}, ErrUnknown
	}
	return packetOwnedAddress{index: index, prefix: netip.PrefixFrom(ip, bits).String()}, nil
}
func (t ipv4LANPacketTopology) boundarySegments() []Segment {
	r := clonePacketSegments([]Segment{t.home})
	for _, l := range t.links {
		if l.IfIndex == t.home.IfIndex {
			continue
		}
		s := Segment{Interface: l.Interface, IfIndex: l.IfIndex, MAC: l.MAC, Members: []Link{l}}
		for _, a := range t.addresses {
			if a.index == l.IfIndex {
				s.LinkAddresses = append(s.LinkAddresses, a.prefix)
				p, _ := netip.ParsePrefix(a.prefix)
				s.Prefixes = append(s.Prefixes, p.Masked().String())
			}
		}
		r = append(r, s)
	}
	return r
}
func packetDecodeNeighbor(m message, t ipv4LANPacketTopology) (kernelNeighbor, bool, error) {
	if len(m.data) < 12 {
		return kernelNeighbor{}, false, at("kernel.bindings.neighbor.header", nil)
	}
	var n kernelNeighbor
	var bookkeeping bool
	var err error
	if int(int32(binary.NativeEndian.Uint32(m.data[4:8]))) == t.home.IfIndex {
		n, bookkeeping, err = decodeSegmentNeighbor(m, t.home)
	} else {
		n, bookkeeping, err = decodeForeignKernelNeighbor(m, t.boundarySegments())
		if err == nil && !bookkeeping {
			if n.kind == 3 || n.kind == 5 {
				s := Segment{IfIndex: n.index}
				for _, a := range t.addresses {
					if a.index == n.index {
						p, _ := netip.ParsePrefix(a.prefix)
						s.Prefixes = append(s.Prefixes, p.Masked().String())
					}
				}
				n, bookkeeping, err = decodeSegmentNeighbor(m, s)
			} else {
				err = validateUnicastNeighbor(n)
			}
		}
	}
	// Only this new purpose omits arbitrary peer router negative coverage.
	// UNKNOWN remains an address/state observation without a positive identity;
	// all other decoder and actual owned-infrastructure guards remain closed.
	if f, ok := err.(*failure); ok && f.stage == "kernel.bindings.neighbor.router-state" && n.kind == 1 && n.address.Is6() && !n.address.IsMulticast() && n.flags&128 != 0 && (n.state == 1 || n.state == 32) && (n.mac == "" || validMAC(n.mac)) {
		err = nil
	}
	if f, ok := err.(*failure); ok && f.stage == "kernel.bindings.neighbor.mac" && packetOpaqueForeignNOARP(m, n, t) {
		// Retain the actual foreign address/state below. It is neither
		// bookkeeping nor a MAC association; all owned guards still apply.
		err = nil
	}
	if f, ok := err.(*failure); ok && f.stage == "kernel.bindings.neighbor.type" && packetOpaqueForeignLoopback(m, n, t) {
		// Exact zero LLADDR on proven loopback is unobservable L2, not a MAC.
		// Preserve the original link-local address/index for all guards below.
		n.mac, err = "", nil
	}
	if f, ok := err.(*failure); ok && f.stage == "kernel.bindings.neighbor.bookkeeping-mac" && packetOpaqueForeignMulticast(m, n, t) {
		// Router502 observed empty L2 on unrelated ARPHRD_NONE multicast.
		// Retain it as an opaque foreign row, not an ignored bookkeeping
		// record or client/MAC identity. Owned-address and epoch guards remain.
		err = nil
	}
	if err != nil || bookkeeping {
		return n, bookkeeping, err
	}
	if n.mac != "" && !validMAC(n.mac) {
		return n, false, at("packet.neighbor.mac", nil)
	}
	ownedMAC := false
	for _, l := range t.links {
		ownedMAC = ownedMAC || n.mac != "" && n.mac == l.MAC
	}
	ownedAddress := false
	matched := false
	for _, a := range t.addresses {
		p, _ := netip.ParsePrefix(a.prefix)
		if projectionAddressKey(a.index, p.Addr()) == projectionAddressKey(n.index, n.address) {
			ownedAddress = true
			for _, l := range t.links {
				if n.index == a.index && l.IfIndex == a.index && l.MAC == n.mac && n.mac != "" {
					matched = true
				}
			}
		}
	}
	if (ownedMAC || ownedAddress) && !matched {
		return n, false, at("packet.owned.neighbor.conflict", nil)
	}
	return n, ownedMAC || ownedAddress, nil // Proven own infrastructure is negative only.
}

// Exact observed IPv6 NOARP/RTN_MULTICAST wire shape on a positively known
// unrelated non-Ethernet link. No selected/member/parent or unknown link may
// use this exception; the shared full/finite decoder stays unchanged.
func packetOpaqueForeignMulticast(m message, n kernelNeighbor, t ipv4LANPacketTopology) bool {
	if (m.kind != 28 && m.kind != 29) || len(m.data) < 12 || m.data[0] != 10 || n.index <= 1 || n.index == t.home.IfIndex || n.kind != 5 || n.state != 64 || n.flags != 0 || n.mac != "" || !n.address.Is6() || !n.address.IsMulticast() {
		return false
	}
	a, err := attrs(m.data[12:])
	ll, present := a[2]
	if err != nil || len(a) != 4 || len(a[1]) != 16 || !present || len(ll) != 0 || len(a[3]) != 16 || len(a[4]) != 4 {
		return false
	}
	for raw := m.data[12:]; len(raw) != 0; {
		if binary.NativeEndian.Uint16(raw[2:4])&0xc000 != 0 {
			return false
		}
		size := int(binary.NativeEndian.Uint16(raw[:2]))
		raw = raw[(size+3)&^3:]
	}
	for _, member := range t.home.Members {
		if n.index == member.IfIndex || n.index == member.ParentIfIndex || member.Parent.Known && n.index == member.Parent.IfIndex {
			return false
		}
	}
	for _, link := range t.noneLinks {
		if link.IfIndex == n.index {
			return link.LinkType == 65534 && link.Flags&8 == 0 && !link.ForeignParent && link.MasterIfIndex == 0 && link.ParentIfIndex == 0
		}
	}
	return false
}

// Purpose-specific observed AF10 NOARP shape. Unknown link/attachment facts
// never prove foreign ingress. Shared full/finite neighbor grammar is unchanged.
func packetOpaqueForeignNOARP(m message, n kernelNeighbor, t ipv4LANPacketTopology) bool {
	if (m.kind != 28 && m.kind != 29) || len(m.data) < 12 || m.data[0] != 10 || n.index <= 1 || n.kind != 1 || n.state != 64 || n.flags != 0 || n.mac != "" || !n.address.Is6() || n.address.IsMulticast() {
		return false
	}
	a, err := attrs(m.data[12:])
	ll, present := a[2]
	if err != nil || !present || len(ll) != 0 || n.index == t.home.IfIndex {
		return false
	}
	for _, member := range t.home.Members {
		if n.index == member.IfIndex || n.index == member.ParentIfIndex || member.Parent.Known && n.index == member.Parent.IfIndex {
			return false
		}
	}
	for _, link := range t.noneLinks {
		if link.IfIndex == n.index {
			// Require a native namespace link with positively absent attachments;
			// no indirect/foreign parent relationship is inferred from a name.
			return link.LinkType == 65534 && !link.ForeignParent && link.MasterIfIndex == 0 && link.ParentIfIndex == 0
		}
	}
	return false
}

// Only this purpose retains the observed link-local RTN_LOCAL loopback tuple
// as foreign and opaque. It never promotes an address to owned infrastructure.
func packetOpaqueForeignLoopback(m message, n kernelNeighbor, t ipv4LANPacketTopology) bool {
	if (m.kind != 28 && m.kind != 29) || len(m.data) < 12 || m.data[0] != 10 || n.index <= 0 || n.kind != 2 || n.state != 64 || n.flags != 0 || !n.address.Is6() || !n.address.IsLinkLocalUnicast() || n.index == t.home.IfIndex {
		return false
	}
	a, err := attrs(m.data[12:])
	if err != nil || len(a) != 4 || len(a[1]) != 16 || !bytes.Equal(a[2], []byte{0, 0, 0, 0, 0, 0}) || len(a[3]) != 16 || len(a[4]) != 4 {
		return false
	}
	for raw := m.data[12:]; len(raw) != 0; {
		if binary.NativeEndian.Uint16(raw[2:4])&0xc000 != 0 {
			return false
		}
		size := int(binary.NativeEndian.Uint16(raw[:2]))
		raw = raw[(size+3)&^3:]
	}
	for _, member := range t.home.Members {
		if n.index == member.IfIndex || n.index == member.ParentIfIndex || member.Parent.Known && n.index == member.Parent.IfIndex {
			return false
		}
	}
	for _, link := range t.loopbackLinks {
		if link.IfIndex == n.index {
			return link.LinkType == 772 && link.Flags&8 != 0 && !link.ForeignParent && link.MasterIfIndex == 0 && link.ParentIfIndex == 0
		}
	}
	return false
}
func packetNeighborBoundary(ctx context.Context, t ipv4LANPacketTopology, frames map[byte][]message) ([]kernelNeighbor, []kernelNeighbor, error) {
	var home, foreign []kernelNeighbor
	seen := map[string]bool{}
	total, records := 0, 0
	for _, family := range []byte{2, 10} {
		rows, ok := frames[family]
		if !ok {
			return nil, nil, at("kernel.bindings.neighbor.family-missing", nil)
		}
		for _, m := range rows {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			total += len(m.data)
			records++
			if total > 1<<20 || records > 4096 {
				return nil, nil, at("kernel.bindings.neighbor.limit", nil)
			}
			if len(m.data) < 12 || m.data[0] != family {
				return nil, nil, at("kernel.bindings.neighbor.dump-family", nil)
			}
			n, bookkeeping, err := packetDecodeNeighbor(m, t)
			if err != nil {
				return nil, nil, err
			}
			key := projectionAddressKey(n.index, n.address) + "/" + strconv.Itoa(n.index)
			if seen[key] {
				return nil, nil, at("kernel.bindings.neighbor.duplicate", nil)
			}
			seen[key] = true
			if bookkeeping {
				continue
			}
			if n.index == t.home.IfIndex {
				home = append(home, n)
			} else {
				foreign = append(foreign, n)
			}
		}
	}
	return home, foreign, nil
}
func packetBindMembership(ctx context.Context, t ipv4LANPacketTopology, frames map[byte][]message) ([]Device, error) {
	home, foreign, err := packetNeighborBoundary(ctx, t, frames)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, n := range home {
		if n.address.Is4() && n.state != 1 && n.state != 32 && validMAC(n.mac) {
			wanted[n.mac] = true
		}
	}
	owners := map[string]string{}
	for _, n := range home {
		if wanted[n.mac] {
			key := projectionAddressKey(n.index, n.address)
			if old, ok := owners[key]; ok && old != n.mac {
				return nil, at("packet.membership.address-conflict", nil)
			}
			owners[key] = n.mac
		}
	}
	for _, n := range foreign {
		if wanted[n.mac] {
			return nil, at("packet.membership.foreign", nil)
		}
		if mac, ok := owners[projectionAddressKey(n.index, n.address)]; ok && mac != n.mac {
			return nil, at("packet.membership.address-conflict", nil)
		}
	}
	rows := kernelNeighborRows{t.home.Interface: {false: {}, true: {}}}
	for _, n := range home {
		if wanted[n.mac] && n.address.Is4() && n.state != 1 && n.state != 32 {
			rows[t.home.Interface][false] = append(rows[t.home.Interface][false], []byte(n.row())...)
		}
	}
	devices, err := bindDevices(ctx, []Segment{t.home}, rows)
	if err != nil {
		return nil, err
	}
	if len(devices) > 512 {
		return nil, at("packet.membership.limit", nil)
	}
	slices.SortFunc(devices, func(a, b Device) int { return strings.Compare(a.ID, b.ID) })
	return devices, nil
}

type ipv4LANPacketFenceSnapshot struct{ original ipv4LANPacketTopology }

// maxMembershipClasses bounds the collector's per-row memory. Beyond it an
// unseen row always moves the epoch, as before this filter existed.
const maxMembershipClasses = 8192

func packetMembershipKey(n kernelNeighbor) string {
	return projectionAddressKey(n.index, n.address) + "/" + strconv.Itoa(n.index)
}

// packetMembershipClass is what packetBindMembership reads from one row: its
// MAC and whether the row counts (not INCOMPLETE/FAILED). Deletion is a class.
func packetMembershipClass(kind uint16, n kernelNeighbor) string {
	if kind == 29 {
		return "deleted"
	}
	usable := "unusable"
	if n.state != 1 && n.state != 32 {
		usable = "usable"
	}
	return n.mac + "|" + usable
}

func packetMembershipClasses(home, foreign []kernelNeighbor) map[string]string {
	out := make(map[string]string, len(home)+len(foreign))
	for _, set := range [][]kernelNeighbor{home, foreign} {
		for _, n := range set {
			out[packetMembershipKey(n)] = packetMembershipClass(28, n)
		}
	}
	return out
}

func (s *fenceCollectorState) membershipClassChanged(key, class string) bool {
	if old, known := s.membershipClasses[key]; known {
		if old == class {
			return false
		}
		s.membershipClasses[key] = class
		return true
	}
	if s.membershipClasses == nil {
		s.membershipClasses = map[string]string{}
	}
	if len(s.membershipClasses) < maxMembershipClasses {
		s.membershipClasses[key] = class
	}
	return true
}

// seedMembership records dumped classes for rows without an observed event.
// A row seen in an event keeps that newer class.
func (s *fenceCollectorState) seedMembership(rows map[string]string) error {
	if !s.bound || s.packet == nil {
		return at("fence.seed.purpose", nil)
	}
	if s.membershipClasses == nil {
		s.membershipClasses = map[string]string{}
	}
	for key, class := range rows {
		if _, known := s.membershipClasses[key]; !known && len(s.membershipClasses) < maxMembershipClasses {
			s.membershipClasses[key] = class
		}
	}
	return nil
}

func (s *fenceCollectorState) checkPurposeNotifications(frames []message) error {
	if s.packet == nil {
		return s.checkNotifications(frames)
	}
	t := s.packet.original
	for _, m := range frames {
		if m.kind == 28 || m.kind == 29 {
			if m.flags != 0 {
				return at("packet.notifications.neighbor.flags", nil)
			}
			if packetHomeFDBRefresh(m, t) {
				continue // FDB learning is neither an IP binding nor membership B.
			}
			n, bookkeeping, err := packetDecodeNeighbor(m, t)
			if err != nil {
				return err
			}
			// Proven own infrastructure never enters membership (see
			// packetNeighborBoundary). An ordinary refresh of a known row
			// (REACHABLE/STALE/DELAY/PROBE with the same MAC) cannot change
			// the device list either; only a changed class moves the epoch.
			if bookkeeping || !s.membershipClassChanged(packetMembershipKey(n), packetMembershipClass(m.kind, n)) {
				continue
			}
			if s.membershipEpoch == ^uint64(0) {
				return at("packet.membership.epoch.overflow", nil)
			}
			s.membershipEpoch++
			continue
		}
		if m.kind == 16 || m.kind == 17 {
			if m.flags != 0 {
				return at("packet.notifications.link.flags", nil)
			}
			wireless, err := originalWirelessNotification(m, []Segment{t.home})
			if err != nil {
				return err
			}
			if wireless {
				continue
			}
			foreign, err := packetForeignWirelessNotification(m, t)
			if err != nil {
				return err
			}
			if foreign {
				continue
			}
			l, err := decodeLink(m)
			if err != nil {
				return err
			}
			if validMAC(l.MAC) || l.LinkType == 65534 || l.LinkType == 772 || slices.ContainsFunc(t.noneLinks, func(original Link) bool { return original.IfIndex == l.IfIndex }) || slices.ContainsFunc(t.loopbackLinks, func(original Link) bool { return original.IfIndex == l.IfIndex }) {
				return at("packet.notifications.owned-link", nil)
			}
		}
		if m.kind == 20 || m.kind == 21 {
			if m.flags != 0 {
				return at("packet.notifications.address.flags", nil)
			}
			if _, err := packetDecodeOwnedAddress(m); err != nil {
				return err
			}
			return at("packet.notifications.owned-address", nil)
		}
		if err := checkSnapshotNotifications([]message{m}, Snapshot{Segments: t.boundarySegments()}); err != nil {
			return err
		}
	}
	return nil
}
