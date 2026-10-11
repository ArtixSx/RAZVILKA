package physicalscope

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// PrimaryIPv4Review is read-only evidence from the SAME open physical Review
// and a complete native address dump. It is neither a listener/effect grant nor
// a detached Snapshot constructor. Current always rechecks the original owner.
type PrimaryIPv4Review struct{ state *primaryIPv4ReviewState }

type primaryIPv4ReviewState struct {
	self     *PrimaryIPv4Review
	observer *Observer
	original *Review
	ingress  string
	address  netip.Addr
	index    int
	row      primaryIPv4Row
	read     func(context.Context) ([]message, error)
	issued   bool
	invalid  bool // Protected by the original Review's mutex, also used by Close.
}

type primaryIPv4Row struct {
	index                    int
	address, peer, broadcast netip.Addr
	prefix, scope            byte
	flags                    uint32
	label                    string
	cache                    bool
	created, updated         uint32
	preferred, valid         uint32 // Aging counters are checked, never pinned.
}

func (*PrimaryIPv4Review) String() string   { return "[original physical primary IPv4 review]" }
func (*PrimaryIPv4Review) GoString() string { return "[original physical primary IPv4 review]" }

// ingress/address are exact candidate intent only. Production always uses the
// fixed native RTM_GETADDR reader inside the original provider's current-scope
// bookends. No public API accepts a snapshot, fact reader, flag or boolean.
func (o *Observer) ReviewPrimaryIPv4(ctx context.Context, original *Review, ingress string, address netip.Addr) (*PrimaryIPv4Review, error) {
	return o.reviewPrimaryIPv4(ctx, original, ingress, address, readPrimaryIPv4Dump)
}

// Private socket-free source seam. The public factory above cannot select it.
func (o *Observer) reviewPrimaryIPv4(ctx context.Context, original *Review, ingress string, address netip.Addr, read func(context.Context) ([]message, error)) (*PrimaryIPv4Review, error) {
	if !o.ready() || original == nil || original.state == nil || original.state.self != original || original.state.issuer != o || !interfaceName.MatchString(ingress) || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || read == nil {
		return nil, at("primary.dependencies", nil)
	}
	p := &PrimaryIPv4Review{state: &primaryIPv4ReviewState{observer: o, original: original, ingress: ingress, address: address, read: read}}
	p.state.self = p
	if err := p.Current(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// The existing original notification fence covers ifindex/name incarnation,
// selected members and address churn. Fresh selection and NI/boot/build checks
// bracket BOTH complete IPv4 dumps. A copied witness cannot substitute itself.
func (p *PrimaryIPv4Review) Current(ctx context.Context) error {
	if p == nil || p.state == nil || p.state.self != p {
		return at("primary.original", nil)
	}
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return boundary("primary.context", err)
	}
	defer cancel()
	v := p.state
	r := v.original
	if r == nil || r.state == nil || r.state.self != r || !v.observer.ready() || v.read == nil {
		return at("primary.dependencies", nil)
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.issuer != v.observer || s.closed || s.invalid || s.physicalInvalid || s.fence == nil || v.invalid {
		return at("primary.review.unavailable", nil)
	}
	refuse := func(stage string, err error) error {
		v.invalid = true
		if v.issued {
			s.invalid, s.physicalInvalid = true, true
		}
		return boundary(stage, err)
	}
	checkSelection := func() error {
		selection, err := v.observer.readSelection(c)
		if err != nil || !reflect.DeepEqual(selection, s.snapshot.Selection) {
			s.invalid = true
			return errors.Join(ErrUnknown, err)
		}
		return nil
	}
	if err := checkSelection(); err != nil {
		return refuse("primary.selection.before", err)
	}
	index := 0
	bits := 0
	for _, segment := range s.snapshot.Segments {
		if segment.Interface != v.ingress {
			continue
		}
		if index != 0 || segment.IfIndex <= 0 {
			return refuse("primary.interface.ambiguous", nil)
		}
		for _, raw := range segment.LinkAddresses {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil && prefix.Addr() == v.address && lanPrefix(prefix.Masked()) {
				index = segment.IfIndex
				bits = prefix.Bits()
				break
			}
		}
	}
	if index == 0 || v.issued && index != v.index {
		return refuse("primary.interface.candidate", nil)
	}
	var observed primaryIPv4Row
	entered := false
	err = v.observer.source.current(c, func(held context.Context, identity netidentity.Identity) error {
		if entered || held == nil || held.Err() != nil || identity != s.snapshot.Identity || identity.Validate() != nil {
			return at("primary.identity", nil)
		}
		entered = true
		deadline, finite := held.Deadline()
		originalDeadline, _ := c.Deadline()
		if !finite || deadline.After(originalDeadline) {
			return at("primary.identity.context", nil)
		}
		for pass := 0; pass < 2; pass++ {
			if err := s.fence.check(held, s.snapshot); err != nil {
				return boundary("primary.fence.before", err)
			}
			frames, err := v.read(held)
			if err != nil {
				return boundary("primary.dump", err)
			}
			row, err := selectPrimaryIPv4(frames, index, v.ingress, v.address)
			if err != nil {
				return boundary("primary.address", err)
			}
			if int(row.prefix) != bits {
				return at("primary.prefix.changed", nil)
			}
			if err := s.fence.check(held, s.snapshot); err != nil {
				return boundary("primary.fence.after", err)
			}
			row.preferred, row.valid = 0, 0 // Residence aging is not an incarnation.
			if pass == 0 {
				observed = row
			} else if observed != row {
				return at("primary.dump.changed", nil)
			}
		}
		return errors.Join(held.Err(), c.Err())
	})
	if err != nil || !entered {
		return refuse("primary.current", errors.Join(err, c.Err()))
	}
	if err := checkSelection(); err != nil {
		return refuse("primary.selection.after", err)
	}
	// Close queued churn during the selection read in the same original scope.
	closingEntered := false
	err = v.observer.source.current(c, func(held context.Context, identity netidentity.Identity) error {
		if closingEntered || held == nil || held.Err() != nil || identity != s.snapshot.Identity {
			return at("primary.identity.closing", nil)
		}
		closingEntered = true
		deadline, finite := held.Deadline()
		originalDeadline, _ := c.Deadline()
		if !finite || deadline.After(originalDeadline) {
			return at("primary.identity.closing.context", nil)
		}
		return s.fence.check(held, s.snapshot)
	})
	if err != nil || !closingEntered || c.Err() != nil || v.issued && v.row != observed {
		return refuse("primary.closing", errors.Join(err, c.Err()))
	}
	v.row, v.index, v.issued = observed, index, true
	return nil
}

// Decode every row in the complete AF_INET image before accepting a candidate.
// Pinned stock producer: keenetic/kernel-49@7b6c9477, if_addr.h and
// net/ipv4/devinet.c:inet_fill_ifaddr. Full IFA_FLAGS overrides the u8 header;
// the actual producer also emits their consistent low byte. Native attributes
// cannot carry nested/network-endian flags. Unknown/malformed rows refuse.
func selectPrimaryIPv4(frames []message, index int, ingress string, address netip.Addr) (primaryIPv4Row, error) {
	var selected primaryIPv4Row
	count := 0
	if len(frames) == 0 || len(frames) > 8192 {
		return selected, ErrUnknown
	}
	for _, m := range frames {
		row, err := decodePrimaryIPv4Row(m)
		if err != nil {
			return selected, err
		}
		if row.address != address {
			continue
		}
		count++ // The exact address on a second interface is also ambiguous.
		if row.index != index || row.peer != row.address || row.scope != 0 || row.flags&^uint32(0x80) != 0 || row.label != "" && row.label != ingress || row.cache && (row.preferred == 0 || row.valid == 0) {
			return selected, ErrUnknown
		}
		selected = row
	}
	if count != 1 {
		return selected, ErrUnknown
	}
	return selected, nil
}

func decodePrimaryIPv4Row(m message) (row primaryIPv4Row, err error) {
	if m.kind != 20 || m.flags != 2 || len(m.data) < 8 || len(m.data) > 256 || m.data[0] != 2 || m.data[1] > 32 {
		return row, ErrUnknown
	}
	// Preserve strict attr type bits before the existing bounded parser masks
	// NLA_F_NESTED. IPv4's fixed publisher emits neither flag on these leaves.
	for raw := m.data[8:]; len(raw) > 0; {
		if len(raw) < 4 || binary.NativeEndian.Uint16(raw[2:4])&0xc000 != 0 {
			return row, ErrUnknown
		}
		n := int(binary.NativeEndian.Uint16(raw[:2]))
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(raw) {
			return row, ErrUnknown
		}
		for _, pad := range raw[n:aligned] {
			if pad != 0 {
				return row, ErrUnknown
			}
		}
		raw = raw[aligned:]
	}
	a, err := attrs(m.data[8:])
	if err != nil || len(a[1]) != 4 || len(a[2]) != 4 || len(a[8]) != 4 || len(a[6]) != 16 {
		return row, ErrUnknown
	}
	row.index = int(binary.NativeEndian.Uint32(m.data[4:8]))
	if row.index <= 0 || uint64(row.index) > 0x7fffffff {
		return row, ErrUnknown
	}
	row.address, _ = netip.AddrFromSlice(a[2])
	row.peer, _ = netip.AddrFromSlice(a[1])
	row.prefix, row.scope, row.flags = m.data[1], m.data[3], uint32(m.data[2])
	for kind, raw := range a {
		switch kind {
		case 1, 2:
		case 3:
			if len(raw) < 2 || len(raw) > 16 || raw[len(raw)-1] != 0 || bytes.IndexByte(raw[:len(raw)-1], 0) >= 0 {
				return row, ErrUnknown
			}
			row.label = string(raw[:len(raw)-1])
			if strings.ContainsAny(row.label, "\r\n\t") {
				return row, ErrUnknown
			}
		case 4:
			if len(raw) != 4 {
				return row, ErrUnknown
			}
			row.broadcast, _ = netip.AddrFromSlice(raw)
		case 6:
			if len(raw) != 16 {
				return row, ErrUnknown
			}
			row.cache = true
			row.preferred, row.valid = binary.NativeEndian.Uint32(raw[:4]), binary.NativeEndian.Uint32(raw[4:8])
			row.created, row.updated = binary.NativeEndian.Uint32(raw[8:12]), binary.NativeEndian.Uint32(raw[12:16])
			if row.preferred > row.valid {
				return row, ErrUnknown
			}
		case 8:
			if len(raw) != 4 {
				return row, ErrUnknown
			}
			row.flags = binary.NativeEndian.Uint32(raw)
		default:
			return row, ErrUnknown
		}
	}
	if row.flags&^uint32(0x1fff) != 0 || byte(row.flags) != m.data[2] {
		return row, ErrUnknown
	}
	if row.flags&0x80 != 0 && (row.preferred != ^uint32(0) || row.valid != ^uint32(0)) {
		return row, ErrUnknown
	}
	return row, nil
}
