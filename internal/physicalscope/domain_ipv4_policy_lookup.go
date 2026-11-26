package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// DomainIPv4PolicyLookupQuery asks the kernel about an explicit original
// source/ingress and mark. Zero ingress is a distinct local-output lookup.
// The caller must establish the real pre-routing mark independently; this
// lookup does not execute PREROUTING, emulate NAT or classify native VPN rules.
type DomainIPv4PolicyLookupQuery struct {
	Source, Destination netip.Addr
	IngressIndex        int
	Mark                uint32
}

// DomainIPv4PolicyLookup retains the actual FIB table rather than silently
// normalising it to main. Its result is only an observation, not permission to
// send packets or bypass the existing baseline's whole-policy guard.
type DomainIPv4PolicyLookup struct {
	Source, Destination, Gateway netip.Addr
	IngressIndex, EgressIndex    int
	Table, Mark                  uint32
	Attributes                   []DomainPolicyAttribute
	Raw                          []byte
}

func ReadDomainIPv4PolicyRoute(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, query DomainIPv4PolicyLookupQuery) (DomainIPv4PolicyLookup, error) {
	if provider == nil {
		return DomainIPv4PolicyLookup{}, ErrUnknown
	}
	return readDomainIPv4PolicyRoute(ctx, expected, query, provider.WithCurrent, platformDomainIPv4PolicyRoute)
}

func readDomainIPv4PolicyRoute(ctx context.Context, expected netidentity.Identity, query DomainIPv4PolicyLookupQuery, current func(context.Context, func(context.Context, netidentity.Identity) error) error, lookup func(context.Context, DomainIPv4PolicyLookupQuery) (DomainIPv4PolicyLookup, error)) (DomainIPv4PolicyLookup, error) {
	var zero DomainIPv4PolicyLookup
	if ctx == nil || ctx.Err() != nil || expected.Validate() != nil || current == nil || lookup == nil || !query.valid() {
		return zero, ErrUnknown
	}
	if _, finite := ctx.Deadline(); !finite {
		return zero, ErrUnknown
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var result DomainIPv4PolicyLookup
	uses := 0
	err := current(bounded, func(held context.Context, actual netidentity.Identity) error {
		uses++
		if uses != 1 || actual != expected || held.Err() != nil {
			return ErrUnknown
		}
		var err error
		result, err = lookup(held, query)
		return errors.Join(err, held.Err())
	})
	if err != nil || uses != 1 || bounded.Err() != nil {
		return zero, errors.Join(ErrUnknown, err, bounded.Err())
	}
	return result, nil
}

func (q DomainIPv4PolicyLookupQuery) valid() bool {
	return q.Source.Is4() && q.Source.IsGlobalUnicast() && q.Destination.Is4() && publicfetch.PublicAddress(q.Destination) &&
		q.Source != q.Destination && q.IngressIndex >= 0 && q.IngressIndex <= 0x7fffffff && (q.IngressIndex == 0 || q.Source.IsPrivate())
}

func domainIPv4PolicyRouteRequest(query DomainIPv4PolicyLookupQuery, seq, port uint32) []byte {
	// Use the existing fixed src/dst/iif ABI, then add one explicit mark.
	raw := domainIPv4RouteRequest(domainIPv4RouteQuery{query.Source, query.Destination, query.IngressIndex}, seq, port)
	var attribute [8]byte
	binary.NativeEndian.PutUint16(attribute[:2], 8)
	binary.NativeEndian.PutUint16(attribute[2:4], 16) // RTA_MARK
	binary.NativeEndian.PutUint32(attribute[4:], query.Mark)
	raw = append(raw, attribute[:]...)
	binary.NativeEndian.PutUint32(raw[:4], uint32(len(raw)))
	return raw
}

func decodeDomainIPv4PolicyRouteReply(raw []byte, query DomainIPv4PolicyLookupQuery, seq, port, uid uint32) (DomainIPv4PolicyLookup, error) {
	var zero DomainIPv4PolicyLookup
	if len(raw) > 4096 {
		return zero, ErrUnknown
	}
	frames, err := messages(raw)
	if err != nil || len(frames) != 1 {
		return zero, ErrUnknown
	}
	reply := frames[0]
	d := reply.data
	if reply.kind != domainRouteReply || reply.flags != 0 || reply.seq != seq || reply.pid != port ||
		len(d) < 12 || d[0] != 2 || d[1] != 32 || d[2] != 32 || d[3] != 0 ||
		d[5] != 0 || d[6] != 0 || d[7] != 1 || binary.NativeEndian.Uint32(d[8:12]) != domainRouteCloned {
		return zero, ErrUnknown
	}
	entries, fields, err := domainPolicyAttributes(d[12:])
	if err != nil {
		return zero, err
	}
	for _, a := range entries {
		if a.Type&0xc000 != 0 || !slices.Contains([]uint16{1, 2, 3, 4, 5, 12, 15, 16, 25}, a.Type) ||
			a.Type == 12 && len(a.Value) != 32 || a.Type != 12 && len(a.Value) != 4 {
			return zero, ErrUnknown
		}
	}
	for _, required := range []uint16{1, 2, 4, 12, 15} {
		if fields[required] == nil {
			return zero, ErrUnknown
		}
	}
	scalar := func(kind uint16) uint32 { return binary.NativeEndian.Uint32(fields[kind]) }
	address := func(kind uint16) netip.Addr { return netip.AddrFrom4([4]byte(fields[kind])) }
	table, egress := scalar(15), scalar(4)
	// rt_fill_info in Linux 4.9 writes the low byte of table_id; modern
	// kernels use RT_TABLE_COMPAT for large tables. The mandatory RTA_TABLE
	// retains the full value, and no other header encoding is accepted.
	if table == 0 || d[4] != byte(table) && !(table > 255 && d[4] == 252) ||
		address(1) != query.Destination || address(2) != query.Source || egress == 0 || egress > 0x7fffffff ||
		binary.NativeEndian.Uint32(fields[12][8:12]) != 0 || binary.NativeEndian.Uint32(fields[12][12:16]) != 0 ||
		query.Mark != 0 && fields[16] == nil ||
		fields[16] != nil && scalar(16) != query.Mark {
		return zero, ErrUnknown
	}
	if query.IngressIndex == 0 {
		if fields[3] != nil || fields[25] != nil && scalar(25) != uid {
			return zero, ErrUnknown
		}
	} else if fields[3] == nil || scalar(3) != uint32(query.IngressIndex) || fields[25] != nil || egress == uint32(query.IngressIndex) {
		return zero, ErrUnknown
	}
	result := DomainIPv4PolicyLookup{Source: query.Source, Destination: query.Destination,
		IngressIndex: query.IngressIndex, EgressIndex: int(egress), Table: table, Mark: query.Mark,
		Attributes: entries, Raw: slices.Clone(d)}
	if fields[5] != nil {
		result.Gateway = address(5)
		if !result.Gateway.IsGlobalUnicast() {
			return zero, ErrUnknown
		}
	}
	return result, nil
}
