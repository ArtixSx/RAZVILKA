package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// DomainIPv4RouteLookup records only the result of one fixed kernel query.
// A caller must still observe the entire route, rule, link and packet policy.
// The result cannot issue a socket, authorise a flow or modify a route.
type DomainIPv4RouteLookup struct {
	Source, Destination, Gateway netip.Addr
	IngressIndex, EgressIndex    int
}

type domainIPv4RouteQuery struct {
	source, destination netip.Addr
	ingress             int // Zero is the distinct local-output query.
}

const (
	domainRouteGet         = 26 // RTM_GETROUTE
	domainRouteReply       = 24 // RTM_NEWROUTE
	domainRouteCloned      = 0x200
	domainRouteLookupTable = 0x1000
	domainRouteMainTable   = 254
	domainRouteDestination = 1
	domainRouteSource      = 2
	domainRouteInput       = 3
	domainRouteOutput      = 4
	domainRouteGateway     = 5
	domainRouteCache       = 12
	domainRouteTable       = 15
	domainRouteUID         = 25
)

// ReadDomainIPv4ForwardedRoute supplies the exact LAN source, public
// destination and original ingress to the input FIB lookup.
func ReadDomainIPv4ForwardedRoute(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, source, destination netip.Addr, ingress int) (DomainIPv4RouteLookup, error) {
	if ingress <= 0 || ingress > 0x7fffffff || !source.IsPrivate() {
		return DomainIPv4RouteLookup{}, ErrUnknown
	}
	return readDomainIPv4Route(ctx, provider, expected, domainIPv4RouteQuery{source, destination, ingress})
}

// ReadDomainIPv4LocalRoute supplies the router's explicit source and public
// destination. The request contains neither an ingress nor a forced egress.
func ReadDomainIPv4LocalRoute(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, source, destination netip.Addr) (DomainIPv4RouteLookup, error) {
	return readDomainIPv4Route(ctx, provider, expected, domainIPv4RouteQuery{source: source, destination: destination})
}

func readDomainIPv4Route(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, query domainIPv4RouteQuery) (DomainIPv4RouteLookup, error) {
	if ctx == nil || ctx.Err() != nil || provider == nil || expected.Validate() != nil ||
		!query.source.Is4() || !query.source.IsGlobalUnicast() ||
		!query.destination.Is4() || !publicfetch.PublicAddress(query.destination) || query.source == query.destination {
		return DomainIPv4RouteLookup{}, ErrUnknown
	}
	if _, finite := ctx.Deadline(); !finite {
		return DomainIPv4RouteLookup{}, ErrUnknown
	}
	leaf, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var observation DomainIPv4RouteLookup
	err := provider.WithCurrent(leaf, func(held context.Context, actual netidentity.Identity) error {
		if actual != expected {
			return ErrUnknown
		}
		var err error
		observation, err = platformDomainIPv4RouteLookup(held, query)
		return err
	})
	if err != nil || leaf.Err() != nil {
		return DomainIPv4RouteLookup{}, errors.Join(ErrUnknown, err, leaf.Err())
	}
	return observation, nil
}

func domainIPv4RouteRequest(query domainIPv4RouteQuery, seq, port uint32) []byte {
	// nlmsghdr, rtmsg, followed by two or three fixed-length attributes.
	request := make([]byte, 28, 52)
	put16, put32 := binary.NativeEndian.PutUint16, binary.NativeEndian.PutUint32
	put16(request[4:6], domainRouteGet)
	put16(request[6:8], 1) // NLM_F_REQUEST, never a dump or a write.
	put32(request[8:12], seq)
	put32(request[12:16], port)
	request[16], request[17], request[18] = 2, 32, 32 // AF_INET and both host prefixes.
	// In Linux 4.9 an unflagged GETROUTE can report main by default even
	// when lookup selected a different table. Request the actual table.
	put32(request[24:28], domainRouteLookupTable)
	appendAttribute := func(kind uint16, value [4]byte) {
		var a [8]byte
		put16(a[:2], 8)
		put16(a[2:4], kind)
		copy(a[4:], value[:])
		request = append(request, a[:]...)
	}
	appendAttribute(domainRouteDestination, query.destination.As4())
	appendAttribute(domainRouteSource, query.source.As4())
	if query.ingress != 0 {
		var value [4]byte
		put32(value[:], uint32(query.ingress))
		appendAttribute(domainRouteInput, value)
	}
	put32(request[:4], uint32(len(request)))
	return request
}

func decodeDomainIPv4RouteReply(raw []byte, query domainIPv4RouteQuery, seq, port, uid uint32) (DomainIPv4RouteLookup, error) {
	var zero DomainIPv4RouteLookup
	if len(raw) > 4096 {
		return zero, ErrUnknown
	}
	frames, err := messages(raw)
	if err != nil || len(frames) != 1 {
		return zero, ErrUnknown
	}
	reply := frames[0]
	if reply.kind != domainRouteReply || reply.flags != 0 || reply.seq != seq || reply.pid != port {
		return zero, ErrUnknown
	}
	data := reply.data
	if len(data) < 12 || data[0] != 2 || data[1] != 32 || data[2] != 32 || data[3] != 0 ||
		data[4] != domainRouteMainTable || data[5] != 0 || data[6] != 0 || data[7] != 1 ||
		binary.NativeEndian.Uint32(data[8:12]) != domainRouteCloned {
		return zero, ErrUnknown
	}
	var fields [domainRouteUID + 1][]byte
	for remaining := data[12:]; len(remaining) != 0; {
		if len(remaining) < 4 {
			return zero, ErrUnknown
		}
		n := int(binary.NativeEndian.Uint16(remaining[:2]))
		kind := binary.NativeEndian.Uint16(remaining[2:4])
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(remaining) || kind >= uint16(len(fields)) || fields[kind] != nil {
			return zero, ErrUnknown
		}
		switch kind {
		case domainRouteDestination, domainRouteSource, domainRouteInput, domainRouteOutput, domainRouteGateway, domainRouteTable, domainRouteUID:
			if n != 8 {
				return zero, ErrUnknown
			}
		case domainRouteCache:
			if n != 36 {
				return zero, ErrUnknown
			}
		default:
			// Reject flags on otherwise-known attributes as well as
			// metrics, marks, encapsulation, multipath and unknown fields.
			return zero, ErrUnknown
		}
		fields[kind] = remaining[4:n]
		remaining = remaining[aligned:]
	}
	for _, required := range []uint16{domainRouteDestination, domainRouteSource, domainRouteOutput, domainRouteTable, domainRouteCache} {
		if fields[required] == nil {
			return zero, ErrUnknown
		}
	}
	address := func(kind uint16) netip.Addr { return netip.AddrFrom4([4]byte(fields[kind])) }
	scalar := func(kind uint16) uint32 { return binary.NativeEndian.Uint32(fields[kind]) }
	egress := scalar(domainRouteOutput)
	cache := fields[domainRouteCache]
	if address(domainRouteDestination) != query.destination || address(domainRouteSource) != query.source ||
		scalar(domainRouteTable) != domainRouteMainTable || egress == 0 || egress > 0x7fffffff ||
		binary.NativeEndian.Uint32(cache[8:12]) != 0 || binary.NativeEndian.Uint32(cache[12:16]) != 0 {
		return zero, ErrUnknown
	}
	if query.ingress == 0 {
		if fields[domainRouteInput] != nil || fields[domainRouteUID] != nil && scalar(domainRouteUID) != uid {
			return zero, ErrUnknown
		}
	} else if fields[domainRouteInput] == nil || scalar(domainRouteInput) != uint32(query.ingress) ||
		egress == uint32(query.ingress) || fields[domainRouteUID] != nil {
		return zero, ErrUnknown
	}
	observation := DomainIPv4RouteLookup{Source: query.source, Destination: query.destination, IngressIndex: query.ingress, EgressIndex: int(egress)}
	if fields[domainRouteGateway] != nil {
		observation.Gateway = address(domainRouteGateway)
		if !observation.Gateway.IsGlobalUnicast() {
			return zero, ErrUnknown
		}
	}
	return observation, nil
}
