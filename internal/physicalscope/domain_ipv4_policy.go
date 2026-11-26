package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// DomainPolicyAttribute retains the original type (including NLA flags), order
// and detached value. Unknown selectors are never discarded or interpreted as
// permission. Raw payloads below additionally retain headers and padding.
type DomainPolicyAttribute struct {
	Type  uint16
	Value []byte
}

type DomainIPv4PolicyRule struct {
	Priority, Table, Flags   uint32
	Source, Destination      netip.Prefix
	Input, Output            string
	Mark, Mask               uint32
	MarkPresent, MaskPresent bool
	Action, TOS              uint8
	Attributes               []DomainPolicyAttribute
	Raw                      []byte
}

type DomainIPv4PolicyRoute struct {
	Table, Flags, Metric       uint32
	InputIndex, OutputIndex    int
	Source, Destination        netip.Prefix
	Gateway, PreferredSource   netip.Addr
	Protocol, Scope, Type, TOS uint8
	Attributes                 []DomainPolicyAttribute
	Raw                        []byte
}

type DomainIPv4PolicyLink struct {
	Index, MasterIndex, ParentIndex int
	Name, Kind                      string
	Type                            uint16
	Flags, Change, MTU              uint32
	Attributes                      []DomainPolicyAttribute
	Raw                             []byte
}

// DomainIPv4PolicyInventory is a complete, bounded read of three kernel dumps
// in one retained namespace. It is not atomic across the dumps, a durable
// fence, evidence of unchanged packet hooks, or authority to Apply/Connect.
// Rule order and all unrecognised attributes remain available to the caller.
type DomainIPv4PolicyInventory struct {
	Rules  []DomainIPv4PolicyRule
	Routes []DomainIPv4PolicyRoute
	Links  []DomainIPv4PolicyLink
}

// ReadDomainIPv4PolicySnapshot needs neither ip JSON nor an executable. Its
// caller must independently verify the target platform and packet semantics;
// a stock provider is permitted to read facts, not to mint a baseline owner.
func ReadDomainIPv4PolicySnapshot(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity) (DomainIPv4PolicyInventory, error) {
	if provider == nil {
		return DomainIPv4PolicyInventory{}, ErrUnknown
	}
	return readDomainIPv4PolicySnapshot(ctx, expected, provider.WithCurrent, platformDomainIPv4PolicyDump)
}

func readDomainIPv4PolicySnapshot(ctx context.Context, expected netidentity.Identity, current func(context.Context, func(context.Context, netidentity.Identity) error) error, capture func(context.Context, uint16, byte) ([]message, error)) (DomainIPv4PolicyInventory, error) {
	var zero DomainIPv4PolicyInventory
	if ctx == nil || ctx.Err() != nil || expected.Validate() != nil || current == nil || capture == nil {
		return zero, ErrUnknown
	}
	if _, finite := ctx.Deadline(); !finite {
		return zero, ErrUnknown
	}
	bounded, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var result DomainIPv4PolicyInventory
	uses := 0
	err := current(bounded, func(held context.Context, actual netidentity.Identity) error {
		uses++
		if uses != 1 || actual != expected || held.Err() != nil {
			return ErrUnknown
		}
		var err error
		result, err = collectDomainIPv4PolicyInventory(held, capture)
		return errors.Join(err, held.Err())
	})
	if err != nil || uses != 1 || bounded.Err() != nil {
		return zero, errors.Join(ErrUnknown, err, bounded.Err())
	}
	return result, nil
}

func collectDomainIPv4PolicyInventory(ctx context.Context, capture func(context.Context, uint16, byte) ([]message, error)) (DomainIPv4PolicyInventory, error) {
	read := func(kind uint16, family byte) ([]message, error) {
		leaf, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		frames, err := capture(leaf, kind, family)
		return frames, errors.Join(err, leaf.Err())
	}
	rules, err := read(34, 2) // RTM_GETRULE, AF_INET
	if err != nil {
		return DomainIPv4PolicyInventory{}, err
	}
	routes, err := read(26, 2) // RTM_GETROUTE, all tables
	if err != nil {
		return DomainIPv4PolicyInventory{}, err
	}
	links, err := read(18, 0) // RTM_GETLINK, AF_UNSPEC
	if err != nil {
		return DomainIPv4PolicyInventory{}, err
	}
	return decodeDomainIPv4PolicyInventory(rules, routes, links)
}

func domainPolicyAttributes(raw []byte) ([]DomainPolicyAttribute, map[uint16][]byte, error) {
	var entries []DomainPolicyAttribute
	values := make(map[uint16][]byte)
	for len(raw) != 0 {
		if len(raw) < 4 || len(entries) >= 256 {
			return nil, nil, ErrUnknown
		}
		n := int(binary.NativeEndian.Uint16(raw[:2]))
		kind := binary.NativeEndian.Uint16(raw[2:4])
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(raw) {
			return nil, nil, ErrUnknown
		}
		base := kind & 0x3fff
		if _, duplicate := values[base]; duplicate {
			return nil, nil, ErrUnknown
		}
		value := slices.Clone(raw[4:n])
		entries = append(entries, DomainPolicyAttribute{Type: kind, Value: value})
		values[base] = value
		raw = raw[aligned:]
	}
	return entries, values, nil
}

func domainPolicyPlain(entries []DomainPolicyAttribute, kinds ...uint16) bool {
	for _, entry := range entries {
		if slices.Contains(kinds, entry.Type&0x3fff) && entry.Type&0xc000 != 0 {
			return false
		}
	}
	return true
}

func domainPolicyPrefix(raw []byte, width byte) (netip.Prefix, error) {
	if width > 32 || len(raw) != 4 && !(len(raw) == 0 && width == 0) {
		return netip.Prefix{}, ErrUnknown
	}
	a := netip.IPv4Unspecified()
	if len(raw) == 4 {
		a = netip.AddrFrom4([4]byte(raw))
	}
	p := netip.PrefixFrom(a, int(width))
	if p != p.Masked() {
		return netip.Prefix{}, ErrUnknown
	}
	return p, nil
}

func domainPolicyAddress(raw []byte) (netip.Addr, error) {
	if raw == nil {
		return netip.Addr{}, nil
	}
	if len(raw) != 4 {
		return netip.Addr{}, ErrUnknown
	}
	return netip.AddrFrom4([4]byte(raw)), nil
}

func domainPolicyIndex(fields map[uint16][]byte, kind uint16) (int, error) {
	v, err := u32(fields, kind)
	if err != nil || v > 0x7fffffff {
		return 0, ErrUnknown
	}
	return int(v), nil
}

func decodeDomainIPv4PolicyInventory(rules, routes, links []message) (DomainIPv4PolicyInventory, error) {
	var result DomainIPv4PolicyInventory
	bytesRead := 0
	for _, frames := range [][]message{rules, routes, links} {
		if len(frames) > 8192 {
			return DomainIPv4PolicyInventory{}, ErrUnknown
		}
		for _, frame := range frames {
			bytesRead += len(frame.data)
			if len(frame.data) > 64<<10 || bytesRead > 12<<20 {
				return DomainIPv4PolicyInventory{}, ErrUnknown
			}
		}
	}
	for _, frame := range rules {
		rule, err := decodeDomainIPv4PolicyRule(frame)
		if err != nil {
			return DomainIPv4PolicyInventory{}, err
		}
		result.Rules = append(result.Rules, rule)
	}
	for _, frame := range routes {
		route, err := decodeDomainIPv4PolicyRoute(frame)
		if err != nil {
			return DomainIPv4PolicyInventory{}, err
		}
		result.Routes = append(result.Routes, route)
	}
	names, indices := map[string]bool{}, map[int]bool{}
	for _, frame := range links {
		link, err := decodeDomainIPv4PolicyLink(frame)
		if err != nil || names[link.Name] || indices[link.Index] {
			return DomainIPv4PolicyInventory{}, errors.Join(ErrUnknown, err)
		}
		names[link.Name], indices[link.Index] = true, true
		result.Links = append(result.Links, link)
	}
	if len(result.Links) == 0 {
		return DomainIPv4PolicyInventory{}, ErrUnknown
	}
	return result, nil
}

func decodeDomainIPv4PolicyRule(frame message) (DomainIPv4PolicyRule, error) {
	var result DomainIPv4PolicyRule
	d := frame.data
	if frame.kind != 32 || frame.flags != 2 || len(d) < 12 || d[0] != 2 || d[5] != 0 || d[6] != 0 {
		return result, ErrUnknown
	}
	entries, fields, err := domainPolicyAttributes(d[12:])
	if err != nil || !domainPolicyPlain(entries, 1, 2, 3, 6, 10, 15, 16, 17) {
		return result, ErrUnknown
	}
	result.Priority, err = u32(fields, 6)
	if err != nil {
		return DomainIPv4PolicyRule{}, err
	}
	result.Table = uint32(d[4])
	if fields[15] != nil {
		result.Table, err = u32(fields, 15)
		// Linux 4.9 fib_nl_fill_rule writes the low byte to frh->table;
		// modern kernels use RT_TABLE_COMPAT for a large table. The full
		// FRA_TABLE remains mandatory for that compatibility encoding.
		if err != nil || byte(result.Table) != d[4] && !(result.Table > 255 && d[4] == 252) {
			return DomainIPv4PolicyRule{}, ErrUnknown
		}
	} else if d[4] == 252 {
		return DomainIPv4PolicyRule{}, ErrUnknown
	}
	result.Destination, err = domainPolicyPrefix(fields[1], d[1])
	if err != nil {
		return DomainIPv4PolicyRule{}, err
	}
	result.Source, err = domainPolicyPrefix(fields[2], d[2])
	if err != nil {
		return DomainIPv4PolicyRule{}, err
	}
	for _, v := range []struct {
		kind   uint16
		target *string
	}{{3, &result.Input}, {17, &result.Output}} {
		if fields[v.kind] != nil {
			*v.target, err = wireString(fields[v.kind], 15)
			if err != nil || !interfaceName.MatchString(*v.target) {
				return DomainIPv4PolicyRule{}, ErrUnknown
			}
		}
	}
	result.Mark, err = u32(fields, 10)
	if err != nil {
		return DomainIPv4PolicyRule{}, err
	}
	result.Mask, err = u32(fields, 16)
	if err != nil {
		return DomainIPv4PolicyRule{}, err
	}
	result.MarkPresent, result.MaskPresent = fields[10] != nil, fields[16] != nil
	result.Action, result.TOS, result.Flags = d[7], d[3], binary.NativeEndian.Uint32(d[8:12])
	result.Attributes, result.Raw = entries, slices.Clone(d)
	return result, nil
}

func decodeDomainIPv4PolicyRoute(frame message) (DomainIPv4PolicyRoute, error) {
	var result DomainIPv4PolicyRoute
	d := frame.data
	if frame.kind != 24 || frame.flags != 2 || len(d) < 12 || d[0] != 2 {
		return result, ErrUnknown
	}
	table, err := wgKernelRouteTable(frame, 4)
	if err != nil {
		return result, err
	}
	entries, fields, err := domainPolicyAttributes(d[12:])
	if err != nil || !domainPolicyPlain(entries, 1, 2, 3, 4, 5, 6, 7, 15) {
		return result, ErrUnknown
	}
	result.Table = table
	result.Destination, err = domainPolicyPrefix(fields[1], d[1])
	if err != nil {
		return DomainIPv4PolicyRoute{}, err
	}
	result.Source, err = domainPolicyPrefix(fields[2], d[2])
	if err != nil {
		return DomainIPv4PolicyRoute{}, err
	}
	result.InputIndex, err = domainPolicyIndex(fields, 3)
	if err != nil {
		return DomainIPv4PolicyRoute{}, err
	}
	result.OutputIndex, err = domainPolicyIndex(fields, 4)
	if err != nil {
		return DomainIPv4PolicyRoute{}, err
	}
	result.Gateway, err = domainPolicyAddress(fields[5])
	if err != nil {
		return DomainIPv4PolicyRoute{}, err
	}
	result.PreferredSource, err = domainPolicyAddress(fields[7])
	if err != nil {
		return DomainIPv4PolicyRoute{}, err
	}
	result.Metric, err = u32(fields, 6)
	if err != nil {
		return DomainIPv4PolicyRoute{}, err
	}
	result.Protocol, result.Scope, result.Type, result.TOS = d[5], d[6], d[7], d[3]
	result.Flags, result.Attributes, result.Raw = binary.NativeEndian.Uint32(d[8:12]), entries, slices.Clone(d)
	return result, nil
}

func decodeDomainIPv4PolicyLink(frame message) (DomainIPv4PolicyLink, error) {
	var result DomainIPv4PolicyLink
	d := frame.data
	if frame.kind != 16 || frame.flags != 2 || len(d) < 16 || d[0] != 0 || d[1] != 0 {
		return result, ErrUnknown
	}
	entries, fields, err := domainPolicyAttributes(d[16:])
	if err != nil || !domainPolicyPlain(entries, 3, 4, 5, 10) {
		return result, ErrUnknown
	}
	result.Index = int(int32(binary.NativeEndian.Uint32(d[4:8])))
	result.Name, err = wireString(fields[3], 15)
	if err != nil || result.Index <= 0 || !interfaceName.MatchString(result.Name) {
		return DomainIPv4PolicyLink{}, ErrUnknown
	}
	result.MasterIndex, err = domainPolicyIndex(fields, 10)
	if err != nil {
		return DomainIPv4PolicyLink{}, err
	}
	result.ParentIndex, err = domainPolicyIndex(fields, 5)
	if err != nil {
		return DomainIPv4PolicyLink{}, err
	}
	result.MTU, err = u32(fields, 4)
	if err != nil {
		return DomainIPv4PolicyLink{}, err
	}
	if fields[18] != nil {
		infoEntries, info, e := domainPolicyAttributes(fields[18])
		if e != nil || !domainPolicyPlain(infoEntries, 1) {
			return DomainIPv4PolicyLink{}, ErrUnknown
		}
		if info[1] != nil {
			result.Kind, err = wireString(info[1], 64)
			if err != nil {
				return DomainIPv4PolicyLink{}, err
			}
		}
	}
	result.Type, result.Flags, result.Change = binary.NativeEndian.Uint16(d[2:4]), binary.NativeEndian.Uint32(d[8:12]), binary.NativeEndian.Uint32(d[12:16])
	result.Attributes, result.Raw = entries, slices.Clone(d)
	return result, nil
}
