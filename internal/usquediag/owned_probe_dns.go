package usquediag

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"golang.org/x/net/dns/dnsmessage"
)

var errOwnedNetworkDNS = errors.New("owned-network-dns-unconfirmed")

const (
	ownedDNSWireLimit    = 4096
	ownedDNSRecordLimit  = 64
	ownedDNSAddressLimit = 32
	ownedDNSAliasLimit   = 8
)

// Queries are fresh, single-question messages. DNS transport is supplied by the
// owned worker; these helpers never call the host resolver or retain a cache.
func ownedDNSQuery(host string, kind dnsmessage.Type) ([]byte, error) {
	name, err := ownedDNSName(host)
	if err != nil || kind != dnsmessage.TypeA && kind != dnsmessage.TypeAAAA {
		return nil, errOwnedNetworkDNS
	}
	var nonce [2]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errOwnedNetworkDNS
	}
	questionName, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, errOwnedNetworkDNS
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(nonce[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: questionName, Type: kind, Class: dnsmessage.ClassINET}},
	}
	wire, err := query.Pack()
	if err != nil || len(wire) > ownedDNSWireLimit {
		return nil, errOwnedNetworkDNS
	}
	return wire, nil
}

func parseOwnedDNSAnswer(query, response []byte) ([]netip.Addr, error) {
	addresses, _, err := parseOwnedDNSAnswerDetails(query, response)
	return addresses, err
}

// The address budget counts every A/AAAA RR, including unused glue. Returning
// only the requested terminal family never hides a private/mapped address in a
// different family or section from validation.
func parseOwnedDNSAnswerDetails(query, response []byte) ([]netip.Addr, int, error) {
	q, err := unpackOwnedDNSMessage(query)
	if err != nil || q.Response || q.OpCode != 0 || q.Truncated || q.RCode != dnsmessage.RCodeSuccess || len(q.Answers)+len(q.Authorities)+len(q.Additionals) != 0 {
		return nil, 0, errOwnedNetworkDNS
	}
	question := q.Questions[0]
	questionName, err := ownedDNSName(question.Name.String())
	if err != nil || question.Class != dnsmessage.ClassINET || question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA {
		return nil, 0, errOwnedNetworkDNS
	}
	r, err := unpackOwnedDNSMessage(response)
	if err != nil || !r.Response || r.ID != q.ID || r.OpCode != 0 || r.Truncated || r.RCode != dnsmessage.RCodeSuccess {
		return nil, 0, errOwnedNetworkDNS
	}
	replyName, err := ownedDNSName(r.Questions[0].Name.String())
	if err != nil || replyName != questionName || r.Questions[0].Type != question.Type || r.Questions[0].Class != question.Class {
		return nil, 0, errOwnedNetworkDNS
	}

	aliases := map[string]string{}
	addressCount, optCount := 0, 0
	for section, records := range [][]dnsmessage.Resource{r.Answers, r.Authorities, r.Additionals} {
		for _, record := range records {
			if record.Header.Type == dnsmessage.TypeOPT {
				// Reject an extended RCODE, unknown EDNS version/flags, duplicate
				// OPT or a pseudo-record outside the additional section.
				optCount++
				if section != 2 || optCount != 1 || record.Header.Name.String() != "." || record.Header.TTL & ^uint32(0x8000) != 0 {
					return nil, 0, errOwnedNetworkDNS
				}
				continue
			}
			if record.Header.Class != dnsmessage.ClassINET {
				return nil, 0, errOwnedNetworkDNS
			}
			switch body := record.Body.(type) {
			case *dnsmessage.AResource:
				addressCount++
				if !publicfetch.PublicAddress(netip.AddrFrom4(body.A)) {
					return nil, 0, errOwnedNetworkDNS
				}
			case *dnsmessage.AAAAResource:
				addressCount++
				address := netip.AddrFrom16(body.AAAA)
				if address.Is4In6() || !publicfetch.PublicAddress(address) {
					return nil, 0, errOwnedNetworkDNS
				}
			case *dnsmessage.CNAMEResource:
				owner, ownerErr := ownedDNSName(record.Header.Name.String())
				target, targetErr := ownedDNSName(body.CNAME.String())
				if section != 0 || ownerErr != nil || targetErr != nil || aliases[owner] != "" || owner == target {
					return nil, 0, errOwnedNetworkDNS
				}
				aliases[owner] = target
			}
			if addressCount > ownedDNSAddressLimit {
				return nil, 0, errOwnedNetworkDNS
			}
		}
	}

	terminal := questionName
	visited := map[string]bool{terminal: true}
	for steps := 0; aliases[terminal] != ""; steps++ {
		if steps >= ownedDNSAliasLimit {
			return nil, 0, errOwnedNetworkDNS
		}
		terminal = aliases[terminal]
		if visited[terminal] {
			return nil, 0, errOwnedNetworkDNS
		}
		visited[terminal] = true
	}
	// Every alias must belong to the question's single chain. An unrelated
	// chain, even one without an address, cannot be treated as benign NODATA.
	if len(visited)-1 != len(aliases) {
		return nil, 0, errOwnedNetworkDNS
	}

	addresses := []netip.Addr{}
	seen := map[netip.Addr]bool{}
	for _, record := range r.Answers {
		var address netip.Addr
		switch body := record.Body.(type) {
		case *dnsmessage.AResource:
			address = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			address = netip.AddrFrom16(body.AAAA)
		default:
			continue
		}
		owner, err := ownedDNSName(record.Header.Name.String())
		if err != nil || owner != terminal {
			return nil, 0, errOwnedNetworkDNS
		}
		if record.Header.Type == question.Type && !seen[address] {
			seen[address] = true
			addresses = append(addresses, address)
		}
	}
	return addresses, addressCount, nil
}

// Both families share a three-second window. A failure of either fresh query
// invalidates the set; only genuine NOERROR/NODATA may leave one family empty.
func ownedResolvePublic(parent context.Context, host string, exchange func(context.Context, []byte) ([]byte, error)) ([]netip.Addr, error) {
	if parent == nil || parent.Err() != nil {
		return nil, errOwnedNetworkDNS
	}
	if literal, err := netip.ParseAddr(host); err == nil {
		if literal.Is4In6() || literal.Zone() != "" || literal.String() != host || !publicfetch.PublicAddress(literal) {
			return nil, errOwnedNetworkDNS
		}
		return []netip.Addr{literal}, nil
	}
	if _, err := ownedDNSName(host); err != nil || exchange == nil {
		return nil, errOwnedNetworkDNS
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	addresses := []netip.Addr{}
	seen := map[netip.Addr]bool{}
	addressCount := 0
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if ctx.Err() != nil {
			return nil, errOwnedNetworkDNS
		}
		query, err := ownedDNSQuery(host, kind)
		if err != nil {
			return nil, errOwnedNetworkDNS
		}
		response, err := exchange(ctx, query)
		if err != nil || ctx.Err() != nil {
			return nil, ownedProbeTargetFailure(errOwnedNetworkDNS, err)
		}
		answer, count, err := parseOwnedDNSAnswerDetails(query, response)
		addressCount += count
		if err != nil || addressCount > ownedDNSAddressLimit {
			return nil, errOwnedNetworkDNS
		}
		for _, address := range answer {
			if !seen[address] {
				seen[address] = true
				addresses = append(addresses, address)
			}
		}
	}
	if len(addresses) == 0 || ctx.Err() != nil {
		return nil, errOwnedNetworkDNS
	}
	return addresses, nil
}

func ownedDNSName(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(raw, "."))
	if _, err := netip.ParseAddr(host); err == nil {
		return "", errOwnedNetworkDNS
	}
	parsed, err := validateOwnedNetworkHTTPS("https://" + host + "/")
	if err != nil || parsed.Host != host || parsed.Hostname() != host || parsed.EscapedPath() != "/" {
		return "", errOwnedNetworkDNS
	}
	return host + ".", nil
}

func unpackOwnedDNSMessage(wire []byte) (dnsmessage.Message, error) {
	if !ownedDNSWireComplete(wire) {
		return dnsmessage.Message{}, errOwnedNetworkDNS
	}
	var message dnsmessage.Message
	if err := message.Unpack(wire); err != nil || len(message.Questions) != 1 {
		return dnsmessage.Message{}, errOwnedNetworkDNS
	}
	return message, nil
}

// dnsmessage.Unpack validates resource bodies but does not reject trailing
// bytes. This bounded framing pass also limits declared counts before allocation.
func ownedDNSWireComplete(wire []byte) bool {
	if len(wire) < 12 || len(wire) > ownedDNSWireLimit || binary.BigEndian.Uint16(wire[4:6]) != 1 || wire[3]&0x40 != 0 {
		return false
	}
	count := int(binary.BigEndian.Uint16(wire[6:8])) + int(binary.BigEndian.Uint16(wire[8:10])) + int(binary.BigEndian.Uint16(wire[10:12]))
	if count > ownedDNSRecordLimit {
		return false
	}
	offset, ok := skipOwnedDNSWireName(wire, 12)
	if !ok || offset+4 > len(wire) {
		return false
	}
	offset += 4
	for range count {
		offset, ok = skipOwnedDNSWireName(wire, offset)
		if !ok || offset+10 > len(wire) {
			return false
		}
		size := int(binary.BigEndian.Uint16(wire[offset+8 : offset+10]))
		kind := dnsmessage.Type(binary.BigEndian.Uint16(wire[offset : offset+2]))
		body := offset + 10
		offset = body + size
		if offset > len(wire) || !ownedDNSWireResource(wire, body, offset, kind) {
			return false
		}
	}
	return offset == len(wire)
}

// The DNS library deliberately advances by RDLENGTH even for fixed-size and
// name-bearing resources. Check those boundaries before it decodes them, so a
// short body cannot borrow bytes from the next RR and extra bytes cannot hide.
func ownedDNSWireResource(wire []byte, start, end int, kind dnsmessage.Type) bool {
	nameEnd := func(offset int) (int, bool) {
		next, ok := skipOwnedDNSWireName(wire, offset)
		return next, ok && next <= end
	}
	switch kind {
	case dnsmessage.TypeA:
		return end-start == 4
	case dnsmessage.TypeAAAA:
		return end-start == 16
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS, dnsmessage.TypePTR:
		next, ok := nameEnd(start)
		return ok && next == end
	case dnsmessage.TypeSOA:
		next, ok := nameEnd(start)
		if !ok {
			return false
		}
		next, ok = nameEnd(next)
		return ok && next+20 == end
	case dnsmessage.TypeMX, dnsmessage.TypeSRV:
		size := 2
		if kind == dnsmessage.TypeSRV {
			size = 6
		}
		if start+size >= end {
			return false
		}
		next, ok := nameEnd(start + size)
		return ok && next == end
	case dnsmessage.TypeTXT:
		for start < end {
			start += 1 + int(wire[start])
			if start > end {
				return false
			}
		}
		return start == end
	case dnsmessage.TypeOPT:
		for start < end {
			if start+4 > end {
				return false
			}
			start += 4 + int(binary.BigEndian.Uint16(wire[start+2:start+4]))
			if start > end {
				return false
			}
		}
		return start == end
	default:
		return true
	}
}

func skipOwnedDNSWireName(wire []byte, offset int) (int, bool) {
	for offset < len(wire) {
		size := int(wire[offset])
		if size&0xc0 == 0xc0 {
			if offset+1 >= len(wire) {
				return 0, false
			}
			pointer := (size&0x3f)<<8 | int(wire[offset+1])
			return offset + 2, pointer >= 12 && pointer < offset
		}
		if size > 63 || offset+1+size > len(wire) {
			return 0, false
		}
		offset += 1 + size
		if size == 0 {
			return offset, true
		}
	}
	return 0, false
}
