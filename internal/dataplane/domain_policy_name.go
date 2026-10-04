package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

// NameState describes bytes from this connection before any outbound. ECH
// includes GREASE: an outer SNI never proves the inner name. This is connection
// identity, not authority for later HTTP/2 or HTTP/3 coalesced requests.
type DomainPolicyNameState string

const (
	DomainPolicyNameVisible   DomainPolicyNameState = "visible"
	DomainPolicyNameAbsent    DomainPolicyNameState = "absent"
	DomainPolicyNameAmbiguous DomainPolicyNameState = "ambiguous"
	DomainPolicyNameEncrypted DomainPolicyNameState = "encrypted-outer-only"
	DomainPolicyNameTimeout   DomainPolicyNameState = "timeout"
	DomainPolicyNameBound     DomainPolicyNameState = "bound-exceeded"
	DomainPolicyNameOpaque    DomainPolicyNameState = "opaque"
)

type DomainPolicyNameEvidence struct {
	State  DomainPolicyNameState
	Name   string
	Source string
}

type DomainPolicySniffLimits struct {
	Bytes   int
	Timeout time.Duration
}

func (l DomainPolicySniffLimits) valid() bool {
	return l.Bytes >= 512 && l.Bytes <= 64<<10 && l.Timeout > 0 && l.Timeout <= 2*time.Second
}

func domainNameState(state DomainPolicyNameState) DomainPolicyNameEvidence {
	return DomainPolicyNameEvidence{State: state}
}

// sniffDomainPolicyTCP consumes a bounded prefix but never writes, resolves or
// dials. The caller must replay the entire prefix unchanged after authorization.
// It owns the connection's temporary read deadline; cancellation closes only
// this admitted connection and the forwarding owner joins its lifetime.
func sniffDomainPolicyTCP(ctx context.Context, conn net.Conn, limits DomainPolicySniffLimits) (DomainPolicyNameEvidence, []byte, error) {
	if conn == nil || !limits.valid() {
		return domainNameState(DomainPolicyNameOpaque), nil, ErrDomainPolicy
	}
	deadline := time.Now().Add(limits.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return domainNameState(DomainPolicyNameOpaque), nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer conn.SetReadDeadline(time.Time{})
	buffer := make([]byte, 0, limits.Bytes)
	chunk := make([]byte, min(limits.Bytes, 4096))
	for {
		if err := ctx.Err(); err != nil {
			return domainNameState(DomainPolicyNameOpaque), buffer, err
		}
		evidence, complete := parseDomainPolicyName(buffer)
		if complete {
			return evidence, buffer, nil
		}
		if len(buffer) == limits.Bytes {
			return domainNameState(DomainPolicyNameBound), buffer, nil
		}
		n, err := conn.Read(chunk[:min(len(chunk), limits.Bytes-len(buffer))])
		buffer = append(buffer, chunk[:n]...)
		if err != nil {
			if ctx.Err() != nil {
				return domainNameState(DomainPolicyNameOpaque), buffer, ctx.Err()
			}
			// A complete prefix returned with EOF remains evidence. A partial
			// prefix never becomes a visible name or a valid no-name flow.
			if e, complete := parseDomainPolicyName(buffer); complete {
				return e, buffer, nil
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				return domainNameState(DomainPolicyNameTimeout), buffer, nil
			}
			return domainNameState(DomainPolicyNameOpaque), buffer, err
		}
		if n == 0 {
			return domainNameState(DomainPolicyNameOpaque), buffer, io.ErrNoProgress
		}
	}
}

func parseDomainPolicyName(data []byte) (DomainPolicyNameEvidence, bool) {
	if len(data) == 0 {
		return DomainPolicyNameEvidence{}, false
	}
	if data[0] == 22 {
		return parseDomainPolicyTLS(data)
	}
	// Wait for a bounded request line only for supported HTTP/1 methods.
	methods := []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	partial := false
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method)) {
			return parseDomainPolicyHTTP(data)
		}
		partial = partial || bytes.HasPrefix([]byte(method), data)
	}
	if partial {
		return DomainPolicyNameEvidence{}, false
	}
	return domainNameState(DomainPolicyNameOpaque), true
}

func domainPolicyAuthority(authority string) (string, bool) {
	if authority == "" || strings.ContainsAny(authority, "\t\r\n /@?#\\") {
		return "", false
	}
	u, err := url.Parse("http://" + authority)
	if err != nil || u.Host != authority || u.User != nil {
		return "", false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", false
		}
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return "", true // literal address has no domain identity
	}
	name, err := config.PolicyDomain(u.Hostname())
	return name, err == nil
}

func parseDomainPolicyHTTP(data []byte) (DomainPolicyNameEvidence, bool) {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		return DomainPolicyNameEvidence{}, false
	}
	header := string(data[:end])
	if strings.ContainsAny(strings.ReplaceAll(header, "\r\n", ""), "\r\n\x00") {
		return domainNameState(DomainPolicyNameAmbiguous), true
	}
	lines := strings.Split(header, "\r\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || parts[1] == "" || parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0" {
		return domainNameState(DomainPolicyNameAmbiguous), true
	}
	host := ""
	found := false
	for _, line := range lines[1:] {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			return domainNameState(DomainPolicyNameAmbiguous), true
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return domainNameState(DomainPolicyNameAmbiguous), true
		}
		if strings.EqualFold(key, "host") {
			if found {
				return domainNameState(DomainPolicyNameAmbiguous), true
			}
			found = true
			var valid bool
			host, valid = domainPolicyAuthority(strings.Trim(value, " \t"))
			if !valid {
				return domainNameState(DomainPolicyNameAmbiguous), true
			}
		}
	}
	if parts[2] == "HTTP/1.1" && !found {
		return domainNameState(DomainPolicyNameAmbiguous), true
	}
	// Proxy absolute-form and CONNECT authorities must agree with Host. Never
	// choose between conflicting identities, even when only one matches a rule.
	if parts[0] == "CONNECT" || strings.Contains(parts[1], "://") {
		authority := parts[1]
		if parts[0] != "CONNECT" {
			u, err := url.Parse(parts[1])
			if err != nil || u.User != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
				return domainNameState(DomainPolicyNameAmbiguous), true
			}
			authority = u.Host
		}
		name, valid := domainPolicyAuthority(authority)
		if !valid || !found || name != host {
			return domainNameState(DomainPolicyNameAmbiguous), true
		}
	} else if !strings.HasPrefix(parts[1], "/") && parts[1] != "*" {
		return domainNameState(DomainPolicyNameAmbiguous), true
	}
	if host == "" {
		return domainNameState(DomainPolicyNameAbsent), true
	}
	return DomainPolicyNameEvidence{State: DomainPolicyNameVisible, Name: host, Source: "application"}, true
}

func parseDomainPolicyTLS(data []byte) (DomainPolicyNameEvidence, bool) {
	var handshake []byte
	for offset, records := 0, 0; ; records++ {
		if records >= 128 {
			return domainNameState(DomainPolicyNameBound), true
		}
		if len(data)-offset < 5 {
			return DomainPolicyNameEvidence{}, false
		}
		h := data[offset : offset+5]
		length := int(binary.BigEndian.Uint16(h[3:]))
		if h[0] != 22 || h[1] != 3 || h[2] > 4 || h[2] == 0 || length == 0 || length > (1<<14)+256 {
			return domainNameState(DomainPolicyNameAmbiguous), true
		}
		if len(data)-offset-5 < length {
			return DomainPolicyNameEvidence{}, false
		}
		handshake = append(handshake, data[offset+5:offset+5+length]...)
		offset += 5 + length
		if len(handshake) < 4 {
			continue
		}
		size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshake[0] != 1 || size < 38 || size > 64<<10 {
			return domainNameState(DomainPolicyNameAmbiguous), true
		}
		if len(handshake) < size+4 {
			continue
		}
		if len(handshake) != size+4 {
			return domainNameState(DomainPolicyNameAmbiguous), true
		}
		return parseDomainPolicyClientHello(handshake[4:]), true
	}
}

func parseDomainPolicyClientHello(hello []byte) DomainPolicyNameEvidence {
	bad := domainNameState(DomainPolicyNameAmbiguous)
	if len(hello) < 38 || hello[0] != 3 || hello[1] < 1 || hello[1] > 3 {
		return bad
	}
	rest := hello[34:]
	takeVector := func(width int) ([]byte, bool) {
		if len(rest) < width {
			return nil, false
		}
		n := int(rest[0])
		if width == 2 {
			n = int(binary.BigEndian.Uint16(rest))
		}
		rest = rest[width:]
		if n > len(rest) {
			return nil, false
		}
		v := rest[:n]
		rest = rest[n:]
		return v, true
	}
	if session, ok := takeVector(1); !ok || len(session) > 32 {
		return bad
	}
	if ciphers, ok := takeVector(2); !ok || len(ciphers) < 2 || len(ciphers)%2 != 0 {
		return bad
	}
	if compression, ok := takeVector(1); !ok || len(compression) == 0 {
		return bad
	}
	if len(rest) == 0 {
		return domainNameState(DomainPolicyNameAbsent)
	}
	extensions, ok := takeVector(2)
	if !ok || len(rest) != 0 {
		return bad
	}
	seen := map[uint16]bool{}
	name := ""
	encrypted := false
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return bad
		}
		kind, n := binary.BigEndian.Uint16(extensions), int(binary.BigEndian.Uint16(extensions[2:]))
		extensions = extensions[4:]
		if n > len(extensions) || seen[kind] {
			return bad
		}
		seen[kind] = true
		value := extensions[:n]
		extensions = extensions[n:]
		if kind == 0xfe0d || kind == 0xffce {
			encrypted = true
		}
		if kind != 0 {
			continue
		}
		if len(value) < 5 || int(binary.BigEndian.Uint16(value)) != len(value)-2 {
			return bad
		}
		value = value[2:]
		if value[0] != 0 || int(binary.BigEndian.Uint16(value[1:])) != len(value)-3 {
			return bad
		}
		var err error
		name, err = config.PolicyDomain(string(value[3:]))
		if err != nil || name == "" {
			return bad
		}
	}
	if encrypted {
		return domainNameState(DomainPolicyNameEncrypted)
	}
	if name == "" {
		return domainNameState(DomainPolicyNameAbsent)
	}
	return DomainPolicyNameEvidence{State: DomainPolicyNameVisible, Name: name, Source: "tls-sni"}
}
