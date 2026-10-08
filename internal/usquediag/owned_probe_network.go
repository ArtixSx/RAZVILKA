package usquediag

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const ownedWarpTraceURL = "https://www.cloudflare.com/cdn-cgi/trace"
const ownedTraceBodyLimit = 16 << 10
const ownedServiceBodyLimit = 32 << 10
const ownedDoHURL = "https://cloudflare-dns.com/dns-query"
const ownedDoHBodyLimit = 4096

var (
	errOwnedNetworkRequest = errors.New("owned-network-request-invalid")
	errOwnedNetworkHTTP    = errors.New("owned-network-http-unconfirmed")
	errOwnedNetworkTrace   = errors.New("owned-network-warp-unconfirmed")
	errOwnedNetworkUDP     = errors.New("owned-network-udp-unconfirmed")
	errOwnedNetworkStopped = errors.New("owned-network-window-canceled")
)

// All input is trusted worker configuration. The caller separately proves the
// process and listener owner; this worker never grants authority from an address.
// Validation is complete before any socket, entropy read, or HTTP request.
func validateOwnedNetworkRequest(request OwnedNetworkRequest) error {
	if _, err := ownedLoopbackSOCKS(request.SOCKSAddress); err != nil || len(request.Services) > 8 || request.Timeout < 0 || request.Timeout > 20*time.Second {
		return errOwnedNetworkRequest
	}
	ids := make(map[string]bool, len(request.Services))
	for _, service := range request.Services {
		if !ownedServiceID(service.ID) || ids[service.ID] {
			return errOwnedNetworkRequest
		}
		ids[service.ID] = true
		if _, err := validateOwnedNetworkHTTPS(service.URL); err != nil {
			return errOwnedNetworkRequest
		}
	}
	if request.UDP != nil && !ownedPublicTarget(request.UDP.Target) {
		return errOwnedNetworkRequest
	}
	return nil
}

func ownedServiceID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func ownedLoopbackSOCKS(raw string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(raw)
	if err != nil || endpoint.Port() == 0 || !endpoint.Addr().IsLoopback() || endpoint.Addr().Is4In6() || endpoint.Addr().Zone() != "" || endpoint.String() != raw {
		return netip.AddrPort{}, errOwnedNetworkRequest
	}
	return endpoint, nil
}

func ownedPublicTarget(target netip.AddrPort) bool {
	return target.IsValid() && target.Port() != 0 && !target.Addr().Is4In6() && publicfetch.PublicAddress(target.Addr())
}

func validateOwnedNetworkHTTPS(raw string) (*url.URL, error) {
	if len(raw) > 2048 || publicfetch.ValidateURL(raw) != nil {
		return nil, errOwnedNetworkRequest
	}
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errOwnedNetworkRequest
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, suffix := range []string{".internal", ".home", ".corp", ".onion", ".invalid", ".test"} {
		if strings.HasSuffix(host, suffix) {
			return nil, errOwnedNetworkRequest
		}
	}
	if literal, err := netip.ParseAddr(u.Hostname()); err == nil && (literal.Is4In6() || literal.Zone() != "" || literal.String() != u.Hostname()) {
		return nil, errOwnedNetworkRequest
	}
	return u, nil
}

func probeOwnedNetwork(parent context.Context, request OwnedNetworkRequest) (OwnedApplicationProof, error) {
	var proof OwnedApplicationProof
	request.Services = append([]OwnedServiceProbe(nil), request.Services...)
	if request.UDP != nil {
		udp := *request.UDP
		request.UDP = &udp
	}
	if err := validateOwnedNetworkRequest(request); err != nil {
		return proof, err
	}
	if parent == nil {
		return proof, errOwnedNetworkRequest
	}
	if parent.Err() != nil {
		return proof, errOwnedNetworkStopped
	}
	if err := checkOwnedNetworkTargets(parent, request); err != nil {
		return proof, err
	}
	timeout := request.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	sockets := &probeSockets{}
	defer sockets.close()
	stop := context.AfterFunc(ctx, sockets.close)
	defer stop()
	proxy, _ := ownedLoopbackSOCKS(request.SOCKSAddress)
	dnsTransport := ownedDoHTransport(proxy, sockets, timeout)
	defer dnsTransport.CloseIdleConnections()
	dnsClient := &http.Client{Transport: dnsTransport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resolve := func(resolveCtx context.Context, host string) ([]netip.Addr, error) {
		return ownedResolvePublic(resolveCtx, host, func(exchangeCtx context.Context, query []byte) ([]byte, error) {
			response, err := ownedDoHExchange(exchangeCtx, dnsClient, query)
			if err != nil {
				return nil, err
			}
			if err := checkOwnedDNSProbeAnswer(exchangeCtx, query, response); err != nil {
				return nil, err
			}
			return response, nil
		})
	}
	transport := ownedHTTPTransport(proxy, sockets, timeout, resolve)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, err := ownedHTTPSBody(ctx, client, ownedWarpTraceURL, "", ownedTraceBodyLimit, true)
	if err != nil {
		return proof, ownedNetworkFailure(ctx, ownedProbeTargetFailure(errOwnedNetworkTrace, err))
	}
	proof, err = parseOwnedWarpTrace(body)
	clear(body)
	if err != nil {
		return OwnedApplicationProof{}, errOwnedNetworkTrace
	}
	for _, service := range request.Services {
		challenge := ""
		limit := ownedServiceBodyLimit
		if service.Challenge {
			var nonce [32]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return OwnedApplicationProof{}, errOwnedNetworkHTTP
			}
			challenge, limit = hex.EncodeToString(nonce[:]), 256
		}
		response, err := ownedHTTPSResponse(ctx, client, service.URL, challenge, limit, service.Challenge, !service.Challenge)
		if err != nil {
			return OwnedApplicationProof{}, ownedNetworkFailure(ctx, ownedProbeTargetFailure(errOwnedNetworkHTTP, err))
		}
		if err := validateOwnedServiceResponse(ctx, service, challenge, response); err != nil {
			return OwnedApplicationProof{}, ownedNetworkFailure(ctx, errOwnedNetworkService)
		}
		recordOwnedServiceProof(&proof, service)
	}
	if request.UDP != nil {
		if err := probeOwnedSOCKSUDP(ctx, proxy, request.UDP.Target, sockets); err != nil {
			return OwnedApplicationProof{}, ownedNetworkFailure(ctx, ownedProbeTargetFailure(errOwnedNetworkUDP, err))
		}
		proof.UDPConfirmed = true
	}
	if ctx.Err() != nil {
		return OwnedApplicationProof{}, errOwnedNetworkStopped
	}
	if err := checkOwnedNetworkTargets(ctx, request); err != nil {
		return OwnedApplicationProof{}, err
	}
	return proof, nil
}

type ownedOperationContextKey struct{}

// Transport detaches dial cancellation/deadlines from Request.Context while
// preserving values. Carry this request's actual bounded operation separately;
// in particular each DNS exchange must replace any outer operation value.
func ownedOperationRequestContext(parent context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	operation, cancel := context.WithTimeout(parent, limit)
	return context.WithValue(operation, ownedOperationContextKey{}, operation), cancel
}

func ownedOperationDialContext(dial context.Context) (context.Context, error) {
	if dial == nil || dial.Err() != nil {
		return nil, errOwnedNetworkStopped
	}
	operation, ok := dial.Value(ownedOperationContextKey{}).(context.Context)
	if !ok || operation == nil || operation.Err() != nil {
		return nil, errOwnedNetworkStopped
	}
	if _, bounded := operation.Deadline(); !bounded {
		return nil, errOwnedNetworkStopped
	}
	return operation, nil
}

func ownedHTTPTransport(proxy netip.AddrPort, sockets *probeSockets, timeout time.Duration, resolve func(context.Context, string) ([]netip.Addr, error)) *http.Transport {
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 1, ForceAttemptHTTP2: true,
		DialContext: func(dialCtx context.Context, network, target string) (net.Conn, error) {
			operation, err := ownedOperationDialContext(dialCtx)
			if err != nil || network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errOwnedNetworkHTTP
			}
			// The HTTP URL remains unchanged, so TLS verifies its original
			// hostname while SOCKS sees only an independently checked literal.
			return ownedDialPublic(operation, proxy, target, sockets, resolve, ownedSOCKSCommand)
		},
	}
}

// Bootstrap uses one fixed public literal through the same owned SOCKS path;
// it never asks the local/system resolver to resolve the DoH hostname.
func ownedDoHTransport(proxy netip.AddrPort, sockets *probeSockets, timeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "cloudflare-dns.com"},
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 1, ForceAttemptHTTP2: true,
		DialContext: func(dialCtx context.Context, network, target string) (net.Conn, error) {
			operation, err := ownedOperationDialContext(dialCtx)
			if err != nil || (network != "tcp" && network != "tcp4" && network != "tcp6") || target != "cloudflare-dns.com:443" {
				return nil, errOwnedNetworkDNS
			}
			return ownedDialDoH(operation, proxy, sockets, ownedSOCKSCommand)
		},
	}
}

func ownedDialDoH(ctx context.Context, proxy netip.AddrPort, sockets *probeSockets, connect func(context.Context, netip.AddrPort, byte, []byte, *probeSockets) (net.Conn, []byte, error)) (net.Conn, error) {
	pins := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	if connect == nil {
		return nil, errOwnedNetworkDNS
	}
	if err := checkOwnedProbeTarget(ctx, "cloudflare-dns.com", pins); err != nil {
		return nil, ownedProbeTargetFailure(errOwnedNetworkDNS, err)
	}
	address, _ := ownedSOCKSAddress(pins[0].String(), 443)
	connection, _, err := connect(ctx, proxy, 1, address, sockets)
	if err == nil && connection != nil {
		err = checkOwnedProbeTarget(ctx, "cloudflare-dns.com", pins)
	}
	if err != nil || connection == nil {
		if connection != nil {
			connection.Close()
		}
		return nil, ownedProbeTargetFailure(errOwnedNetworkDNS, err)
	}
	return connection, nil
}

func ownedDoHExchange(ctx context.Context, client *http.Client, query []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || client == nil || len(query) < 12 || len(query) > ownedDoHBodyLimit {
		return nil, errOwnedNetworkDNS
	}
	ctx, cancel := ownedOperationRequestContext(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, ownedDoHURL, bytes.NewReader(query))
	if err != nil {
		return nil, errOwnedNetworkDNS
	}
	request.Close = true
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Cache-Control", "no-cache, no-store")
	response, err := client.Do(request)
	if err != nil {
		return nil, ownedProbeTargetFailure(errOwnedNetworkDNS, err)
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || response.ContentLength > ownedDoHBodyLimit || mediaErr != nil || mediaType != "application/dns-message" || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return nil, errOwnedNetworkDNS
	}
	answer, err := io.ReadAll(io.LimitReader(response.Body, ownedDoHBodyLimit+1))
	if err != nil || len(answer) > ownedDoHBodyLimit || ctx.Err() != nil {
		clear(answer)
		return nil, errOwnedNetworkDNS
	}
	return answer, nil
}

func ownedDialPublic(ctx context.Context, proxy netip.AddrPort, target string, sockets *probeSockets, resolve func(context.Context, string) ([]netip.Addr, error), connect func(context.Context, netip.AddrPort, byte, []byte, *probeSockets) (net.Conn, []byte, error)) (net.Conn, error) {
	if ctx == nil || ctx.Err() != nil || connect == nil {
		return nil, errOwnedNetworkHTTP
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || port != "443" {
		return nil, errOwnedNetworkHTTP
	}
	if _, err := validateOwnedNetworkHTTPS("https://" + net.JoinHostPort(host, port) + "/"); err != nil {
		return nil, errOwnedNetworkHTTP
	}
	var addresses []netip.Addr
	reviewHost := host
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
		reviewHost = ""
	} else {
		if err := checkOwnedProbeTarget(ctx, host, nil); err != nil {
			return nil, ownedProbeTargetFailure(errOwnedNetworkHTTP, err)
		}
		if resolve == nil {
			return nil, errOwnedNetworkDNS
		}
		addresses, err = resolve(ctx, host)
		if err != nil {
			return nil, ownedProbeTargetFailure(errOwnedNetworkDNS, err)
		}
		addresses = append([]netip.Addr(nil), addresses...)
	}
	if len(addresses) == 0 || len(addresses) > 32 {
		return nil, errOwnedNetworkDNS
	}
	for _, address := range addresses {
		if address.Is4In6() || address.Zone() != "" || !ownedPublicAddress(address) {
			return nil, errOwnedNetworkDNS
		}
	}
	if ctx.Err() != nil {
		return nil, errOwnedNetworkDNS
	}
	if err := checkOwnedProbeTarget(ctx, reviewHost, addresses); err != nil {
		return nil, ownedProbeTargetFailure(errOwnedNetworkHTTP, err)
	}
	// One checked destination, one CONNECT. No second name resolution or
	// fallback after a failed connection can move this request to another peer.
	address, err := ownedSOCKSAddress(addresses[0].String(), 443)
	if err != nil {
		return nil, errOwnedNetworkDNS
	}
	if err := checkOwnedProbeTarget(ctx, reviewHost, []netip.Addr{addresses[0]}); err != nil {
		return nil, ownedProbeTargetFailure(errOwnedNetworkHTTP, err)
	}
	connection, _, err := connect(ctx, proxy, 1, address, sockets)
	if err == nil && ctx.Err() == nil && connection != nil {
		err = checkOwnedProbeTarget(ctx, reviewHost, addresses)
	}
	if err != nil || ctx.Err() != nil || connection == nil {
		if connection != nil {
			connection.Close()
		}
		return nil, ownedProbeTargetFailure(errOwnedNetworkHTTP, err)
	}
	return connection, nil
}

func ownedNetworkFailure(ctx context.Context, otherwise error) error {
	if ctx.Err() != nil {
		return errOwnedNetworkStopped
	}
	return otherwise
}

func ownedHTTPSBody(ctx context.Context, client *http.Client, raw, challenge string, limit int, requireOK bool) ([]byte, error) {
	response, err := ownedHTTPSResponse(ctx, client, raw, challenge, limit, requireOK, false)
	if err != nil {
		return nil, ownedProbeTargetFailure(errOwnedNetworkHTTP, err)
	}
	return []byte(response.Body), nil
}

func parseOwnedWarpTrace(body []byte) (OwnedApplicationProof, error) {
	var proof OwnedApplicationProof
	if len(body) == 0 || len(body) > ownedTraceBodyLimit {
		return proof, errOwnedNetworkTrace
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || len(line) > 1024 {
			return proof, errOwnedNetworkTrace
		}
		switch key {
		case "warp", "colo", "loc", "ip":
			if _, duplicate := values[key]; duplicate {
				return proof, errOwnedNetworkTrace
			}
			values[key] = value
		}
	}
	if values["warp"] != "on" && values["warp"] != "plus" {
		return proof, errOwnedNetworkTrace
	}
	proof.Warp = values["warp"]
	if coloPattern.MatchString(values["colo"]) {
		proof.Colo = values["colo"]
	}
	if locPattern.MatchString(values["loc"]) {
		proof.Loc = values["loc"]
	}
	if ip, err := netip.ParseAddr(values["ip"]); err == nil && !ip.Is4In6() && publicfetch.PublicAddress(ip) && ip.String() == values["ip"] {
		proof.EgressIP = ip.String()
	}
	return proof, nil
}

func ownedSOCKSAddress(host string, port uint16) ([]byte, error) {
	if port == 0 {
		return nil, errOwnedNetworkRequest
	}
	var address []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4In6() || ip.Zone() != "" {
			return nil, errOwnedNetworkRequest
		}
		if ip.Is4() {
			address = append([]byte{1}, ip.AsSlice()...)
		} else {
			address = append([]byte{4}, ip.AsSlice()...)
		}
	} else {
		return nil, errOwnedNetworkRequest
	}
	return binary.BigEndian.AppendUint16(address, port), nil
}

// A reply address is parsed as bytes, with domain names never resolved here.
func readOwnedSOCKSReply(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil || header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, errOwnedNetworkHTTP
	}
	address := []byte{header[3]}
	size := 0
	switch header[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil || length[0] == 0 {
			return nil, errOwnedNetworkHTTP
		}
		address = append(address, length[0])
		size = int(length[0])
	default:
		return nil, errOwnedNetworkHTTP
	}
	data := make([]byte, size+2)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, errOwnedNetworkHTTP
	}
	return append(address, data...), nil
}

func ownedSOCKSCommand(ctx context.Context, proxy netip.AddrPort, command byte, address []byte, sockets *probeSockets) (net.Conn, []byte, error) {
	if ctx == nil || ctx.Err() != nil || sockets == nil {
		return nil, nil, errOwnedNetworkHTTP
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !deadline.After(time.Now()) {
		return nil, nil, errOwnedNetworkHTTP
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy.String())
	if err != nil {
		return nil, nil, errOwnedNetworkHTTP
	}
	if !sockets.retain(connection) {
		return nil, nil, errOwnedNetworkHTTP
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	fail := func() (net.Conn, []byte, error) {
		connection.Close()
		return nil, nil, errOwnedNetworkHTTP
	}
	if connection.SetDeadline(deadline) != nil {
		return fail()
	}
	if written, err := connection.Write([]byte{5, 1, 0}); err != nil || written != 3 {
		return fail()
	}
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		return fail()
	}
	packet := append([]byte{5, command, 0}, address...)
	if written, err := connection.Write(packet); err != nil || written != len(packet) {
		return fail()
	}
	reply, err := readOwnedSOCKSReply(connection)
	if err != nil || ctx.Err() != nil {
		return fail()
	}
	return connection, reply, nil
}

func ownedSOCKSLiteral(address []byte) (netip.AddrPort, error) {
	if len(address) == 7 && address[0] == 1 {
		var ip [4]byte
		copy(ip[:], address[1:5])
		return netip.AddrPortFrom(netip.AddrFrom4(ip), binary.BigEndian.Uint16(address[5:])), nil
	}
	if len(address) == 19 && address[0] == 4 {
		var ip [16]byte
		copy(ip[:], address[1:17])
		endpoint := netip.AddrPortFrom(netip.AddrFrom16(ip), binary.BigEndian.Uint16(address[17:]))
		if !endpoint.Addr().Is4In6() {
			return endpoint, nil
		}
	}
	return netip.AddrPort{}, errOwnedNetworkUDP
}

func validateOwnedUDPReply(packet []byte, target netip.AddrPort, expected []byte) error {
	if !ownedPublicTarget(target) || len(expected) == 0 || len(expected) > 256 || len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return errOwnedNetworkUDP
	}
	size := 7
	if packet[3] == 4 {
		size = 19
	}
	if len(packet) != 3+size+len(expected) {
		return errOwnedNetworkUDP
	}
	peer, err := ownedSOCKSLiteral(packet[3 : 3+size])
	if err != nil || peer != target || string(packet[3+size:]) != string(expected) {
		return errOwnedNetworkUDP
	}
	return nil
}

func validateOwnedUDPRelay(address []byte, proxy netip.AddrPort) (netip.AddrPort, error) {
	relay, err := ownedSOCKSLiteral(address)
	if err != nil || !relay.Addr().IsLoopback() || relay.Port() == 0 || relay != proxy {
		return netip.AddrPort{}, errOwnedNetworkUDP
	}
	return relay, nil
}

func probeOwnedSOCKSUDP(ctx context.Context, proxy, target netip.AddrPort, sockets *probeSockets) error {
	if !ownedPublicTarget(target) || sockets == nil {
		return errOwnedNetworkUDP
	}
	pins := []netip.Addr{target.Addr()}
	if err := checkOwnedProbeTarget(ctx, "", pins); err != nil {
		return ownedProbeTargetFailure(errOwnedNetworkUDP, err)
	}
	network := "udp4"
	if proxy.Addr().Is6() {
		network = "udp6"
	}
	udp, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(proxy.Addr(), 0)))
	if err != nil {
		return errOwnedNetworkUDP
	}
	defer udp.Close()
	if !sockets.retain(udp) {
		return errOwnedNetworkUDP
	}
	deadline, ok := ctx.Deadline()
	if !ok || udp.SetDeadline(deadline) != nil {
		return errOwnedNetworkUDP
	}
	local := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	address, _ := ownedSOCKSAddress(local.Addr().String(), local.Port())
	if err := checkOwnedProbeTarget(ctx, "", pins); err != nil {
		return ownedProbeTargetFailure(errOwnedNetworkUDP, err)
	}
	control, reply, err := ownedSOCKSCommand(ctx, proxy, 3, address, sockets)
	if err != nil {
		return errOwnedNetworkUDP
	}
	defer control.Close()
	relay, err := validateOwnedUDPRelay(reply, proxy)
	if err != nil {
		return errOwnedNetworkUDP
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errOwnedNetworkUDP
	}
	expected := []byte(TransportChallengeResponse(hex.EncodeToString(nonce[:])))
	targetAddress, err := ownedSOCKSAddress(target.Addr().String(), target.Port())
	if err != nil {
		return errOwnedNetworkUDP
	}
	packet := append(append([]byte{0, 0, 0}, targetAddress...), expected...)
	if err := checkOwnedProbeTarget(ctx, "", pins); err != nil {
		return ownedProbeTargetFailure(errOwnedNetworkUDP, err)
	}
	if written, err := udp.WriteToUDPAddrPort(packet, relay); err != nil || written != len(packet) {
		return errOwnedNetworkUDP
	}
	var response [512]byte
	n, source, err := udp.ReadFromUDPAddrPort(response[:])
	if err != nil || source != relay || ctx.Err() != nil {
		return errOwnedNetworkUDP
	}
	if err := checkOwnedProbeTarget(ctx, "", pins); err != nil {
		return ownedProbeTargetFailure(errOwnedNetworkUDP, err)
	}
	return validateOwnedUDPReply(response[:n], target, expected)
}
