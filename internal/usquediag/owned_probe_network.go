package usquediag

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
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
const ownedServiceBodyLimit = 16 << 10

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
	if err := validateOwnedNetworkRequest(request); err != nil {
		return proof, err
	}
	if parent == nil {
		return proof, errOwnedNetworkRequest
	}
	if parent.Err() != nil {
		return proof, errOwnedNetworkStopped
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
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 1, ForceAttemptHTTP2: true,
		DialContext: func(dialCtx context.Context, network, target string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errOwnedNetworkHTTP
			}
			host, port, err := net.SplitHostPort(target)
			if err != nil || port != "443" {
				return nil, errOwnedNetworkHTTP
			}
			if _, err := validateOwnedNetworkHTTPS("https://" + net.JoinHostPort(host, port) + "/"); err != nil {
				return nil, errOwnedNetworkHTTP
			}
			address, err := ownedSOCKSAddress(host, 443)
			if err != nil {
				return nil, errOwnedNetworkHTTP
			}
			connection, _, err := ownedSOCKSCommand(dialCtx, proxy, 1, address, sockets)
			return connection, err
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, err := ownedHTTPSBody(ctx, client, ownedWarpTraceURL, "", ownedTraceBodyLimit, true)
	if err != nil {
		return proof, ownedNetworkFailure(ctx, errOwnedNetworkTrace)
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
		body, err := ownedHTTPSBody(ctx, client, service.URL, challenge, limit, service.Challenge)
		if err != nil || challenge != "" && string(body) != TransportChallengeResponse(challenge) {
			clear(body)
			return OwnedApplicationProof{}, ownedNetworkFailure(ctx, errOwnedNetworkHTTP)
		}
		clear(body)
		proof.ConfirmedRoutes = append(proof.ConfirmedRoutes, service.ID)
	}
	if request.UDP != nil {
		if err := probeOwnedSOCKSUDP(ctx, proxy, request.UDP.Target, sockets); err != nil {
			return OwnedApplicationProof{}, ownedNetworkFailure(ctx, errOwnedNetworkUDP)
		}
		proof.UDPConfirmed = true
	}
	if ctx.Err() != nil {
		return OwnedApplicationProof{}, errOwnedNetworkStopped
	}
	return proof, nil
}

func ownedNetworkFailure(ctx context.Context, otherwise error) error {
	if ctx.Err() != nil {
		return errOwnedNetworkStopped
	}
	return otherwise
}

func ownedHTTPSBody(ctx context.Context, client *http.Client, raw, challenge string, limit int, requireOK bool) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, errOwnedNetworkHTTP
	}
	request.Close = true
	request.Header.Set("User-Agent", "RAZVILKA-Owned-USQUE-Probe/1")
	if challenge != "" {
		request.Header.Set(TransportChallengeHeader, challenge)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errOwnedNetworkHTTP
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 || requireOK && response.StatusCode != http.StatusOK || response.ContentLength > int64(limit) || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return nil, errOwnedNetworkHTTP
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(body) > limit || ctx.Err() != nil {
		clear(body)
		return nil, errOwnedNetworkHTTP
	}
	return body, nil
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
		if len(host) == 0 || len(host) > 253 {
			return nil, errOwnedNetworkRequest
		}
		address = append([]byte{3, byte(len(host))}, host...)
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
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy.String())
	if err != nil {
		return nil, nil, errOwnedNetworkHTTP
	}
	if !sockets.retain(connection) {
		return nil, nil, errOwnedNetworkHTTP
	}
	fail := func() (net.Conn, []byte, error) {
		connection.Close()
		return nil, nil, errOwnedNetworkHTTP
	}
	deadline, ok := ctx.Deadline()
	if !ok || connection.SetDeadline(deadline) != nil {
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
	if written, err := udp.WriteToUDPAddrPort(packet, relay); err != nil || written != len(packet) {
		return errOwnedNetworkUDP
	}
	var response [512]byte
	n, source, err := udp.ReadFromUDPAddrPort(response[:])
	if err != nil || source != relay || ctx.Err() != nil {
		return errOwnedNetworkUDP
	}
	return validateOwnedUDPReply(response[:n], target, expected)
}
