package usquediag

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const TransportChallengeHeader = "Razvilka-Transport-Challenge"
const transportProofPrefix = "razvilka-transport-proof-v1:"

var ErrTransportProbe = errors.New("native transport probe failed; no WARP account or tunnel was verified")
var ErrTransportProbeDisabled = errors.New("native transport probe requires explicit trusted opt-in")

// TransportProbeOptions is trusted harness configuration, never an HTTP input
// or source URL. The exact socket address is pinned independently from TLS SNI.
// Loopback is permitted only by explicit opt-in for a controllable local server.
type TransportProbeOptions struct {
	Enabled       bool
	AllowLoopback bool
	URL           string
	Endpoint      netip.AddrPort
	Transport     string // HTTP/2 or HTTP/3; never auto/fallback.
	RootCAs       *x509.CertPool
	Environment   func(context.Context) (string, error)
	Timeout       time.Duration
}

// TransportProbeEvidence deliberately differs from CanaryEvidence. Even a
// successful local H3 proof cannot claim WARP, MASQUE CONNECT-UDP, route/service
// reachability, generic UDP forwarding, or permission to apply a profile.
type TransportProbeEvidence struct {
	Transport     string    `json:"transport"`
	Endpoint      string    `json:"endpoint"`
	EnvironmentID string    `json:"environment_id"`
	CheckedAt     time.Time `json:"checked_at"`
	ValidUntil    time.Time `json:"valid_until"`
	HTTP2         bool      `json:"http2_confirmed"`
	HTTP3         bool      `json:"http3_confirmed"`
	QUICUDP       bool      `json:"quic_udp_confirmed"`
	ReasonCode    string    `json:"reason_code"`
	verified      bool
	seal          string
}

func (e TransportProbeEvidence) Fresh(now time.Time, endpoint netip.AddrPort, environmentID string) bool {
	return e.verified && e.seal == transportEvidenceSeal(e) && e.Endpoint == endpoint.String() && e.EnvironmentID == environmentID &&
		!e.CheckedAt.After(now) && now.Before(e.ValidUntil) && e.ValidUntil.Sub(e.CheckedAt) <= MaxCanaryAge
}

func transportEvidenceSeal(e TransportProbeEvidence) string {
	data, _ := json.Marshal(e)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TransportChallengeResponse is the entire response expected from the local
// controllable test server. No remote body is exposed in evidence or errors.
func TransportChallengeResponse(challenge string) string {
	data, err := hex.DecodeString(challenge)
	if err != nil || len(data) != 32 || hex.EncodeToString(data) != challenge {
		return ""
	}
	return transportProofPrefix + challenge
}

type probeSockets struct {
	mu          sync.Mutex
	closed      bool
	connections []net.Conn
}

func (s *probeSockets) retain(connection net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		connection.Close()
		return false
	}
	s.connections = append(s.connections, connection)
	return true
}

func (s *probeSockets) close() {
	s.mu.Lock()
	s.closed = true
	connections := s.connections
	s.connections = nil
	s.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
}

func validateTransportProbe(options TransportProbeOptions) (*url.URL, error) {
	if !options.Enabled {
		return nil, ErrTransportProbeDisabled
	}
	u, err := url.Parse(options.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || !options.Endpoint.IsValid() || options.Endpoint.Port() == 0 || options.Endpoint.Addr().Is4In6() || options.Endpoint.Addr().Zone() != "" || options.Environment == nil || (options.Transport != "HTTP/2" && options.Transport != "HTTP/3") || options.Timeout < 0 || options.Timeout > 20*time.Second {
		return nil, ErrTransportProbe
	}
	address := options.Endpoint.Addr()
	if address.IsLoopback() {
		if !options.AllowLoopback {
			return nil, ErrTransportProbe
		}
	} else if !publicfetch.PublicAddress(address) {
		return nil, ErrTransportProbe
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if port != strconv.Itoa(int(options.Endpoint.Port())) {
		return nil, ErrTransportProbe
	}
	return u, nil
}

// ProbeNativeTransport performs one bounded GET over exactly one TLS-verified
// protocol and literal endpoint. It has no DNS, proxy, redirect, fallback,
// registration, profile export or route mutation capability.
func ProbeNativeTransport(ctx context.Context, options TransportProbeOptions) (TransportProbeEvidence, error) {
	result := TransportProbeEvidence{ReasonCode: "probe-not-confirmed"}
	u, err := validateTransportProbe(options)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	environmentID, err := options.Environment(ctx)
	if err != nil || !canaryDigest(environmentID) {
		return result, ErrTransportProbe
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return result, ErrTransportProbe
	}
	challenge := hex.EncodeToString(nonce[:])
	tlsConfig := &tls.Config{ServerName: u.Hostname(), RootCAs: options.RootCAs, MinVersion: tls.VersionTLS12}
	var transport http.RoundTripper
	if options.Transport == "HTTP/2" {
		sockets := &probeSockets{}
		defer sockets.close()
		tlsConfig.NextProtos = []string{"h2"}
		h2 := &http2.Transport{TLSClientConfig: tlsConfig, DisableCompression: true, MaxHeaderListSize: 8192,
			DialTLSContext: func(dialCtx context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
				connection, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp", options.Endpoint.String())
				if err != nil {
					return nil, err
				}
				if !sockets.retain(connection) {
					return nil, ErrTransportProbe
				}
				secure := tls.Client(connection, cfg)
				if err := secure.HandshakeContext(dialCtx); err != nil {
					connection.Close()
					return nil, err
				}
				return secure, nil
			}}
		transport = h2
		defer h2.CloseIdleConnections()
	} else {
		tlsConfig.MinVersion, tlsConfig.NextProtos = tls.VersionTLS13, []string{http3.NextProtoH3}
		network, local := "udp4", "0.0.0.0:0"
		if options.Endpoint.Addr().Is6() {
			network, local = "udp6", "[::]:0"
		}
		conn, err := net.ListenPacket(network, local)
		if err != nil {
			return result, ErrTransportProbe
		}
		defer conn.Close()
		quicTransport := &quic.Transport{Conn: conn}
		defer quicTransport.Close()
		h3 := &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: &quic.Config{HandshakeIdleTimeout: timeout, MaxIdleTimeout: timeout}, DisableCompression: true, MaxResponseHeaderBytes: 8192,
			Dial: func(dialCtx context.Context, _ string, cfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
				return quicTransport.Dial(dialCtx, net.UDPAddrFromAddrPort(options.Endpoint), cfg, qc)
			}}
		transport = h3
		defer h3.Close()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return result, ErrTransportProbe
	}
	request.Header.Set(TransportChallengeHeader, challenge)
	request.Close = true
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, ErrTransportProbe
	}
	defer response.Body.Close()
	expectedProto, expectedALPN := 2, "h2"
	if options.Transport == "HTTP/3" {
		expectedProto, expectedALPN = 3, http3.NextProtoH3
	}
	if response.StatusCode != http.StatusOK || response.ProtoMajor != expectedProto || response.TLS == nil || response.TLS.NegotiatedProtocol != expectedALPN || len(response.TLS.VerifiedChains) == 0 {
		return result, ErrTransportProbe
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 257))
	if err != nil || len(body) > 256 || string(body) != TransportChallengeResponse(challenge) {
		return result, ErrTransportProbe
	}
	current, err := options.Environment(ctx)
	if err != nil || current != environmentID || ctx.Err() != nil {
		return result, ErrTransportProbe
	}
	now := time.Now().UTC()
	result = TransportProbeEvidence{Transport: options.Transport, Endpoint: options.Endpoint.String(), EnvironmentID: environmentID, CheckedAt: now, ValidUntil: now.Add(MaxCanaryAge), ReasonCode: "exact-native-transport-confirmed", verified: true}
	if expectedProto == 2 {
		result.HTTP2 = true
	} else {
		result.HTTP3, result.QUICUDP = true, true
	}
	result.seal = transportEvidenceSeal(result)
	return result, nil
}
