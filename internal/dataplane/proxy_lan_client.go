package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const nodeLANHTTPSDeadline = 15 * time.Second

// NodeLANHTTPSRequest is ephemeral router-issued intent for a one-shot probe
// run on an actual LAN client. Neither identifier grants runtime authority.
// The collector must join this artifact with its own nonce, current runtime,
// selected/control flow and independent egress evidence.
type NodeLANHTTPSRequest struct {
	RuntimeID   string     `json:"runtime_id"`
	Challenge   string     `json:"challenge"`
	URL         string     `json:"url"`
	Source      netip.Addr `json:"source"`
	Destination netip.Addr `json:"destination"`
}

// NodeLANHTTPSResult records only this client's local HTTPS connection. It is
// not NodeTUNObservation, a router path proof, or an egress measurement.
// BodySHA256 covers only the bounded accepted sample, not the complete page.
type NodeLANHTTPSResult struct {
	RuntimeID       string         `json:"runtime_id"`
	Challenge       string         `json:"challenge"`
	URL             string         `json:"url"`
	Source          netip.AddrPort `json:"source"`
	Destination     netip.AddrPort `json:"destination"`
	Interface       string         `json:"interface"`
	InterfaceIndex  int            `json:"interface_index"`
	StartedAt       time.Time      `json:"started_at"`
	FinishedAt      time.Time      `json:"finished_at"`
	HTTPStatus      int            `json:"http_status"`
	ServiceAccepted bool           `json:"service_accepted"`
	BodySHA256      string         `json:"body_sha256,omitempty"`
	BodyBytes       int            `json:"body_bytes"`
}

// RunNodeLANHTTPSProbe performs one source-bound HTTPS request from this client.
// Production has no proxy, alternate destination, TLS bypass or test options.
func RunNodeLANHTTPSProbe(ctx context.Context, request NodeLANHTTPSRequest) (NodeLANHTTPSResult, error) {
	return runNodeLANHTTPSProbe(ctx, request, nodeLANHTTPSOptions{})
}

// Per-call fixtures may map a public literal to a local TLS server. There are
// no package-global hooks, and the exported entry point always uses OS sources,
// net.Dialer and verified system certificate roots.
type nodeLANHTTPSOptions struct {
	interfaces func() ([]net.Interface, error)
	addresses  func(net.Interface) ([]net.Addr, error)
	dial       func(context.Context, *net.Dialer, string, string) (net.Conn, error)
	roots      *x509.CertPool
}

func runNodeLANHTTPSProbe(ctx context.Context, request NodeLANHTTPSRequest, options nodeLANHTTPSOptions) (NodeLANHTTPSResult, error) {
	if ctx == nil {
		return NodeLANHTTPSResult{}, errors.New("LAN HTTPS probe context is required")
	}
	if err := ctx.Err(); err != nil {
		return NodeLANHTTPSResult{}, err
	}
	if !nodeLANHash(request.RuntimeID) || !nodeLANHash(request.Challenge) || len(request.URL) > 4096 || publicfetch.ValidateURL(request.URL) != nil {
		return NodeLANHTTPSResult{}, errors.New("LAN HTTPS probe requires exact runtime/challenge hashes and original public HTTPS URL")
	}
	if request.Destination.Is4In6() || !publicfetch.PublicAddress(request.Destination) || !nodeLANSourceAddress(request.Source) || request.Source.Is4() != request.Destination.Is4() {
		return NodeLANHTTPSResult{}, errors.New("LAN HTTPS probe requires a public pin and explicit matching local source")
	}
	origin, _ := url.Parse(request.URL)
	if literal, err := netip.ParseAddr(origin.Hostname()); err == nil && literal != request.Destination {
		return NodeLANHTTPSResult{}, errors.New("LAN HTTPS pin differs from its literal URL")
	}
	probeCtx, cancel := context.WithTimeout(ctx, nodeLANHTTPSDeadline)
	defer cancel()
	iface, err := nodeLANAssignedSource(probeCtx, request.Source, options)
	if err != nil {
		return NodeLANHTTPSResult{}, err
	}
	result := NodeLANHTTPSResult{
		RuntimeID: request.RuntimeID, Challenge: request.Challenge, URL: request.URL,
		Interface: iface.Name, InterfaceIndex: iface.Index, StartedAt: time.Now().UTC(),
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(request.Source.AsSlice())}}
	dial := options.dial
	if dial == nil {
		dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
			return d.DialContext(ctx, network, target)
		}
	}
	var mu sync.Mutex
	var source, destination netip.AddrPort
	dialed := false
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.roots, ServerName: origin.Hostname()},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 1,
		DialContext: func(_ context.Context, network, target string) (net.Conn, error) {
			if err := probeCtx.Err(); err != nil {
				return nil, err
			}
			host, port, err := net.SplitHostPort(target)
			if err != nil || !samePinnedServiceHost(host, origin.Hostname()) || port != "443" || network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errors.New("LAN HTTPS transport target changed")
			}
			mu.Lock()
			if dialed {
				mu.Unlock()
				return nil, errors.New("LAN HTTPS probe cannot retry another connection")
			}
			dialed = true
			mu.Unlock()
			family := "tcp4"
			if request.Destination.Is6() {
				family = "tcp6"
			}
			// net/http may detach its dial context from request cancellation to
			// reuse a connection. This dedicated one-shot dial stays bound to
			// the caller's probe context and its shorter connect deadline.
			dialCtx, stopDial := context.WithTimeout(probeCtx, dialer.Timeout)
			defer stopDial()
			conn, err := dial(dialCtx, dialer, family, net.JoinHostPort(request.Destination.String(), "443"))
			if err != nil {
				return nil, errors.New("LAN HTTPS source-bound connection failed")
			}
			actualSource, sourceOK := nodeLANTCPEndpoint(conn.LocalAddr())
			actualDestination, destinationOK := nodeLANTCPEndpoint(conn.RemoteAddr())
			if !sourceOK || !destinationOK || actualSource.Addr() != request.Source || actualDestination != netip.AddrPortFrom(request.Destination, 443) {
				_ = conn.Close()
				return nil, errors.New("LAN HTTPS connection differs from its source or pin")
			}
			mu.Lock()
			source, destination = actualSource, actualDestination
			mu.Unlock()
			// Keep the connected socket cancellation-bound during TLS too;
			// net/http may also use its detached context for the handshake.
			context.AfterFunc(probeCtx, func() { _ = conn.Close() })
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: nodeLANHTTPSDeadline, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	httpRequest, err := http.NewRequestWithContext(probeCtx, http.MethodGet, request.URL, nil)
	if err != nil {
		return result, errors.New("LAN HTTPS request is invalid")
	}
	httpRequest.Header.Set("User-Agent", "RAZVILKA-LAN-Check/1")
	response, err := client.Do(httpRequest)
	mu.Lock()
	result.Source, result.Destination = source, destination
	mu.Unlock()
	finish := func() { result.FinishedAt = time.Now().UTC() }
	if err != nil {
		finish()
		if probeCtx.Err() != nil {
			return result, probeCtx.Err()
		}
		return result, errors.New("LAN HTTPS request failed")
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	body, err := strictServiceResponse(request.URL, response)
	defer clear(body)
	finish()
	if probeCtx.Err() != nil {
		return result, probeCtx.Err()
	}
	if err != nil {
		return result, err
	}
	current, err := nodeLANAssignedSource(probeCtx, request.Source, options)
	if err != nil || current.Index != iface.Index || current.Name != iface.Name {
		return result, errors.New("LAN HTTPS local source changed during the probe")
	}
	if err := probeCtx.Err(); err != nil {
		return result, err
	}
	digest := sha256.Sum256(body)
	result.BodySHA256, result.BodyBytes = hex.EncodeToString(digest[:]), len(body)
	result.ServiceAccepted = true
	return result, nil
}

func nodeLANHash(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func nodeLANSourceAddress(source netip.Addr) bool {
	return source.IsValid() && source.Zone() == "" && !source.Is4In6() && source.IsGlobalUnicast() && !source.IsLoopback() && !source.IsLinkLocalUnicast()
}

func nodeLANTCPEndpoint(address net.Addr) (netip.AddrPort, bool) {
	tcp, ok := address.(*net.TCPAddr)
	if !ok || tcp.Zone != "" || tcp.Port < 1 || tcp.Port > 65535 {
		return netip.AddrPort{}, false
	}
	endpoint := tcp.AddrPort()
	if !endpoint.IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()), true
}

func nodeLANAssignedSource(ctx context.Context, source netip.Addr, options nodeLANHTTPSOptions) (net.Interface, error) {
	if err := ctx.Err(); err != nil {
		return net.Interface{}, err
	}
	if !nodeLANSourceAddress(source) {
		return net.Interface{}, errors.New("LAN HTTPS source must be a non-loopback local unicast address")
	}
	interfaces := options.interfaces
	if interfaces == nil {
		interfaces = net.Interfaces
	}
	addresses := options.addresses
	if addresses == nil {
		addresses = func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() }
	}
	items, err := interfaces()
	if err != nil || len(items) == 0 || len(items) > 256 {
		return net.Interface{}, errors.New("LAN HTTPS local interfaces are unavailable")
	}
	var selected net.Interface
	for _, iface := range items {
		if err := ctx.Err(); err != nil {
			return net.Interface{}, err
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		values, err := addresses(iface)
		if err != nil || len(values) > 256 {
			return net.Interface{}, errors.New("LAN HTTPS assigned source addresses are unavailable")
		}
		found := false
		for _, value := range values {
			address, ok := nodeLANInterfaceAddress(value)
			if ok && address == source {
				found = true
			}
		}
		if found {
			if selected.Index != 0 || iface.Index <= 0 || len(iface.Name) == 0 || len(iface.Name) > 128 {
				return net.Interface{}, errors.New("LAN HTTPS source interface is ambiguous")
			}
			selected = iface
		}
	}
	if err := ctx.Err(); err != nil {
		return net.Interface{}, err
	}
	if selected.Index == 0 {
		return net.Interface{}, errors.New("LAN HTTPS source is not assigned to an up non-loopback interface on this client")
	}
	return selected, nil
}

func nodeLANInterfaceAddress(value net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch value := value.(type) {
	case *net.IPNet:
		if value != nil {
			ip = value.IP
		}
	case *net.IPAddr:
		if value != nil && value.Zone == "" {
			ip = value.IP
		}
	default:
		if value != nil && len(value.String()) <= 256 {
			prefix, err := netip.ParsePrefix(value.String())
			return prefix.Addr().Unmap(), err == nil
		}
	}
	address, ok := netip.AddrFromSlice(ip)
	return address.Unmap(), ok
}
