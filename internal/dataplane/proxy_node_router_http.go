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
	"sync"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const (
	nodeRouterHTTPSBudget = 10 * time.Second
	nodeRouterHTTPSOrigin = "router-owned-tun"
)

var errNodeRouterHTTPSUnavailable = errors.New("router TUN HTTPS transport unavailable")

// The caller supplies an already owned TUN identity and admitted service pin.
// Runtime/manifest/epoch, assigned TunnelCIDR, transit lease ownership/readback,
// admission and return-path capability must be checked by that owner before and
// after this operation. These private fields are not an HTTP authority DTO.
type nodeRouterHTTPSRequest struct {
	URL         string
	Interface   string
	IfIndex     int
	Source      netip.Addr
	Destination netip.Addr
}

// This result describes one router-origin socket, never a LAN observation or
// an egress address. BodySHA256 identifies only the bounded accepted sample.
// ServiceAccepted alone grants no route/lease/runtime ownership or Commit.
type nodeRouterHTTPSResult struct {
	Origin          string
	Interface       string
	IfIndex         int
	Source          netip.AddrPort
	Destination     netip.AddrPort
	StartedAt       time.Time
	FinishedAt      time.Time
	HTTPStatus      int
	ServiceAccepted bool
	BodySHA256      string
	BodyBytes       int
}

func probeNodeRouterHTTPS(ctx context.Context, request nodeRouterHTTPSRequest) (nodeRouterHTTPSResult, error) {
	return runNodeRouterHTTPSProbe(ctx, request, nodeRouterHTTPSOptions{})
}

// Local-only fixtures may inject OS inventory, verified CA roots and socket
// controls. Production exposes no options, TLS bypass, alternate source or dial.
type nodeRouterHTTPSOptions struct {
	interfaces func() ([]net.Interface, error)
	addresses  func(net.Interface) ([]net.Addr, error)
	bind       func(syscall.RawConn, string) error
	dial       func(context.Context, *net.Dialer, string, string) (net.Conn, error)
	roots      *x509.CertPool
}

func nodeRouterAssignedSource(ctx context.Context, request nodeRouterHTTPSRequest, options nodeRouterHTTPSOptions) error {
	iface, err := nodeLANAssignedSource(ctx, request.Source, nodeLANHTTPSOptions{interfaces: options.interfaces, addresses: options.addresses})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || iface.Name != request.Interface || iface.Index != request.IfIndex {
		return errors.Join(errNodeRouterHTTPSUnavailable, errors.New("owned TUN source/interface identity is unavailable"))
	}
	return ctx.Err()
}

func runNodeRouterHTTPSProbe(ctx context.Context, request nodeRouterHTTPSRequest, options nodeRouterHTTPSOptions) (nodeRouterHTTPSResult, error) {
	if ctx == nil {
		return nodeRouterHTTPSResult{}, errors.New("router HTTPS probe context is required")
	}
	if err := ctx.Err(); err != nil {
		return nodeRouterHTTPSResult{}, err
	}
	if !proxyFirewallInterface.MatchString(request.Interface) || request.Interface == "lo" || request.IfIndex < 1 || request.IfIndex > 1<<31-1 ||
		!request.Source.Is4() || request.Source.Is4In6() || !nodeLANSourceAddress(request.Source) || !request.Destination.Is4() || request.Destination.Is4In6() ||
		!publicfetch.PublicAddress(request.Destination) || len(request.URL) > 4096 || publicfetch.ValidateURL(request.URL) != nil {
		return nodeRouterHTTPSResult{}, errors.New("router HTTPS probe requires an exact TUN identity, assigned IPv4 source and public original HTTPS pin")
	}
	origin, _ := url.Parse(request.URL)
	if literal, err := netip.ParseAddr(origin.Hostname()); err == nil && literal != request.Destination {
		return nodeRouterHTTPSResult{}, errors.New("router HTTPS pin differs from its literal URL")
	}
	bind := options.bind
	if bind == nil {
		if !nodeRouterDeviceBindingAvailable() {
			return nodeRouterHTTPSResult{}, errNodeRouterHTTPSUnavailable
		}
		bind = nodeRouterSystemBindSocket
	}
	probeCtx, cancel := context.WithTimeout(ctx, nodeRouterHTTPSBudget)
	defer cancel()
	if err := nodeRouterAssignedSource(probeCtx, request, options); err != nil {
		return nodeRouterHTTPSResult{}, err
	}
	result := nodeRouterHTTPSResult{Origin: nodeRouterHTTPSOrigin, Interface: request.Interface, IfIndex: request.IfIndex, StartedAt: time.Now().UTC()}
	var mu sync.Mutex
	var actualSource, actualDestination netip.AddrPort
	var socket net.Conn
	var dialDone chan struct{}
	closed, bound := false, false
	dialer := &net.Dialer{Timeout: 4 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(request.Source.AsSlice())}, FallbackDelay: -1}
	dialer.SetMultipathTCP(false)
	dialer.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		if network != "tcp4" || address != net.JoinHostPort(request.Destination.String(), "443") {
			return errNodeRouterHTTPSUnavailable
		}
		// Re-read the actual assigned address and ifindex immediately before
		// the kernel connect, both before and after the checked device binding.
		if err := nodeRouterAssignedSource(ctx, request, options); err != nil {
			return err
		}
		if err := bind(raw, request.Interface); err != nil {
			return errors.Join(errNodeRouterHTTPSUnavailable, err)
		}
		if err := nodeRouterAssignedSource(ctx, request, options); err != nil {
			return err
		}
		mu.Lock()
		bound = true
		mu.Unlock()
		return ctx.Err()
	}
	dial := options.dial
	if dial == nil {
		dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
			return d.DialContext(ctx, network, target)
		}
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.roots, ServerName: origin.Hostname()},
		TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 6 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 1,
		DialContext: func(_ context.Context, network, target string) (net.Conn, error) {
			if err := probeCtx.Err(); err != nil {
				return nil, err
			}
			host, port, err := net.SplitHostPort(target)
			if err != nil || !samePinnedServiceHost(host, origin.Hostname()) || port != "443" || network != "tcp" && network != "tcp4" {
				return nil, errors.New("router HTTPS transport target changed")
			}
			mu.Lock()
			if closed || dialDone != nil {
				mu.Unlock()
				return nil, errors.New("router HTTPS probe cannot retry or fall back")
			}
			done := make(chan struct{})
			dialDone = done
			mu.Unlock()
			defer close(done)
			// net/http detaches dial contexts for pooling; this dedicated socket
			// remains bound to the caller's budget/cancellation instead.
			dialCtx, stopDial := context.WithTimeout(probeCtx, dialer.Timeout)
			defer stopDial()
			conn, err := dial(dialCtx, dialer, "tcp4", net.JoinHostPort(request.Destination.String(), "443"))
			if err != nil {
				if errors.Is(err, errNodeRouterHTTPSUnavailable) {
					return nil, err
				}
				return nil, errors.New("router HTTPS device-bound connection failed")
			}
			mu.Lock()
			socket = conn
			bindingChecked, canceled := bound, closed
			mu.Unlock()
			if !bindingChecked || canceled || probeCtx.Err() != nil {
				_ = conn.Close()
				return nil, errNodeRouterHTTPSUnavailable
			}
			source, sourceOK := nodeLANTCPEndpoint(conn.LocalAddr())
			destination, destinationOK := nodeLANTCPEndpoint(conn.RemoteAddr())
			if !sourceOK || !destinationOK || source.Addr() != request.Source || destination != netip.AddrPortFrom(request.Destination, 443) {
				_ = conn.Close()
				return nil, errNodeRouterHTTPSUnavailable
			}
			mu.Lock()
			actualSource, actualDestination = source, destination
			mu.Unlock()
			context.AfterFunc(probeCtx, func() { _ = conn.Close() })
			return conn, nil
		},
	}
	defer func() {
		mu.Lock()
		closed = true
		done := dialDone
		mu.Unlock()
		cancel()
		if done != nil {
			<-done // production dial honors the same canceled context
		}
		mu.Lock()
		conn := socket
		mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		transport.CloseIdleConnections()
	}()
	client := &http.Client{Transport: transport, Timeout: nodeRouterHTTPSBudget, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	httpRequest, err := http.NewRequestWithContext(probeCtx, http.MethodGet, request.URL, nil)
	if err != nil {
		return result, errors.New("router HTTPS request is invalid")
	}
	httpRequest.Header.Set("User-Agent", "RAZVILKA-Router-TUN-Check/1")
	response, err := client.Do(httpRequest)
	mu.Lock()
	result.Source, result.Destination = actualSource, actualDestination
	mu.Unlock()
	result.FinishedAt = time.Now().UTC()
	if err != nil {
		if probeCtx.Err() != nil {
			return result, probeCtx.Err()
		}
		if errors.Is(err, errNodeRouterHTTPSUnavailable) {
			return result, errNodeRouterHTTPSUnavailable
		}
		return result, errors.New("router HTTPS request failed")
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	body, err := strictServiceResponse(request.URL, response)
	defer clear(body)
	result.FinishedAt = time.Now().UTC()
	if probeCtx.Err() != nil {
		return result, probeCtx.Err()
	}
	if err != nil {
		return result, err
	}
	if err := nodeRouterAssignedSource(probeCtx, request, options); err != nil {
		return result, err
	}
	digest := sha256.Sum256(body)
	if err := probeCtx.Err(); err != nil {
		return result, err
	}
	result.BodySHA256, result.BodyBytes = hex.EncodeToString(digest[:]), len(body)
	result.ServiceAccepted = true
	return result, nil
}

// The production Linux binding and per-call unit fixtures share this check;
// no successful set without a matching kernel readback can authorize connect.
func nodeRouterCheckedSocketBinding(raw syscall.RawConn, device string, set func(int, string) error, get func(int) (string, error)) error {
	if raw == nil || set == nil || get == nil {
		return errNodeRouterHTTPSUnavailable
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		if err := set(int(fd), device); err != nil {
			bindErr = err
			return
		}
		actual, err := get(int(fd))
		if err != nil || actual != device {
			bindErr = errors.Join(errNodeRouterHTTPSUnavailable, err)
		}
	}); err != nil {
		return errors.Join(errNodeRouterHTTPSUnavailable, err)
	}
	return bindErr
}
