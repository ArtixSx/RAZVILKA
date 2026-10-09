package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/proxy"
)

func validLANIPv4(address netip.Addr) bool {
	return address.Is4() && !address.IsLoopback() && !address.IsUnspecified() && !address.IsMulticast() && address != netip.MustParseAddr("255.255.255.255")
}

func lanAddressPresent(address netip.Addr) bool {
	if !validLANIPv4(address) {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, local := range addresses {
			prefix, err := netip.ParsePrefix(local.String())
			if err == nil && prefix.Addr() == address {
				return true
			}
		}
	}
	return false
}

// This control is read-only interface inventory, not a reachability, route or
// VLESS control. The actual probes still have to bind their sockets.
func lanEndpointControl(parent context.Context, o options) control {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, o.ControlTimeout)
	defer cancel()
	r := control{Code: "lan_client_address_unavailable"}
	if contextStopCause(ctx, time.Now()) == nil && lanAddressPresent(o.LANClient) {
		r.OK, r.Code = true, "lan_client_address_present"
	}
	if err := contextStopCause(ctx, time.Now()); err != nil {
		r.OK, r.Code = false, failureCode(ctx, err)
	}
	r.LatencyMS = float64(time.Since(started)) / float64(time.Millisecond)
	return r
}

type lanDialer struct {
	address netip.Addr
	socket  net.Dialer
}

func newLANDialer(address netip.Addr) (*lanDialer, error) {
	if !lanAddressPresent(address) {
		return nil, errors.New("LAN client address unavailable")
	}
	return &lanDialer{address: address, socket: net.Dialer{Timeout: 30 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(address.AsSlice())}}}, nil
}

func (d *lanDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if err := contextStopCause(ctx, time.Now()); err != nil {
		return nil, err
	}
	if network != "tcp" || !lanAddressPresent(d.address) {
		return nil, errors.New("LAN client dial unavailable")
	}
	// IPv4 system resolution and routing, with a mandatory source address.
	// A bind/dial error is returned directly; there is no unbound retry or proxy.
	return d.socket.DialContext(ctx, "tcp4", target)
}

func newOutboundDialer(o options) (proxy.ContextDialer, error) {
	if err := o.validateMode(); err != nil {
		return nil, err
	}
	if o.LANClient.IsValid() {
		return newLANDialer(o.LANClient)
	}
	dialer, err := proxy.SOCKS5("tcp", o.SOCKS, nil, &net.Dialer{})
	if err != nil {
		return nil, errors.New("SOCKS dialer unavailable")
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS cancellation unavailable")
	}
	return contextDialer, nil
}
