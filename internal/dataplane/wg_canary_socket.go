package dataplane

import (
	"context"
	"net"
	"net/netip"
	"time"
)

type wgSocketInterfaceKey struct{}

// A source address is not a tunnel identity: the working peer and candidate
// commonly use the same Address. Bind the socket's output device as well, and
// match that device in the RPDB. This applies equally to TCP and UDP sockets.
func wgSocketDialer(ctx context.Context, source net.IP, udp bool) *net.Dialer {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if udp {
		dialer.LocalAddr = &net.UDPAddr{IP: source}
	} else {
		dialer.LocalAddr = &net.TCPAddr{IP: source}
	}
	if device, _ := ctx.Value(wgSocketInterfaceKey{}).(string); device != "" {
		dialer.Control = wgBindSocket(device)
	}
	return dialer
}

func canarySourceFamily(source netip.Addr) string {
	if source.Is6() {
		return "-6"
	}
	return "-4"
}

func canaryFamilyArgs(family string, args ...string) []string {
	if family == "-6" {
		return append([]string{"-6"}, args...)
	}
	return args
}
