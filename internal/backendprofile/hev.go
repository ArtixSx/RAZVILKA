package backendprofile

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
)

type HevOptions struct {
	Interface   string `json:"interface"`
	Address     string `json:"address"` // TUN IPv4 CIDR, not a proxy address.
	SOCKSPort   int    `json:"socks_port"`
	MTU         int    `json:"mtu"`
	MaxSessions int    `json:"max_sessions"`
}

var ownedInterface = regexp.MustCompile(`^rz-[a-z0-9-]{1,11}$`)

// HevJSON is YAML-compatible JSON for upstream 2.17.1. No scripts, mapdns,
// local fake ICMP replies, auto-routing, daemonization or external SOCKS peer.
func HevJSON(o HevOptions) ([]byte, error) {
	p, e := netip.ParsePrefix(o.Address)
	if e != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() < 24 || p.Bits() > 30 || !ownedInterface.MatchString(o.Interface) || o.SOCKSPort < 1024 || o.SOCKSPort > 65535 || o.MTU < 1280 || o.MTU > 1500 || o.MaxSessions < 32 || o.MaxSessions > 4096 {
		return nil, errors.New("invalid managed HEV settings")
	}
	// The adapter adds the subnet separately; reserve a usable host, not its
	// network or broadcast address, as the tunnel's local identity.
	a := p.Addr().As4()
	hostBits := uint32(32 - p.Bits())
	mask := uint32(1<<hostBits) - 1
	last := (uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])) & mask
	if last == 0 || last == mask {
		return nil, errors.New("TUN requires a usable host address")
	}
	doc := map[string]any{
		"tunnel": map[string]any{"name": o.Interface, "mtu": o.MTU, "multi-queue": false, "ipv4": p.Addr().String(), "icmp": "off"},
		"socks5": map[string]any{"address": "127.0.0.1", "port": o.SOCKSPort, "udp": "udp"},
		"misc":   map[string]any{"max-session-count": o.MaxSessions, "connect-timeout": 10000, "tcp-read-write-timeout": 300000, "udp-read-write-timeout": 60000, "log-file": "stderr", "log-level": "warn"},
	}
	return json.MarshalIndent(doc, "", "  ")
}
