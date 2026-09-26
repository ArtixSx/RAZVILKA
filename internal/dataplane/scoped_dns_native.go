package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/routeprobe"
	"golang.org/x/net/dns/dnsmessage"
)

// CheckLAN uses the same bounded bridge/WAN inspection as the existing proxy
// dataplane. A configured interface name alone never grants client ownership.
func (a *ScopedDNSAdapter) CheckLAN(ctx context.Context, p ScopedDNSPlan) error {
	reader := &ProxyTunnelAdapter{Runner: a.Runner, Interface: "rz-dns", IP: "ip"}
	networks, err := reader.connectedLANPrefixes(ctx, false)
	if err != nil {
		return err
	}
	gateway := netip.MustParseAddrPort(p.Listener).Addr()
	bridge, err := net.InterfaceByName(p.Ingress)
	if err != nil || bridge.Flags&net.FlagUp == 0 {
		return errors.New("scoped DNS LAN interface is not available")
	}
	addresses, err := bridge.Addrs()
	if err != nil {
		return err
	}
	found := false
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr() == gateway {
			found = true
		}
	}
	if !found {
		return errors.New("scoped DNS listener is not assigned to the selected LAN bridge")
	}
	checked := map[string]bool{}
	for _, b := range p.Bindings {
		if checked[b.Client] {
			continue
		}
		checked[b.Client] = true
		source := netip.MustParsePrefix(b.Client + "/32")
		ingress, err := connectedLANIngress(networks, source)
		if err != nil || ingress != p.Ingress {
			return errors.New("scoped DNS client is outside the selected LAN bridge")
		}
		ingress, err = policySourceIngress(ctx, a.Runner, reader.ip(), source.Addr(), "rz-dns")
		if err != nil || ingress != p.Ingress {
			return errors.New("scoped DNS client route is not on the selected LAN bridge")
		}
	}
	return ctx.Err()
}

// ProbeDirect checks original TLS/Host against an address from the selected
// resolver. It does NOT attest a LAN packet; Manager keeps scoped route
// evidence unconfirmed until the separate client acceptance step.
func (a *ScopedDNSAdapter) ProbeDirect(ctx context.Context, r *dnscontrol.ScopedDNSResolver, p Plan) error {
	seen := map[string]bool{}
	for _, b := range p.DNS.Bindings {
		var service Route
		for _, route := range p.Routes {
			if route.ServiceID == b.ServiceID {
				service = route
				break
			}
		}
		origin, err := url.Parse(service.ProbeURL)
		if err != nil || origin.Scheme != "https" || strings.ToLower(origin.Hostname()) != b.Domain {
			continue
		}
		key := b.ServiceID + "\x00" + b.Client
		if seen[key] {
			continue
		}
		name, err := dnsmessage.NewName(b.Domain + ".")
		if err != nil {
			return err
		}
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: 31415, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		wire, _ := query.Pack()
		reply, err := r.Resolve(ctx, netip.MustParseAddr(b.Client), wire)
		if err != nil {
			return err
		}
		var answer dnsmessage.Message
		if answer.Unpack(reply) != nil {
			return errors.New("scoped DNS health answer is invalid")
		}
		addresses := []netip.Addr{}
		for _, rr := range answer.Answers {
			if value, ok := rr.Body.(*dnsmessage.AResource); ok {
				addresses = append(addresses, netip.AddrFrom4(value.A))
			}
		}
		if len(addresses) == 0 || len(addresses) > 16 {
			return errors.New("scoped DNS health requires a bounded IPv4 answer")
		}
		// One sampled address is a bounded router-side canary, not a claim of
		// coverage over the other answers, address family, scenarios or devices.
		result := routeprobe.ProbeDNSAddress(ctx, catalog.Service{ID: service.ServiceID, Name: service.ServiceName, Domains: service.Domains, ProbeURL: service.ProbeURL, Probes: []catalog.Probe{p.DNS.Probe}}, addresses[0])
		if result.Status != "pass" || !result.TLSVerified || !result.ServiceVerified {
			return errors.New("scoped DNS HTTPS canary did not confirm the selected web scenario")
		}
		seen[key] = true
	}
	for _, b := range p.DNS.Bindings {
		if !seen[b.ServiceID+"\x00"+b.Client] {
			return errors.New("scoped DNS service has no matching HTTPS canary binding")
		}
	}
	return ctx.Err()
}
