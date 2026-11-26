//go:build linux && razvilka_native_fixture

package physicalscope

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// The optical lab provisions two veth pairs and never sends packets. An
// ordinary run does not assume the host's links belong to a fixture.
func TestNativeDomainIPv4RouteLookup(t *testing.T) {
	mode := os.Getenv("RAZVILKA_DOMAIN_ROUTE_LOOKUP_FIXTURE")
	if mode != "main" && mode != "alternate" {
		t.Skip("requires the explicit offline domain route lookup fixture")
	}
	ingress, err := net.InterfaceByName("rz-domain-in")
	if err != nil {
		t.Fatal(err)
	}
	egress, err := net.InterfaceByName("rz-domain-out")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destination := netip.MustParseAddr("93.184.216.34")
	gateway := netip.MustParseAddr("192.168.72.2")
	client := netip.MustParseAddr("192.168.71.2")
	router := netip.MustParseAddr("192.168.72.1")
	out, err := ReadDomainIPv4LocalRoute(ctx, provider, identity, router, destination)
	if err != nil || out != (DomainIPv4RouteLookup{Source: router, Destination: destination, Gateway: gateway, EgressIndex: egress.Index}) {
		t.Fatalf("local kernel route refused or changed: %+v %v", out, err)
	}
	observed, err := ReadDomainIPv4ForwardedRoute(ctx, provider, identity, client, destination, ingress.Index)
	if mode == "alternate" {
		if observed != (DomainIPv4RouteLookup{}) || !errors.Is(err, ErrUnknown) {
			t.Fatalf("foreign forwarding table authenticated: %+v %v", observed, err)
		}
		return
	}
	if err != nil || observed != (DomainIPv4RouteLookup{Source: client, Destination: destination, Gateway: gateway, IngressIndex: ingress.Index, EgressIndex: egress.Index}) {
		t.Fatalf("forwarded kernel route refused or changed: %+v %v", observed, err)
	}
	if _, err := ReadDomainIPv4ForwardedRoute(ctx, provider, identity, client, destination, 0x7fffffff); !errors.Is(err, ErrUnknown) {
		t.Fatalf("foreign ingress accepted: %v", err)
	}
}
