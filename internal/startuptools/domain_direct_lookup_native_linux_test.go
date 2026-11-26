//go:build linux && razvilka_native_fixture

package startuptools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNativeDomainDirectRouteReadsHeldIPAndKernel(t *testing.T) {
	review := os.Getenv("RAZVILKA_DOMAIN_DIRECT_NATIVE_TOOLS_REVIEW")
	mode := os.Getenv("RAZVILKA_DOMAIN_ROUTE_LOOKUP_FIXTURE")
	if review == "" || mode != "main" && mode != "alternate" {
		t.Skip("requires the offline NC-independent domain route/tool fixture")
	}
	egress, err := net.InterfaceByName("rz-domain-out")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	lease, err := AcquireNativeFixturePolicy(ctx, netidentity.NewProcProvider(), review)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	tools, err := lease.SyntheticDNSCommandTools()
	if err != nil {
		t.Fatal(err)
	}
	original, ok := tools.Runner.(*syntheticDNSRunner)
	if !ok || original.lease != lease {
		t.Fatal("read did not retain the original tools")
	}
	source := netip.MustParseAddr("192.168.72.1")
	destination := netip.MustParseAddr("93.184.216.34")
	got, err := original.ReadDomainTCPDirectRoute(ctx, source, destination)
	if mode == "alternate" {
		if err == nil || len(got.JSON) != 0 || got.Kernel.EgressIndex != 0 {
			t.Fatalf("alternate table produced a partial or accepted route: %+v %v", got, err)
		}
		var detail *failure
		if !errors.As(err, &detail) || detail.stage != "DOMAIN_DIRECT_KERNEL_READ" {
			t.Fatalf("held JSON read did not reach the independent kernel check: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var routes []struct {
		Device string `json:"dev"`
		Source string `json:"from"`
		Target string `json:"dst"`
	}
	if json.Unmarshal(got.JSON, &routes) != nil || len(routes) != 1 || routes[0].Device != egress.Name || routes[0].Source != source.String() || routes[0].Target != destination.String() ||
		got.Kernel.Source != source || got.Kernel.Destination != destination || got.Kernel.IngressIndex != 0 ||
		got.Kernel.EgressIndex != egress.Index || got.Kernel.Gateway.String() != "192.168.72.2" {
		t.Fatalf("original held JSON and native local route did not agree: %+v", got)
	}
}
