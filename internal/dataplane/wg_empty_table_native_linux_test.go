//go:build linux

package dataplane

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// The script gives this case a fresh private mount/net/PID namespace before
// any other fixture installs routes. Exercise real CLI diagnostics and the
// complete inactivity observer, without substituting command/process results.
func TestWGNativeEmptyTables(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_NATIVE") != "1" {
		t.Skip("requires the isolated root-only native script")
	}
	links, err := net.Interfaces()
	if err != nil || os.Geteuid() != 0 || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("requires an exclusively assigned namespace containing only lo", err)
	}
	for _, constructor := range []func(*engineconfig.Manager, string) *WARPWireGuardAdapter{NewWARPWireGuardAdapter, NewWireGuardAdapter, NewAmneziaWGAdapter} {
		a := constructor(nil, t.TempDir())
		a.IP = "ip"
		t.Run(a.ID(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := a.VerifyRuntimeInactive(ctx); err != nil {
				nativeWGKernelCapture(t, "", "actual empty-table inactivity refused")
				t.Fatal(err)
			}
			spec, err := a.endpointSpec()
			if err != nil {
				t.Fatal(err)
			}
			if err := a.inspectWGNetworkTransportTable(ctx, spec.EndpointTable, nil); err != nil {
				t.Fatal("fresh endpoint table observation", err)
			}
		})
	}
}
