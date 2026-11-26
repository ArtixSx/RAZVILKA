package app

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestNodeHypotheticalDropsPriorWireGuardReviewBinding(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		cfg := config.Default()
		cfg.AppliedServices = map[string]config.ServiceState{"telegram": {Enabled: true, Route: "wireguard:backup", WireGuardProfileRevision: strings.Repeat("a", 64)}}
		next := nodeRouteConfigForEngineScope(cfg, engine, "telegram", "node-"+strings.Repeat("b", 64), []string{"192.168.1.40/32"})
		if next.Services["telegram"].WireGuardProfileRevision != "" || cfg.AppliedServices["telegram"].WireGuardProfileRevision != strings.Repeat("a", 64) {
			t.Fatal("node preview retained or erased unrelated reviewed WG binding")
		}
	}
}
