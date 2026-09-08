package conntrack

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/telemetry"
)

type fakeRunner struct{ output string }

func (runner fakeRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(runner.output), nil
}

func TestParseFlowsUsesOriginalTupleAndCounters(t *testing.T) {
	line := "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.25 dst=203.0.113.10 sport=55555 dport=443 packets=10 bytes=1200 src=203.0.113.10 dst=198.51.100.2 sport=443 dport=55555 packets=8 bytes=900 [ASSURED]"
	flows := parseFlows(line)
	if len(flows) != 1 || flows[0].Source.String() != "192.168.1.25" || flows[0].DestinationPort != "443" || flows[0].Upload != 1200 || flows[0].Download != 900 {
		t.Fatalf("unexpected flows: %+v", flows)
	}
}

func TestCollectorPublishesOnlyKernelConfirmedServiceRoute(t *testing.T) {
	root := t.TempDir()
	conntrackPath := filepath.Join(root, "nf_conntrack")
	line := "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.25 dst=203.0.113.10 sport=55555 dport=443 packets=10 bytes=1200 src=203.0.113.10 dst=198.51.100.2 sport=443 dport=55555 packets=8 bytes=900 [ASSURED]\n"
	if err := os.WriteFile(conntrackPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := configuration.UpdateService("video", config.ServiceState{Enabled: true, Route: "warp-wg", Sources: []string{"192.168.1.25"}}); err != nil {
		t.Fatal(err)
	}
	if err := configuration.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	store := telemetry.NewStore()
	collector := New(store, configuration, func() catalog.Catalog {
		return catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Video", CIDRs: []string{"203.0.113.10/32"}}}}
	})
	collector.ConntrackPaths = []string{conntrackPath}
	collector.IPCommand = "ip"
	collector.Runner = fakeRunner{output: "203.0.113.10 from 192.168.1.25 dev rz-warp table 201\n"}
	collector.Resolver = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	collector.ResolveTimeout = time.Second
	connections, err := collector.Collect(context.Background())
	if err != nil || len(connections) != 1 || connections[0].Route != "warp-wg" || connections[0].ServiceID != "video" {
		t.Fatalf("connections=%+v err=%v", connections, err)
	}
	collector.Runner = fakeRunner{output: "203.0.113.10 from 192.168.1.25 dev eth0\n"}
	connections, err = collector.Collect(context.Background())
	if err != nil || len(connections) != 0 {
		t.Fatalf("unconfirmed route was published: %+v err=%v", connections, err)
	}
}

func TestStoreReplaceActiveKeepsStartAndClosesMissing(t *testing.T) {
	store := telemetry.NewStore()
	store.ReplaceActive("test", []telemetry.Connection{{ID: "one", Route: "direct"}})
	first := store.Snapshot(false)[0].StartedAt
	time.Sleep(time.Millisecond)
	store.ReplaceActive("test", []telemetry.Connection{{ID: "one", Route: "direct", Upload: 10}})
	if got := store.Snapshot(false)[0]; !got.StartedAt.Equal(first) || got.Upload != 10 {
		t.Fatalf("unexpected replacement: %+v", got)
	}
	store.ReplaceActive("test", nil)
	active, closed := store.Counts()
	if active != 0 || closed != 1 {
		t.Fatalf("counts=%d/%d", active, closed)
	}
}
