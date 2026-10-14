package devices

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type fakeRunner struct{ output string }

func (r fakeRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.output), nil
}

func TestDiscoveryMergesIPv4IPv6AndPersistsFriendlyMetadata(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "leases")
	if err := os.WriteFile(leasePath, []byte("0 aa:bb:cc:dd:ee:ff 192.168.1.25 phone *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := Load(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager.IPCommand = "ip"
	manager.Runner = fakeRunner{output: "192.168.1.25 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\nfd00::25 dev br0 lladdr aa:bb:cc:dd:ee:ff STALE\n"}
	manager.ARPPaths = nil
	manager.LeasePaths = []string{leasePath}
	devices := manager.List(context.Background())
	if len(devices) != 1 || devices[0].Hostname != "phone" || len(devices[0].IPs) != 2 || !devices[0].Discovered {
		t.Fatalf("unexpected discovery: %+v", devices)
	}
	updated, err := manager.Update(devices[0].ID, "Телефон", "Семья")
	if err != nil || updated.Name != "Телефон" || updated.Group != "Семья" {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	reloaded, err := Load(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Keep the persistence assertion independent from neighbors on the host
	// running the test (for example /proc/net/arp on a GitHub runner).
	reloaded.Runner = nil
	reloaded.ARPPaths = nil
	reloaded.LeasePaths = nil
	offline := reloaded.List(context.Background())
	if len(offline) != 1 || offline[0].Name != "Телефон" || offline[0].Group != "Семья" || offline[0].Discovered {
		t.Fatalf("metadata was not persisted: %+v", offline)
	}
}

func TestFailedAndInvalidNeighborsAreIgnored(t *testing.T) {
	manager, err := Load(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager.IPCommand = "ip"
	manager.Runner = fakeRunner{output: "192.168.1.3 dev br0 FAILED\nnot-an-ip dev br0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"}
	manager.ARPPaths, manager.LeasePaths = nil, nil
	if got := manager.List(context.Background()); len(got) != 0 {
		t.Fatalf("unexpected devices: %+v", got)
	}
}

type routeAwareRunner map[string]string

func (r routeAwareRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	key := ""
	for _, arg := range args {
		key += arg + " "
	}
	return []byte(r[key]), nil
}

// The provider gateway and other neighbors behind a default-route interface
// (Router: eth3 for IPv4, a tunnel for IPv6) are not home devices.
func TestDiscoveryLeavesOutNeighborsBehindDefaultRoutes(t *testing.T) {
	root := t.TempDir()
	arp := filepath.Join(root, "arp")
	if err := os.WriteFile(arp, []byte("IP address HW type Flags HW address Mask Device\n100.64.128.2 0x1 0x2 80:7f:f8:5b:38:09 * eth3\n192.168.1.40 0x1 0x2 aa:bb:cc:dd:ee:40 * br0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{IPCommand: "ip", ARPPaths: []string{arp}, Runner: routeAwareRunner{
		"-4 route show default ": "default via 100.64.128.1 dev eth3  metric 1000\n",
		"-6 route show default ": "default proto static metric 1024\n\tnexthop dev nwg0 weight 1\n\tnexthop via fe80::1 dev eth4 weight 1\n",
		"neigh show ": "100.64.128.1 dev eth3 lladdr 80:7f:f8:5b:38:08 REACHABLE\nfe80::9 dev nwg0 lladdr 02:00:00:00:00:09 STALE\nfe80::a dev eth4 lladdr 02:00:00:00:00:0a STALE\n" +
			"192.168.1.25 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n172.16.1.95 dev br1 lladdr 3c:0b:4f:55:c1:4e STALE\n",
	}}
	rows := m.discover(context.Background())
	if len(rows) != 3 || rows["mac-aa-bb-cc-dd-ee-ff"].Interface != "br0" || rows["mac-3c-0b-4f-55-c1-4e"].Interface != "br1" || rows["mac-aa-bb-cc-dd-ee-40"].Interface != "br0" {
		t.Fatalf("home devices: %+v", rows)
	}
	// Without route information nothing is hidden.
	if rows := (&Manager{IPCommand: "ip", Runner: fakeRunner{output: "100.64.128.1 dev eth3 lladdr 80:7f:f8:5b:38:08 REACHABLE\n"}}).discover(context.Background()); len(rows) != 1 {
		t.Fatalf("a neighbor was hidden without a default route: %+v", rows)
	}
}
