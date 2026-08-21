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
