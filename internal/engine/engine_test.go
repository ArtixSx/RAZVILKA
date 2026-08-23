package engine

import (
	"os"
	"strings"
	"testing"
)

func TestProcessListHasExactName(t *testing.T) {
	output := `PID USER COMMAND
12 root /opt/bin/nfqws2-helper --serve
13 root /usr/bin/grep nfqws2
14 root /opt/bin/unrelated --name=nfqws2
`
	if processListHasName(output, "nfqws2") {
		t.Fatal("substring or argument was treated as a running process")
	}
	output += "15 root /opt/bin/nfqws2 --dpi-desync=fake\n"
	if !processListHasName(output, "nfqws2") {
		t.Fatal("exact executable name was not detected")
	}
	if !processListHasName("16 root [nfqws2]\n", "nfqws2") {
		t.Fatal("kernel-style process name was not detected")
	}
}

func TestStatusLooksRunning(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{status: "service is running", want: true},
		{status: "started", want: true},
		{status: "active (running)", want: true},
		{status: "not running", want: false},
		{status: "inactive", want: false},
		{status: "not started", want: false},
		{status: "failed", want: false},
		{status: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			if got := statusLooksRunning(tc.status); got != tc.want {
				t.Fatalf("statusLooksRunning(%q)=%v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

func TestFirstLineBoundsAndTrimsVersionOutput(t *testing.T) {
	if got := firstLine("  sing-box version 1.11.0  \nsecond line"); got != "sing-box version 1.11.0" {
		t.Fatalf("unexpected version line %q", got)
	}
	long := strings.Repeat("x", 200)
	if got := firstLine(long); len(got) != 160 {
		t.Fatalf("version output length=%d, want 160", len(got))
	}
}

func TestSelectVersionLineSkipsUsqueConfigDiagnostics(t *testing.T) {
	output := "2026/08/14 18:50:14 UTC Config file not found: open config.json\n" +
		"2026/08/14 18:50:14 UTC You may only use the register command.\n" +
		"usque version: v4.2.0\nCommit: 0fa6da9e\nBuild Date: 2026-06-21T20:57:16Z\n"
	if got := selectVersionLine(output, "usque"); got != "usque version: v4.2.0" {
		t.Fatalf("selected version line=%q", got)
	}
	if got := selectVersionLine("Config file not found\n", "usque"); got != "" {
		t.Fatalf("diagnostic was treated as version: %q", got)
	}
}

func TestCapabilityInventoryUsesArrays(t *testing.T) {
	status := detectSpec(specification{id: "definitely-not-installed", capabilities: []string{"tcp"}})
	if status.Architecture == "" || len(status.Capabilities) != 1 {
		t.Fatalf("incomplete registry status: %#v", status)
	}
	if status.Ownership.Ports == nil || status.Ownership.Interfaces == nil || status.Ownership.NFQueues == nil {
		t.Fatalf("ownership must serialize as arrays: %#v", status.Ownership)
	}
	if status.NativeCheck {
		t.Fatal("native check claimed without an installed binary")
	}
}

func TestConfigurationAloneDoesNotClaimInstalledRuntime(t *testing.T) {
	root := t.TempDir()
	profile := root + "/warp.conf"
	if err := os.WriteFile(profile, []byte("[Interface]\nAddress = 172.31.0.2/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := detectSpec(specification{id: "warp-wg-test", files: []string{profile}, capabilities: []string{"tun"}})
	if status.Installed || !status.Configured || status.RuntimeReady {
		t.Fatalf("configuration was confused with runtime: %#v", status)
	}
}

func TestFastInventoryKeepsRegistryMetadataWithoutVersionCommands(t *testing.T) {
	items := (Detector{}).Inventory()
	if len(items) != len(specifications()) {
		t.Fatalf("inventory size=%d, registry=%d", len(items), len(specifications()))
	}
	seen := map[string]bool{}
	for _, item := range items {
		if item.ID == "" || item.Name == "" || item.Architecture == "" || len(item.Capabilities) == 0 {
			t.Fatalf("incomplete inventory item: %#v", item)
		}
		if item.Version != "" {
			t.Fatalf("fast inventory unexpectedly ran version probe: %#v", item)
		}
		seen[item.ID] = true
	}
	for _, id := range []string{"nfqws2", "z2k", "usque", "warp-wg", "sing-box", "xray", "amneziawg"} {
		if !seen[id] {
			t.Fatalf("registered engine %q missing from inventory", id)
		}
	}
}

func TestVisibleOmitsExternalNFQWS2Owner(t *testing.T) {
	items := Visible([]Status{{ID: "nfqws2", Name: "NFQWS2"}, {ID: "z2k", Name: "z2k", External: true}, {ID: "usque", Name: "WARP MASQUE"}})
	if len(items) != 2 || items[0].ID != "nfqws2" || items[1].ID != "usque" {
		t.Fatalf("visible bypasses = %#v", items)
	}
}

func TestUsqueKeeneticSessionIsRecognizedAsConfiguration(t *testing.T) {
	for _, spec := range specifications() {
		if spec.id != "usque" {
			continue
		}
		if len(spec.files) == 0 || spec.files[0] != "/opt/etc/usque/session.conf" {
			t.Fatalf("usque-keenetic session path is not preferred: %#v", spec.files)
		}
		return
	}
	t.Fatal("usque engine specification is missing")
}
