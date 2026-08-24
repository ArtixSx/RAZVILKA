package enginelab

import (
	"testing"

	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

func TestExtractResourcesFromJSONAndShell(t *testing.T) {
	jsonConfig := `{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":1080},{"protocol":"socks","port":2080},{"type":"tun","interface_name":"rz-tun"}],"outbounds":[{"type":"vless","server_port":443}]}`
	resources := extractResources("sing-box", jsonConfig, "staged")
	if !hasResource(resources, "port", "1080") || !hasResource(resources, "port", "2080") || !hasResource(resources, "interface", "rz-tun") || hasResource(resources, "port", "443") {
		t.Fatalf("JSON resources = %+v", resources)
	}
	shellConfig := "NFQUEUE=200\nLISTEN_PORT=8080\nINTERFACE_NAME=rz-nfq\n"
	resources = extractResources("nfqws2", shellConfig, "live")
	if !hasResource(resources, "nfqueue", "200") || !hasResource(resources, "port", "8080") || !hasResource(resources, "interface", "rz-nfq") {
		t.Fatalf("shell resources = %+v", resources)
	}
}

func TestResourceConflictsIncludeSystemListener(t *testing.T) {
	resources := []Resource{
		{Kind: "port", Value: "1080", EngineID: "usque"},
		{Kind: "port", Value: "1080", EngineID: "sing-box"},
		{Kind: "interface", Value: "rz0", EngineID: "warp-wg"},
	}
	conflicts := resourceConflicts(resources, map[string]string{"1080": "tcp 127.0.0.1:1080 LISTEN"})
	if len(conflicts) != 1 || !conflicts[0].Blocking || len(conflicts[0].Engines) != 2 || conflicts[0].SystemUse == "" {
		t.Fatalf("conflicts = %+v", conflicts)
	}
}

func TestInspectIsNotReadyWhenNoEngineCanRun(t *testing.T) {
	manager := New(nil)
	manager.Statuses = func() []engine.Status {
		return []engine.Status{{ID: "nfqws2", Name: "NFQWS2", Installed: false}, {ID: "sing-box", Name: "Sing-box", Installed: false}}
	}
	manager.System = func() systemprobe.Snapshot { return systemprobe.Snapshot{} }
	manager.ListeningPorts = func() map[string]string { return map[string]string{} }
	report := manager.Inspect()
	if report.Ready || len(report.Engines) != 2 {
		t.Fatalf("report = %+v", report)
	}
}

func TestInspectHidesExternalZ2KButKeepsOwnershipBlocker(t *testing.T) {
	manager := New(nil)
	manager.Statuses = func() []engine.Status {
		return []engine.Status{
			{ID: "nfqws2", Name: "NFQWS2", Installed: false},
			{ID: "z2k", Name: "z2k", Installed: true, Running: true, External: true},
		}
	}
	manager.System = func() systemprobe.Snapshot { return systemprobe.Snapshot{} }
	manager.ListeningPorts = func() map[string]string { return map[string]string{} }
	report := manager.Inspect()
	if len(report.Engines) != 1 || report.Engines[0].ID != "nfqws2" {
		t.Fatalf("external owner leaked into bypass list: %+v", report.Engines)
	}
	if report.Ready || len(report.Conflicts) != 1 || !report.Conflicts[0].Blocking || report.Conflicts[0].Value != "external-owner" {
		t.Fatalf("ownership blocker missing: %+v", report)
	}
	gate, ok := report.Gate["external_nfqws2_owner"].(map[string]interface{})
	if !ok || gate["running"] != true {
		t.Fatalf("external owner gate missing: %+v", report.Gate)
	}
}

func TestVersionCompatibilityIsEvidenceBased(t *testing.T) {
	version, status := versionCompatibility(engine.Status{Installed: true, Version: "sing-box version 1.12.3"})
	if version != "1.12.3" || status != "native-validation-required" {
		t.Fatalf("version=%q status=%q", version, status)
	}
	version, status = versionCompatibility(engine.Status{Installed: true, Version: "custom build"})
	if version != "" || status != "unknown-requires-native-validation" {
		t.Fatalf("unknown version=%q status=%q", version, status)
	}
}

func TestApplyConflictsIgnoresOwnListenerButBlocksCrossEngineConflict(t *testing.T) {
	report := Report{
		Engines: []EngineReport{{Status: engine.Status{ID: "sing-box", Running: true}}, {Status: engine.Status{ID: "usque", Running: false}}},
		Conflicts: []Conflict{
			{Kind: "port", Value: "1080", Engines: []string{"sing-box"}, SystemUse: "tcp 127.0.0.1:1080 LISTEN", Blocking: true},
			{Kind: "port", Value: "2080", Engines: []string{"sing-box", "usque"}, Blocking: true},
		},
	}
	got := report.ApplyConflicts([]string{"sing-box"})
	if len(got) != 1 || got[0].Value != "2080" {
		t.Fatalf("apply conflicts = %+v", got)
	}
}

func TestApplyConflictsBlocksListenerForStoppedAdapter(t *testing.T) {
	report := Report{
		Engines:   []EngineReport{{Status: engine.Status{ID: "sing-box", Running: false}}},
		Conflicts: []Conflict{{Kind: "port", Value: "1080", Engines: []string{"sing-box"}, SystemUse: "tcp 127.0.0.1:1080 LISTEN", Blocking: true}},
	}
	got := report.ApplyConflicts([]string{"sing-box"})
	if len(got) != 1 || got[0].Value != "1080" {
		t.Fatalf("apply conflicts = %+v", got)
	}
}

func TestPolicyConflictsBlockForeignPriorityAndReservedTable(t *testing.T) {
	conflicts := policyConflictsFromState(
		[]string{"18100: from all to 203.0.113.7 lookup 999\n22000: from all to 198.51.100.8 lookup 203\n", ""},
		map[string]string{
			"warp-wg|4":  "default via 192.0.2.1 dev foreign0\n",
			"sing-box|4": "default dev rz-sing scope link\n",
		},
	)
	if len(conflicts) != 2 {
		t.Fatalf("policy conflicts = %+v", conflicts)
	}
	kinds := map[string]Conflict{}
	for _, conflict := range conflicts {
		kinds[conflict.Kind] = conflict
	}
	if kinds["priority"].Value != "18100" || kinds["priority"].Engines[0] != "warp-wg" || kinds["table"].Value != "201" {
		t.Fatalf("unexpected policy ownership conflicts: %+v", conflicts)
	}
	report := Report{Engines: []EngineReport{{Status: engine.Status{ID: "warp-wg", Running: true}}}, Conflicts: conflicts}
	if got := report.ApplyConflicts([]string{"warp-wg"}); len(got) != 2 {
		t.Fatalf("running adapter hid foreign policy resources: %+v", got)
	}
	if got := report.ApplyConflicts([]string{"sing-box"}); len(got) != 0 {
		t.Fatalf("own sing-box policy was reported as foreign: %+v", got)
	}
}

func TestDNSListenerIsScopedToDNSControl(t *testing.T) {
	manager := New(nil)
	manager.Statuses = func() []engine.Status {
		return []engine.Status{{ID: "sing-box", Name: "Sing-box", Installed: true, Configured: true, Running: true, RuntimeReady: true}}
	}
	manager.System = func() systemprobe.Snapshot { return systemprobe.Snapshot{IPCommand: true} }
	manager.ListeningPorts = func() map[string]string {
		return map[string]string{"53": "udp UNCONN 0 0 0.0.0.0:53 users:((\"ndnproxy\",pid=731,fd=7))"}
	}
	report := manager.Inspect()
	if !report.Ready {
		t.Fatalf("DNS listener must not block unrelated engine probes: %+v", report)
	}
	if len(report.Conflicts) != 1 || report.Conflicts[0].Kind != "dns" || report.Conflicts[0].SystemUse == "" {
		t.Fatalf("DNS ownership conflict = %+v", report.Conflicts)
	}
	conflicts := report.ApplyConflicts([]string{"dns-control"})
	if len(conflicts) != 1 || conflicts[0].Kind != "dns" {
		t.Fatalf("dns-control conflicts = %+v", conflicts)
	}
	if got := report.ApplyConflicts([]string{"sing-box"}); len(got) != 0 {
		t.Fatalf("unrelated conflicts = %+v", got)
	}
}

func TestDNSListenerOwnerFallsBackWithoutProcessMetadata(t *testing.T) {
	conflict, ok := dnsListenerConflict(map[string]string{"53": "udp 0 0 0.0.0.0:53 0.0.0.0:*"})
	if !ok || conflict.SystemUse == "" || conflict.Engines[0] != "dns-control" {
		t.Fatalf("conflict = %+v, ok=%v", conflict, ok)
	}
}

func hasResource(resources []Resource, kind, value string) bool {
	for _, resource := range resources {
		if resource.Kind == kind && resource.Value == value {
			return true
		}
	}
	return false
}
