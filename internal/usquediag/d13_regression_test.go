package usquediag

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDoctorDowngradesHistoricalCanaryAndUsesSelectedTransportEndpoint(t *testing.T) {
	root := t.TempDir()
	path := func(name string) string { return filepath.Join(root, name) }
	for name, contents := range map[string]string{
		"usque": "binary", "S51usque": "init", "ip": "ip",
		"usque.conf":   "IFACE=opkgtun0\nHTTP2_ENABLE=1\n",
		"session.conf": `{"private_key":"private-key-marker","endpoint_pub_key":"public","id":"private-device-marker","access_token":"private-token-marker","endpoint_v4":"162.159.198.2","endpoint_h2_v4":"162.159.198.3"}`,
	} {
		if err := os.WriteFile(path(name), []byte(contents), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	runner := &fakeRunner{}
	environmentID := strings.Repeat("a", 64)
	m := &Manager{Runner: runner, BinaryCandidates: []string{path("usque")}, Architecture: "arm64", ConfigPath: path("usque.conf"), SessionPath: path("session.conf"), InitPath: path("S51usque"), IPCandidates: []string{path("ip")}, EvidencePath: path("evidence.json"), EvidenceEnvironment: func(context.Context) (string, error) { return environmentID, nil }, Now: func() time.Time { return now }}
	binding := CanaryBinding(inspectFile(m.ConfigPath).SHA256, inspectFile(m.SessionPath).SHA256, inspectFile(path("usque")).SHA256, environmentID)
	receipt := CanaryEvidence{CheckedAt: now.Add(-time.Minute).Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339), BindingID: binding, Endpoint: "162.159.198.3:443", Transport: "HTTP/2", Warp: "on", ConfirmedRoutes: []string{"Telegram"}}
	save := func() {
		t.Helper()
		data, _ := json.Marshal(receipt)
		if err := os.WriteFile(m.EvidencePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	report := m.Check(context.Background())
	if !report.Capabilities.Fresh || report.Capabilities.HTTP2 != "confirmed" || report.Capabilities.UDP != "unknown" {
		t.Fatalf("capabilities=%+v", report.Capabilities)
	}
	assertCheckStatus(t, report, "warp-evidence", "pass")
	assertCheckStatus(t, report, "service-evidence", "pass")
	selected := false
	for _, command := range runner.calls {
		args := strings.Join(command.Args, " ")
		if strings.Contains(args, "route get 162.159.198.2") {
			t.Fatal("QUIC endpoint substituted for selected HTTP/2 endpoint")
		}
		selected = selected || args == "route get 162.159.198.3"
	}
	if !selected {
		t.Fatal("HTTP/2 literal endpoint was not inspected")
	}
	// A new network epoch invalidates a still young receipt, without deleting it.
	environmentID = strings.Repeat("b", 64)
	report = m.Check(context.Background())
	if report.Capabilities.Fresh || report.Evidence.Warp != "on" {
		t.Fatal("environment changed proof or lost historical result")
	}
	assertCheckStatus(t, report, "warp-evidence", "warning")
	assertCheckStatus(t, report, "service-evidence", "warning")
	environmentID = strings.Repeat("a", 64)
	// Detect a WAN/DNS epoch change during the diagnostic read itself.
	calls := 0
	m.EvidenceEnvironment = func(context.Context) (string, error) {
		calls++
		if calls == 1 {
			return environmentID, nil
		}
		return strings.Repeat("b", 64), nil
	}
	report = m.Check(context.Background())
	if report.Capabilities.Fresh {
		t.Fatal("network changed during check but receipt stayed fresh")
	}
	m.EvidenceEnvironment = func(context.Context) (string, error) { return environmentID, nil }
	// Exact file changes invalidate an otherwise fresh network-bound receipt.
	if err := os.WriteFile(path("usque"), []byte("changed-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	report = m.Check(context.Background())
	if report.Capabilities.Fresh {
		t.Fatal("changed binary accepted old canary")
	}
	if err := os.WriteFile(path("usque"), []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	report = m.Check(context.Background())
	assertCheckStatus(t, report, "warp-evidence", "warning")
	assertCheckStatus(t, report, "service-evidence", "warning")
	if report.Capabilities.Fresh {
		t.Fatal("expired native canary passed")
	}
	data, _ := json.Marshal(report)
	if strings.Contains(string(data), "private-") {
		t.Fatal("private enrollment material leaked into report")
	}
}

func TestSessionEndpointsRejectPrivateMappedWrongFamilyAndSecretText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.conf")
	for _, value := range []string{"private-token-marker", "127.0.0.1", "192.168.1.1", "::ffff:162.159.198.2", "2606:4700::1111"} {
		data, _ := json.Marshal(map[string]string{"endpoint_v4": value})
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		endpoints, _, _, err := readSafeSession(path)
		if err != nil || endpoints.IPv4 != "" {
			t.Fatalf("unsafe endpoint leaked: %+v %v", endpoints, err)
		}
	}
}
