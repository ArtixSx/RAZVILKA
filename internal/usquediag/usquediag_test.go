package usquediag

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct{ calls []Command }

func (f *fakeRunner) Run(_ context.Context, command Command) ([]byte, error) {
	f.calls = append(f.calls, command)
	switch {
	case filepath.Base(command.Name) == "ndmc" && len(command.Env) == 0:
		return nil, errors.New("wrong library")
	case filepath.Base(command.Name) == "ndmc":
		return []byte("Keenetic"), nil
	case strings.Contains(strings.Join(command.Args, " "), "addr show"):
		return []byte("3: opkgtun0 inet 172.31.255.100/32"), nil
	case strings.Contains(strings.Join(command.Args, " "), "route get"):
		return []byte("162.159.198.2 via 192.0.2.1 dev eth3"), nil
	case len(command.Args) == 1 && command.Args[0] == "status":
		return []byte("usque is running"), nil
	default:
		return nil, errors.New("unexpected command")
	}
}

type fakeHTTP struct{ methods *[]string }

func (f fakeHTTP) Do(req *http.Request) (*http.Response, error) {
	if f.methods != nil {
		*f.methods = append(*f.methods, req.Method)
	}
	return &http.Response{StatusCode: http.StatusMethodNotAllowed, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestDoctorReportsSafeMetadataAndNDMCLibraryIssue(t *testing.T) {
	root := t.TempDir()
	paths := func(name string) string { return filepath.Join(root, name) }
	for _, name := range []string{"usque", "S51usque", "ndmc", "ip"} {
		if err := os.WriteFile(paths(name), []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths("usque.conf"), []byte("IFACE=\"opkgtun0\"\nSNI=\"ozon.ru\"\nHTTP2_ENABLE=0\nCONFIG_VERSION=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths("usque-feed.conf"), []byte("src/gz usque-keenetic https://side-effect-tm.github.io/usque-keenetic/all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths("opkg-status"), []byte("Package: usque-keenetic\nVersion: 1.4.2-1\n\nPackage: usque-core\nVersion: 1.4.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	session := `{"private_key":"secret","endpoint_pub_key":"public","id":"device","access_token":"token","endpoint_v4":"162.159.198.2","endpoint_h2_v4":"162.159.198.2"}`
	if err := os.WriteFile(paths("session.conf"), []byte(session), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths("evidence.json"), []byte(`{"checked_at":"2026-08-28T00:00:00Z","transport":"HTTP/2","warp":"on","colo":"DME","loc":"RU","egress_ip":"203.0.113.8","confirmed_routes":["Telegram"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	m := &Manager{Runner: runner, HTTP: fakeHTTP{}, BinaryCandidates: []string{paths("usque")}, Architecture: "arm64", FeedPatterns: []string{paths("usque-feed.conf")}, PackageStatusCandidates: []string{paths("opkg-status")}, ConfigPath: paths("usque.conf"), SessionPath: paths("session.conf"), InitPath: paths("S51usque"), NDMCPath: paths("ndmc"), IPCandidates: []string{paths("ip")}, RegistrationURL: "https://api.cloudflareclient.com/v0a4471/reg", EvidencePath: paths("evidence.json")}
	report := m.Check(context.Background())
	if !report.OK || report.State != "attention" || report.Config.SNI != "ozon.ru" || report.EndpointRoute != "eth3" || report.Evidence.Warp != "on" || strings.Join(report.Evidence.ConfirmedRoutes, ",") != "Telegram" || report.Versions.Package != "1.4.2-1" || report.Versions.Core != "1.4.2" {
		t.Fatalf("report=%+v", report)
	}
	if report.Ownership.RuntimeOwner != "consistent-with-usque-init" || report.Environment.RouteTool == "" || report.Environment.NDMCMode != "system-libraries-only" {
		t.Fatalf("environment/ownership=%+v %+v", report.Environment, report.Ownership)
	}
	if !report.Files["session"].Present || report.Files["session"].Mode == "" || len(report.Files["session"].SHA256) != 64 {
		t.Fatalf("safe file metadata=%+v", report.Files)
	}
	encoded := strings.ToLower(strings.Join(report.Recommendations, " "))
	if !strings.Contains(encoded, "ld_library_path") {
		t.Fatalf("missing ndmc recommendation: %+v", report.Recommendations)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret", "token"} {
		if strings.Contains(strings.ToLower(string(payload)), secret) {
			t.Fatalf("secret leaked into report")
		}
	}
}

func TestLatestBackupReturnsOnlySafeMetadata(t *testing.T) {
	root := t.TempDir()
	oldPath := filepath.Join(root, "session.old.bak")
	newPath := filepath.Join(root, "session.new.bak")
	for path, contents := range map[string]string{oldPath: "old-secret", newPath: "new-secret"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Now().Add(-time.Hour)
	newTime := time.Now().Add(-time.Minute)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	metadata := latestFileMetadata([]string{filepath.Join(root, "*.bak")})
	if !metadata.Present || metadata.Name != filepath.Base(newPath) || metadata.Mode == "" || len(metadata.SHA256) != 64 {
		t.Fatalf("metadata=%+v", metadata)
	}
	encoded, _ := json.Marshal(metadata)
	if strings.Contains(string(encoded), "new-secret") {
		t.Fatalf("backup contents leaked: %s", encoded)
	}
}

func TestNDMCRepairPreviewRecognizesScopedCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "S51usque")
	contents := "#!/bin/sh\nout=$(LD_LIBRARY_PATH=/lib:/usr/lib /bin/ndmc -c \"$1\")\nLD_LIBRARY_PATH=/lib:/usr/lib /bin/ndmc -c 'show version'\n"
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	preview := previewNDMCRepair(path, "current-environment")
	if preview.Status != "protected" || preview.Needed || !preview.Eligible || preview.NDMCInvocations != 2 || preview.ScopedInvocations != 2 || preview.GlobalLibraryPath {
		t.Fatalf("preview=%+v", preview)
	}
}

func TestNDMCRepairPreviewRequiresScopedPatchWithoutChangingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "S51usque")
	contents := "#!/bin/sh\n/bin/ndmc -c 'show version'\n"
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	preview := previewNDMCRepair(path, "system-libraries-only")
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Status != "needed" || !preview.Needed || !preview.Eligible || preview.NDMCInvocations != 1 || preview.ScopedInvocations != 0 {
		t.Fatalf("preview=%+v", preview)
	}
	if string(after) != contents {
		t.Fatal("repair preview changed init script")
	}
}

func TestNDMCRepairPreviewBlocksGlobalLibraryPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "S51usque")
	contents := "#!/bin/sh\nexport LD_LIBRARY_PATH=/opt/lib\n/bin/ndmc -c 'show version'\n"
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	preview := previewNDMCRepair(path, "system-libraries-only")
	if preview.Status != "blocked" || preview.Eligible || !preview.GlobalLibraryPath || len(preview.Blockers) == 0 {
		t.Fatalf("preview=%+v", preview)
	}
}

func TestInstalledVersionsAreReadFromLocalOPKGMetadata(t *testing.T) {
	root := t.TempDir()
	status := filepath.Join(root, "status")
	contents := "Package: unrelated\nVersion: 9\n\nPackage: usque-keenetic\nVersion: 2.0.0-r3\n\nPackage: usque\nVersion: 1.9.4+keenetic\n"
	if err := os.WriteFile(status, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	pkg, core, source := readInstalledVersions([]string{filepath.Join(root, "missing"), status})
	if pkg != "2.0.0-r3" || core != "1.9.4+keenetic" || source != status {
		t.Fatalf("pkg=%q core=%q source=%q", pkg, core, source)
	}
}

func TestDoctorDetectsEndpointRoutingLoop(t *testing.T) {
	root := t.TempDir()
	paths := func(name string) string { return filepath.Join(root, name) }
	for _, name := range []string{"usque", "S51usque", "ip"} {
		if err := os.WriteFile(paths(name), []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths("usque.conf"), []byte("IFACE=eth3\nHTTP2_ENABLE=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths("session.conf"), []byte(`{"private_key":"secret","endpoint_pub_key":"public","id":"device","access_token":"token","endpoint_v4":"162.159.198.2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report := (&Manager{Runner: &fakeRunner{}, BinaryCandidates: []string{paths("usque")}, Architecture: "arm64", ConfigPath: paths("usque.conf"), SessionPath: paths("session.conf"), InitPath: paths("S51usque"), IPCandidates: []string{paths("ip")}}).Check(context.Background())
	if report.OK || len(report.EndpointRoutes) != 1 || !report.EndpointRoutes[0].DependencyLoop || report.EndpointRoutes[0].Expected {
		t.Fatalf("routing loop not blocked: %+v", report)
	}
	assertCheckStatus(t, report, "endpoint-route-ipv4", "fail")
}

func TestDoctorIsReadOnlyAndUsesOnlyWhitelistedCommands(t *testing.T) {
	root := t.TempDir()
	paths := func(name string) string { return filepath.Join(root, name) }
	files := map[string]struct {
		contents string
		mode     os.FileMode
	}{
		"usque":         {"binary", 0o700},
		"S51usque":      {"init", 0o700},
		"ndmc":          {"ndmc", 0o700},
		"ip":            {"ip", 0o700},
		"usque.conf":    {"IFACE=opkgtun0\nHTTP2_ENABLE=0\n", 0o600},
		"session.conf":  {`{"private_key":"secret","endpoint_pub_key":"public","id":"device","access_token":"token","endpoint_v4":"162.159.198.2"}`, 0o600},
		"feed.conf":     {"src/gz usque-keenetic https://side-effect-tm.github.io/usque-keenetic/all\n", 0o600},
		"opkg-status":   {"Package: usque-keenetic\nVersion: 1.4.2\n", 0o600},
		"evidence.json": {`{"checked_at":"2026-08-28T00:00:00Z","warp":"on","confirmed_routes":["Telegram"]}`, 0o600},
	}
	before := map[string][]byte{}
	beforeMode := map[string]os.FileMode{}
	for name, fixture := range files {
		if err := os.WriteFile(paths(name), []byte(fixture.contents), fixture.mode); err != nil {
			t.Fatal(err)
		}
		before[name], _ = os.ReadFile(paths(name))
		info, _ := os.Stat(paths(name))
		beforeMode[name] = info.Mode()
	}
	runner := &fakeRunner{}
	methods := []string{}
	m := &Manager{
		Runner: runner, HTTP: fakeHTTP{methods: &methods}, BinaryCandidates: []string{paths("usque")}, Architecture: "arm64",
		FeedPatterns: []string{paths("feed.conf")}, PackageStatusCandidates: []string{paths("opkg-status")}, ConfigPath: paths("usque.conf"),
		SessionPath: paths("session.conf"), InitPath: paths("S51usque"), NDMCPath: paths("ndmc"), IPCandidates: []string{paths("ip")},
		RegistrationURL: "https://api.cloudflareclient.com/v0a4471/reg", EvidencePath: paths("evidence.json"),
	}
	_ = m.Check(context.Background())
	for name := range files {
		after, err := os.ReadFile(paths(name))
		if err != nil || string(after) != string(before[name]) {
			t.Fatalf("doctor changed %s", name)
		}
		info, err := os.Stat(paths(name))
		if err != nil || info.Mode() != beforeMode[name] {
			t.Fatalf("doctor changed mode for %s", name)
		}
	}
	for _, command := range runner.calls {
		joined := strings.ToLower(strings.Join(command.Args, " "))
		for _, forbidden := range []string{" start", " stop", " restart", " add ", " delete ", " replace ", " flush ", " apply", "register"} {
			if strings.Contains(" "+joined+" ", forbidden) {
				t.Fatalf("mutating command was attempted: %+v", command)
			}
		}
		allowed := (len(command.Args) == 1 && command.Args[0] == "status") ||
			strings.Contains(joined, "addr show") || strings.Contains(joined, "route get") || joined == "-c show version"
		if !allowed {
			t.Fatalf("unexpected command: %+v", command)
		}
	}
	if strings.Join(methods, ",") != http.MethodGet {
		t.Fatalf("unexpected HTTP methods: %v", methods)
	}
}

func TestFeedDeclarationsDetectDuplicates(t *testing.T) {
	root := t.TempDir()
	line := "src/gz usque-keenetic https://side-effect-tm.github.io/usque-keenetic/all\n"
	if err := os.WriteFile(filepath.Join(root, "a.conf"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.conf"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	count, files := feedDeclarations([]string{filepath.Join(root, "*.conf")})
	if count != 2 || files != 2 {
		t.Fatalf("count=%d files=%d", count, files)
	}
}

func TestSessionRejectsMissingSecretFieldsWithoutReturningValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.conf")
	if err := os.WriteFile(path, []byte(`{"endpoint_v4":"162.159.198.2","private_key":"hidden"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoints, valid, _, err := readSafeSession(path)
	if err != nil || valid || endpoints.IPv4 != "162.159.198.2" {
		t.Fatalf("endpoints=%+v valid=%v err=%v", endpoints, valid, err)
	}
}

func TestDoctorBlocksWhenInitAndInterfaceAreMissing(t *testing.T) {
	root := t.TempDir()
	paths := func(name string) string { return filepath.Join(root, name) }
	for _, name := range []string{"usque", "usque-feed.conf"} {
		contents := "x"
		if name == "usque-feed.conf" {
			contents = "src/gz usque-keenetic https://side-effect-tm.github.io/usque-keenetic/all\n"
		}
		if err := os.WriteFile(paths(name), []byte(contents), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths("usque.conf"), []byte("HTTP2_ENABLE=0\nCONFIG_VERSION=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	session := `{"private_key":"secret","endpoint_pub_key":"public","id":"device","access_token":"token","endpoint_v4":"162.159.198.2"}`
	if err := os.WriteFile(paths("session.conf"), []byte(session), 0o600); err != nil {
		t.Fatal(err)
	}

	report := (&Manager{
		Runner: &fakeRunner{}, BinaryCandidates: []string{paths("usque")}, Architecture: "arm64",
		FeedPatterns: []string{paths("usque-feed.conf")}, ConfigPath: paths("usque.conf"),
		SessionPath: paths("session.conf"), InitPath: paths("missing-init"),
		IPCandidates: []string{paths("missing-ip")},
	}).Check(context.Background())

	if report.OK || report.Readiness != "BLOCKED" || report.State != "problem" {
		t.Fatalf("unexpected summary: %+v", report)
	}
	assertCheckStatus(t, report, "service-init", "fail")
	assertCheckStatus(t, report, "interface-config", "fail")
	for _, id := range []string{"tun-ipv4", "tun-ipv6", "endpoint-route-ipv4", "endpoint-route-ipv6"} {
		assertCheckStatus(t, report, id, "skipped")
	}
}

func TestDoctorReportsUnknownWhenRouteToolCannotRun(t *testing.T) {
	root := t.TempDir()
	paths := func(name string) string { return filepath.Join(root, name) }
	for _, name := range []string{"usque", "S51usque"} {
		if err := os.WriteFile(paths(name), []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths("usque-feed.conf"), []byte("src/gz usque-keenetic https://side-effect-tm.github.io/usque-keenetic/all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths("usque.conf"), []byte("IFACE=opkgtun0\nHTTP2_ENABLE=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	session := `{"private_key":"secret","endpoint_pub_key":"public","id":"device","access_token":"token","endpoint_v4":"162.159.198.2"}`
	if err := os.WriteFile(paths("session.conf"), []byte(session), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths("evidence.json"), []byte(`{"checked_at":"2026-08-28T00:00:00Z","transport":"HTTP/2","warp":"on","confirmed_routes":["Telegram"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	report := (&Manager{
		Runner: &fakeRunner{}, BinaryCandidates: []string{paths("usque")}, Architecture: "arm64",
		FeedPatterns: []string{paths("usque-feed.conf")}, ConfigPath: paths("usque.conf"),
		SessionPath: paths("session.conf"), InitPath: paths("S51usque"),
		IPCandidates: []string{paths("missing-ip")}, EvidencePath: paths("evidence.json"),
	}).Check(context.Background())

	if !report.OK || report.Readiness != "UNKNOWN" || report.State != "attention" {
		t.Fatalf("unexpected summary: %+v", report)
	}
	for _, id := range []string{"tun-ipv4", "tun-ipv6", "endpoint-route-ipv4", "endpoint-route-ipv6"} {
		assertCheckStatus(t, report, id, "skipped")
	}
}

func assertCheckStatus(t *testing.T, report Report, id, status string) {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			if check.Status != status {
				t.Fatalf("check %s status=%s, want %s", id, check.Status, status)
			}
			if status == "skipped" && strings.TrimSpace(check.Message) == "" {
				t.Fatalf("skipped check %s has no reason", id)
			}
			return
		}
	}
	t.Fatalf("check %s not found in %+v", id, report.Checks)
}
