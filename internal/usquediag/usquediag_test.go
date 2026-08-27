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

type fakeHTTP struct{}

func (fakeHTTP) Do(*http.Request) (*http.Response, error) {
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
	session := `{"private_key":"secret","endpoint_pub_key":"public","id":"device","access_token":"token","endpoint_v4":"162.159.198.2","endpoint_h2_v4":"162.159.198.2"}`
	if err := os.WriteFile(paths("session.conf"), []byte(session), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	m := &Manager{Runner: runner, HTTP: fakeHTTP{}, BinaryCandidates: []string{paths("usque")}, Architecture: "arm64", FeedPatterns: []string{paths("usque-feed.conf")}, ConfigPath: paths("usque.conf"), SessionPath: paths("session.conf"), InitPath: paths("S51usque"), NDMCPath: paths("ndmc"), IPCandidates: []string{paths("ip")}, RegistrationURL: "https://api.cloudflareclient.com/v0a4471/reg"}
	report := m.Check(context.Background())
	if !report.OK || report.State != "attention" || report.Config.SNI != "ozon.ru" || report.EndpointRoute != "eth3" {
		t.Fatalf("report=%+v", report)
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
