package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestSelfUpdateStartupSubprocess(t *testing.T) {
	if os.Getenv("RAZVILKA_SELF_UPDATE_BOOTSTRAP_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("razvilka", flag.ExitOnError)
	if fixture := os.Getenv("RAZVILKA_SELF_UPDATE_READER_FIXTURE_TEST"); fixture != "" {
		mainWithSelfUpdateJournalRoots(selfUpdateJournalRoots{installation: filepath.Join(fixture, "installation"), helper: filepath.Join(fixture, "helper"), files: filepath.Join(fixture, "files")})
	} else {
		main()
	}
	os.Exit(0)
}

func selfUpdateMainSubprocess(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, exe, append([]string{"-test.run=^TestSelfUpdateStartupSubprocess$", "--"}, args...)...)
	command.Env = append(os.Environ(), "RAZVILKA_SELF_UPDATE_BOOTSTRAP_TEST=1", "RAZVILKA_SELF_UPDATE_READER_FIXTURE_TEST="+filepath.Join(t.TempDir(), "fixed-protocol"))
	return command.CombinedOutput()
}

func TestSelfUpdateExplicitRootsAndCapability(t *testing.T) {
	work := t.TempDir()
	f, err := configuredSelfUpdateFiles(filepath.Join(work, "installation"), filepath.Join(work, "files"), filepath.Join(work, "helper"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Pending() {
		t.Fatal("missing retained state falsely pending")
	}
	if f.Adapter != nil || f.JournalReadGuard != nil {
		t.Fatal("private root overrides acquired the fixed production provider")
	}
	if _, err := os.Stat(f.Directory); !os.IsNotExist(err) {
		t.Fatal("reader created journal", err)
	}
	for _, bad := range []string{"relative", " " + work, filepath.VolumeName(work) + string(filepath.Separator)} {
		if _, err := configuredSelfUpdateFiles(bad, "", ""); err == nil {
			t.Fatal("unsafe override accepted", bad)
		}
	}
	for _, bad := range []string{filepath.Join(work, "files"), filepath.Join(work, "files", "authority"), work} {
		if _, err := configuredSelfUpdateFiles(filepath.Join(work, "installation"), filepath.Join(work, "files"), filepath.Join(work, "helper"), bad); err == nil {
			t.Fatal("control root overlapping retained journal accepted", bad)
		}
	}
	output, err := selfUpdateMainSubprocess(t, "-self-update-schema")
	if err != nil || strings.TrimSpace(string(output)) != "0" {
		t.Fatal("unsupported consumer advertised", string(output), err)
	}
}

func TestSelfUpdateStartupPendingPrecedesAllOrdinaryWrites(t *testing.T) {
	for _, source := range []string{"file-journal", "helper-receipt"} {
		t.Run(source, func(t *testing.T) {
			work := t.TempDir()
			installation := filepath.Join(work, "installation")
			files := filepath.Join(work, "files")
			helper := filepath.Join(work, "helper")
			configPath := filepath.Join(work, "config.json")
			stage := filepath.Join(work, "staging")
			if err := os.MkdirAll(installation, 0700); err != nil {
				t.Fatal(err)
			}
			root := files
			if source == "helper-receipt" {
				root = helper
			}
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "current.json")
			protected := []byte("retained-corrupt-receipt")
			if err := os.WriteFile(path, protected, 0600); err != nil {
				t.Fatal(err)
			}
			output, err := selfUpdateMainSubprocess(t, "-self-update-installation", installation, "-self-update-file-state", files, "-self-update-helper-state", helper, "-config", configPath, "-stage", stage, "-migrate-config")
			if err == nil || !bytes.Contains(output, []byte("self update recovery required")) {
				t.Fatal("ordinary migration admitted", string(output), err)
			}
			for _, name := range []string{configPath, stage, filepath.Join(work, "private-restore")} {
				if _, err := os.Stat(name); !os.IsNotExist(err) {
					t.Fatal("startup wrote before admission", name, err)
				}
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, protected) {
				t.Fatal("retained journal changed", err)
			}
		})
	}
}

func TestSelfUpdateDurableControlStartupPrecedesBootstrapAndIgnoresMatchingHelper(t *testing.T) {
	for _, state := range []string{"requested", "corrupt", "incomplete"} {
		t.Run(state, func(t *testing.T) {
			work := t.TempDir()
			control := filepath.Join(work, "authority")
			if _, err := operationgate.RequestSelfUpdateStop(context.Background(), control, strings.Repeat("a", 32), 12); err != nil {
				t.Fatal(err)
			}
			current := filepath.Join(control, "current-v1.json")
			if state == "corrupt" {
				if err := os.WriteFile(current, []byte("corrupt authority"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if state == "incomplete" {
				if err := os.Remove(filepath.Join(control, "stop-"+strings.Repeat("a", 32)+".json")); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(current)
			if err != nil {
				t.Fatal(err)
			}
			configPath, stage := filepath.Join(work, "config.json"), filepath.Join(work, "staging")
			output, err := selfUpdateMainSubprocess(t, "-self-update-installation", filepath.Join(work, "installation"), "-self-update-file-state", filepath.Join(work, "files"), "-self-update-helper-state", filepath.Join(work, "helper"), "-self-update-control-state", control, "-config", configPath, "-stage", stage, "-migrate-config")
			if err == nil || !bytes.Contains(output, []byte("self update recovery required")) {
				t.Fatal("durable Stop admitted ordinary bootstrap", string(output), err)
			}
			for _, path := range []string{configPath, stage, filepath.Join(work, "private-restore"), filepath.Join(work, "files"), filepath.Join(work, "helper")} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("startup wrote before authority admission", path, err)
				}
			}
			after, err := os.ReadFile(current)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("restart reset Stop authority", err)
			}
		})
	}
}

func TestSelfUpdateRecoveryBootstrapRealHTTPReadOnly(t *testing.T) {
	work := t.TempDir()
	configPath := filepath.Join(work, "config.json")
	_, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	const token = "self-update-bootstrap-test-admin-token-123456"
	tokenPath := filepath.Join(work, "admin.token")
	credentials := filepath.Join(work, "admin.credentials.json")
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	installation := filepath.Join(work, "installation")
	files := filepath.Join(work, "files")
	helper := filepath.Join(work, "helper")
	dp := filepath.Join(work, "dataplane")
	for _, path := range []string{installation, files} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	protected := []byte("truncated")
	if err := os.WriteFile(filepath.Join(files, "current.json"), protected, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := configuredSelfUpdateFiles(installation, files, helper, filepath.Join(work, "authority"))
	if err != nil {
		t.Fatal(err)
	}
	m := components.New()
	m.StateDir = filepath.Join(work, "components")
	a, err := selfUpdateRecoveryApp(f, configPath, tokenPath, credentials, m, dp)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := selfUpdateRecoveryHandler(a)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(handler)
	defer s.Close()
	for _, test := range []struct {
		method, path string
		code         int
	}{{"GET", "/api/v1/self-update/recovery", 503}, {"GET", "/api/v1/status", 503}, {"POST", "/api/v1/apply", 503}, {"POST", "/api/v1/auth/setup", 503}, {"GET", "/api/v1/components/recovery", 503}} {
		r, err := http.NewRequest(test.method, s.URL+test.path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Origin", s.URL)
		r.Header.Set("Content-Type", "application/json")
		res, err := s.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != test.code {
			t.Fatalf("%s: %d %s", test.path, res.StatusCode, body)
		}
	}
	actual, err := os.ReadFile(filepath.Join(files, "current.json"))
	if err != nil || !bytes.Equal(actual, protected) {
		t.Fatal("corrupt receipt changed", err)
	}
	for _, path := range []string{helper, dp, m.StateDir, credentials, filepath.Join(work, "private-restore")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("recovery bootstrap wrote", path, err)
		}
	}
	if _, err := selfUpdateRecoveryApp(f, filepath.Join(work, "missing-config.json"), tokenPath, credentials, m, dp); err == nil {
		t.Fatal("missing config replaced with defaults")
	}
	if _, err := os.Stat(filepath.Join(work, "missing-config.json")); !os.IsNotExist(err) {
		t.Fatal("missing config created", err)
	}
	stopBody := map[string]any{"action": "stop", "confirm": "STOP_OWNED_ROUTES", "expected_revision": a.Store.Get().Revision}
	encoded, _ := json.Marshal(stopBody)
	request, err := http.NewRequest(http.MethodPost, s.URL+"/api/v1/service-control/runtime", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Origin", s.URL)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	stopData, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted || !bytes.Contains(stopData, []byte(`"authority_revoked":true`)) || !bytes.Contains(stopData, []byte(`"stopped_confirmed":false`)) {
		t.Fatalf("restricted recovery Stop: %d %s", response.StatusCode, stopData)
	}
	actual, err = os.ReadFile(filepath.Join(files, "current.json"))
	if err != nil || !bytes.Equal(actual, protected) {
		t.Fatal("Stop rewrote damaged file transaction", err)
	}
}

func TestSelfUpdateIndependentPrivateFenceNeverRecovers(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "private-restore")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"kind": "razvilka-private-restore", "schema": 1, "scope": strings.Repeat("a", 64), "id": strings.Repeat("b", 32), "state": "committed", "records": []any{}, "digest": strings.Repeat("c", 64)})
	path := filepath.Join(root, "restore.private.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := independentSelfUpdateFences(context.Background(), filepath.Join(work, "config.json"), filepath.Join(work, "dataplane")); err == nil {
		t.Fatal("independent pending restore admitted")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("private journal recovered", err)
	}
}
