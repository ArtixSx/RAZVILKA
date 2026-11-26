//go:build linux && razvilka_native_fixture

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
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
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func mihomoReplacementNativeApp(t *testing.T, ctx context.Context) *App {
	t.Helper()
	for _, dir := range []string{installpath.Config, installpath.State} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.SafeMode = false
	configPath := filepath.Join(installpath.Config, "config.json")
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(configPath)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(os.Getenv("RAZVILKA_MIHOMO_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(os.Getenv("RAZVILKA_MIHOMO_PREDECESSOR_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	cm := components.New()
	cm.Client = &http.Client{Transport: mihomoServiceArchiveTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz" {
			return nil, errors.New("unexpected target release")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(archive))}, nil
	})}
	m := dataplane.New(filepath.Join(installpath.State, "dataplane"))
	fresh := func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() }
	m.FreshProfile = fresh
	a := &App{Store: store, Components: cm, Dataplane: m, FreshProfile: fresh,
		ComponentHistory: updatecheck.NewComponentHistoryAdmission(components.MihomoReleaseReadVersion), ExecutionHistory: updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion),
		SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: filepath.Join(installpath.State, "self-update-stop"), Directory: filepath.Join(installpath.State, "self-update-files")}}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	held, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = operationgate.InitializeSelfUpdateControl(held, a.SelfUpdateFiles.ControlRoot)
	if err == nil {
		err = a.ComponentHistory.CheckWrite(held, components.MihomoReleaseReadVersion)
	}
	if err != nil {
		release()
		t.Fatal(err)
	}
	control, err := a.Operations.ReviewControlEpoch(held, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		release()
		t.Fatal(err)
	}
	result, err := cm.InstallMihomoPredecessorNativeFixture(held, previous, a.hevForwardGuard(store.Get(), control), control.WithRename)
	closeErr := control.Close()
	release()
	if err != nil || closeErr != nil || !result.OK {
		t.Fatal("actual predecessor installer", result, err, closeErr)
	}
	if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMihomoReplacementOriginalMainSetup(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_MAIN_SETUP") != "1" {
		t.Skip("actual ordinary Main fixture setup only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	mihomoReplacementNativeApp(t, ctx)
	t.Log("original pinned predecessor and known idle package journal prepared; no ordinary-Main inactivity or update claim")
}

func TestMihomoOriginalNativeHTTPVersionReplacement(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_REPLACEMENT_NATIVE") != "1" {
		t.Skip("official predecessor/current archives and private PID/net/mount namespace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	a := mihomoReplacementNativeApp(t, ctx)
	cm := a.Components
	const token = "mihomo-real-replacement-http-native-token-123456789"
	gate, err := security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	a.Security = gate
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	request := func(method, path string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Origin", server.URL)
		r.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	receiptPath := "/opt/bin/.mihomo.razvilka.json"
	receipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	lifecyclePath := filepath.Join(cm.StateDir, "receipts", "mihomo.json")
	oldLifecycle, err := os.ReadFile(lifecyclePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte(`{"version":"1.19.32","sha256":"bad"}`)} {
		if bad == nil {
			err = os.Remove(receiptPath)
		} else {
			err = os.WriteFile(receiptPath, bad, 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		status, body := request("GET", "/api/v1/components/mihomo/plan?action=update&refresh=true")
		var plan components.Plan
		if status != 200 || json.Unmarshal(body, &plan) != nil || plan.Ready {
			t.Fatal("foreign/missing receipt accepted", status, string(body))
		}
		if err := os.WriteFile(receiptPath, receipt, 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldBytes, err := os.ReadFile("/opt/bin/mihomo")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"size", "hash"} {
		altered := append([]byte(nil), oldBytes...)
		if change == "size" {
			altered = append(altered, 0)
		} else {
			altered[0] ^= 1
		}
		if err := os.WriteFile("/opt/bin/mihomo", altered, 0755); err != nil {
			t.Fatal(err)
		}
		status, body := request("GET", "/api/v1/components/mihomo/plan?action=update")
		var alteredPlan components.Plan
		if status != 200 || json.Unmarshal(body, &alteredPlan) != nil || alteredPlan.Ready {
			t.Fatal("changed historical image admitted", change, status, string(body))
		}
		if err := os.WriteFile("/opt/bin/mihomo", oldBytes, 0755); err != nil {
			t.Fatal(err)
		}
	}
	status, body := request("GET", "/api/v1/components/mihomo/plan?action=update")
	var plan components.Plan
	if status != 200 || json.Unmarshal(body, &plan) != nil || !plan.Ready || plan.InstalledVersion != "1.19.32" || plan.AvailableVersion != "1.19.33" {
		t.Fatal("real predecessor update unavailable", status, string(body))
	}
	old, err := os.ReadFile("/opt/bin/mihomo")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	opaque := filepath.Join(root, "opaque-old-worker")
	if err := os.WriteFile(opaque, old, 0500); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "old.json")
	if err := os.WriteFile(profile, []byte(`{"socks-port":29995,"bind-address":"127.0.0.1","allow-lan":false,"mode":"direct","log-level":"error","proxies":[],"rules":["MATCH,DIRECT"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, opaque, "-f", profile, "-d", root)
	command.Env = []string{}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	deadline := time.Now().Add(8 * time.Second)
	for {
		connection, e := net.DialTimeout("tcp4", "127.0.0.1:29995", 50*time.Millisecond)
		if e == nil {
			connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual old image never listened", e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	status, body = request("GET", "/api/v1/components/mihomo/plan?action=update")
	if status != 200 || json.Unmarshal(body, &plan) != nil || !plan.Ready || plan.InstalledVersion != "1.19.32" || plan.AvailableVersion != "1.19.33" {
		t.Fatal("live fixture did not reach runtime admission", status, string(body))
	}
	status, body = request("POST", "/api/v1/components/mihomo/update")
	if status == 200 || !strings.Contains(string(body), dataplane.ErrRuntimeInactivity.Error()) {
		t.Fatal("live renamed predecessor did not receive actual global inactivity refusal", status, string(body))
	}
	after, err := os.ReadFile("/opt/bin/mihomo")
	if err != nil || !bytes.Equal(old, after) {
		t.Fatal("refusal changed installed old image", err)
	}
	afterReceipt, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(receipt, afterReceipt) {
		t.Fatal("refusal changed original receipt", err)
	}
	afterLifecycle, err := os.ReadFile(lifecyclePath)
	if err != nil || !bytes.Equal(oldLifecycle, afterLifecycle) {
		t.Fatal("refusal changed original lifecycle", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	waited = true
	started := time.Now()
	status, body = request("POST", "/api/v1/components/mihomo/update")
	var updated components.Result
	if status != 200 || json.Unmarshal(body, &updated) != nil || !updated.OK || !updated.InstalledIdleAccepted {
		t.Fatal("actual HTTP update failed", status, string(body))
	}
	current, err := os.ReadFile("/opt/bin/mihomo")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(current)
	if len(current) != 62017662 || hex.EncodeToString(hash[:]) != "09c2cb429cf45fb56884ceb91a0e5b17cc8b2c866c07811bcf75dfb59fef7662" {
		t.Fatal("actual target bytes mismatch")
	}
	var owner struct{ Version, SHA256 string }
	afterReceipt, err = os.ReadFile(receiptPath)
	if err != nil || json.Unmarshal(afterReceipt, &owner) != nil || owner.Version != "1.19.33" || owner.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("target receipt mismatch", err)
	}
	var lifecycle struct {
		BeforeVersion string `json:"before_version"`
		AfterVersion  string `json:"after_version"`
	}
	life, err := os.ReadFile(filepath.Join(cm.StateDir, "receipts", "mihomo.json"))
	if err != nil || json.Unmarshal(life, &lifecycle) != nil || lifecycle.BeforeVersion != "1.19.32" || lifecycle.AfterVersion != "1.19.33" {
		t.Fatal("target lifecycle mismatch", err)
	}
	if err := cm.CheckMihomoReleaseIdle(ctx); err != nil {
		t.Fatal(err)
	}
	if operation := a.runtimeLifecycle("mihomo").Operations["package_update"]; operation.Registration != "registered" || operation.Available != nil {
		t.Fatal("registration/readiness drift", operation)
	}
	if a.runtimeLifecycle("mihomo").Operations["live_apply"].Registration != "absent" {
		t.Fatal("update invented routing")
	}
	t.Logf("actual HTTP update1.19.32→1.19.33 elapsed=%s: real renamed old process and missing/tampered receipt refused; sole fixture Wait then complete global inactivity, exact new binary/receipt/lifecycle and idle journal; no service/live-apply claim", time.Since(started))
}
