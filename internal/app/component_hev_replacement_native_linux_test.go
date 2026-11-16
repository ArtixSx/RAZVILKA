//go:build linux && amd64 && razvilka_native_fixture && razvilka_hev_altstack_lab

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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
	"golang.org/x/sys/unix"
)

func TestHEVOriginalNativeHTTPSameVersionReplacement(t *testing.T) {
	if os.Getenv("RAZVILKA_HEV_REPLACEMENT_NATIVE") != "1" {
		t.Skip("separate pinned source-build lab in private namespace only")
	}
	if os.Geteuid() != 0 || os.Getpid() != 1 {
		t.Fatal("private original PID namespace required")
	}
	for _, pair := range [][2]string{{"/proc/self/ns/net", "/proc/self/fd/8"}, {"/proc/self/ns/mnt", "/proc/self/fd/9"}} {
		a, e1 := os.Stat(pair[0])
		b, e2 := os.Stat(pair[1])
		if e1 != nil || e2 != nil || os.SameFile(a, b) {
			t.Fatal("private network/mount namespace required")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	old, err := os.ReadFile(os.Getenv("RAZVILKA_HEV_OFFICIAL_NATIVE"))
	if err != nil {
		t.Fatal(err)
	}
	desired, err := os.ReadFile(os.Getenv("RAZVILKA_HEV_NATIVE"))
	if err != nil {
		t.Fatal(err)
	}
	asset, pin, err := components.HEVNativeFixtureAsset("amd64")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(desired)
	if hex.EncodeToString(sum[:]) != pin {
		t.Fatal("exact lab bytes required")
	}
	for _, dir := range []string{installpath.Config, installpath.State} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.SafeMode = false
	raw, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(installpath.Config, "config.json")
	if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cm := components.New()
	cm.Client = &http.Client{Transport: mihomoServiceArchiveTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != asset {
			return nil, errors.New("unexpected HEV fixture URL")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(desired))}, nil
	})}
	manager := dataplane.New(filepath.Join(installpath.State, "dataplane"))
	fresh := func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() }
	manager.FreshProfile = fresh
	a := &App{Store: store, Components: cm, Dataplane: manager, FreshProfile: fresh, ComponentHistory: updatecheck.NewComponentHistoryAdmission(components.MihomoReleaseReadVersion), ExecutionHistory: updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion), SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: filepath.Join(installpath.State, "self-update-stop"), Directory: filepath.Join(installpath.State, "self-update-files")}}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	held, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = operationgate.InitializeSelfUpdateControl(held, a.SelfUpdateFiles.ControlRoot)
	if err == nil {
		err = a.ComponentHistory.CheckWrite(held, components.HEVReleaseReadVersion)
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
	installed, err := cm.InstallHEVPredecessorNativeFixture(held, old, a.hevForwardGuard(store.Get(), control), control.WithRename)
	closeErr := control.Close()
	release()
	if err != nil || closeErr != nil || !installed.OK {
		t.Fatal("original predecessor installation", installed, err, closeErr)
	}
	if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	const token = "hev-source-lab-native-http-token-1234567890"
	a.Security, err = security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
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
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, b
	}
	paths := []string{"/opt/bin/hev-socks5-tunnel", "/opt/bin/.hev-socks5-tunnel.razvilka.json", filepath.Join(cm.StateDir, "receipts", "hev-socks5-tunnel.json")}
	before := map[string][]byte{}
	for _, p := range paths {
		before[p], err = os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	assertBefore := func() {
		t.Helper()
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(b, before[p]) {
				t.Fatal("refused update changed original triple", p, err)
			}
		}
		if err := cm.CheckHEVReleaseIdle(ctx); err != nil {
			t.Fatal("refusal left journal pending", err)
		}
	}
	status, body := request("GET", "/api/v1/components/hev-socks5-tunnel/plan?action=update&refresh=true")
	var plan components.Plan
	if status != 200 || json.Unmarshal(body, &plan) != nil || !plan.Ready || plan.InstalledVersion != "2.17.1" || plan.AvailableVersion != "2.17.1" {
		t.Fatal("same-version exact-image update unavailable", status, string(body))
	}
	for _, row := range []struct {
		name string
		data []byte
	}{{"old", old}, {"desired", desired}} {
		func() {
			root := t.TempDir()
			worker := filepath.Join(root, "opaque-worker")
			fifo := filepath.Join(root, "input")
			if err := os.WriteFile(worker, row.data, 0500); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, worker, fifo)
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
			pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pidfd)
			proc := fmt.Sprintf("/proc/%d", command.Process.Pid)
			birth := func() string {
				b, err := os.ReadFile(proc + "/stat")
				if err != nil {
					t.Fatal(err)
				}
				fields := strings.Fields(string(b)[strings.LastIndexByte(string(b), ')')+1:])
				if len(fields) <= 19 {
					t.Fatal("original birth unavailable")
				}
				return fields[19]
			}
			initialBirth := birth()
			observed, err := os.ReadFile(proc + "/exe")
			if err != nil || !bytes.Equal(observed, row.data) {
				t.Fatal("original worker image unavailable", err)
			}
			if n, err := unix.Poll([]unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}, 0); err != nil || n != 0 || birth() != initialBirth {
				t.Fatal("original worker exited or changed before admission", err)
			}
			status, body = request("POST", "/api/v1/components/hev-socks5-tunnel/update")
			if status == 200 || !strings.Contains(string(body), dataplane.ErrRuntimeInactivity.Error()) {
				t.Fatal("renamed image did not reach actual inactivity refusal", row.name, status, string(body))
			}
			assertBefore()
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = command.Wait()
			waited = true
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal("original worker not joined", err)
			}
			t.Logf("actual renamed %s ELF refused; original pidfd/birth/image retained and sole Wait joined; FIFO pre-init process recognition only", row.name)
		}()
	}
	status, body = request("POST", "/api/v1/components/hev-socks5-tunnel/update")
	var updated components.Result
	if status != 200 || json.Unmarshal(body, &updated) != nil || !updated.OK {
		t.Fatal("actual same-version HTTP replacement failed", status, string(body))
	}
	current, err := os.ReadFile(paths[0])
	if err != nil || !bytes.Equal(current, desired) {
		t.Fatal("desired binary mismatch", err)
	}
	var receipt struct{ Version, SHA256 string }
	b, err := os.ReadFile(paths[1])
	if err != nil || json.Unmarshal(b, &receipt) != nil || receipt.Version != "2.17.1" || receipt.SHA256 != pin {
		t.Fatal("desired receipt mismatch", err)
	}
	var lifecycle struct {
		BeforeVersion string `json:"before_version"`
		AfterVersion  string `json:"after_version"`
		Action        string `json:"action"`
	}
	life, err := os.ReadFile(paths[2])
	if err != nil || json.Unmarshal(life, &lifecycle) != nil || lifecycle.BeforeVersion != "2.17.1" || lifecycle.AfterVersion != "2.17.1" || lifecycle.Action != "update" {
		t.Fatal("same-version lifecycle mismatch", err)
	}
	if _, err := cm.CheckInstalledHEV(ctx); err != nil {
		t.Fatal("installed current verification", err)
	}
	if err := cm.CheckHEVReleaseIdle(ctx); err != nil {
		t.Fatal(err)
	}
	status, body = request("GET", "/api/v1/components/hev-socks5-tunnel/plan?action=update")
	if status != 200 || json.Unmarshal(body, &plan) != nil || plan.Ready {
		t.Fatal("identical target remained update-ready", status, string(body))
	}
	t.Log("HEV_NATIVE_SAME_VERSION_REPLACEMENT_PASS exact official→separately pinned source-lab bytes; old/desired live process refusals, full registry inactivity, actual HTTP and receipt/journal verified; no route/router proof")
}
