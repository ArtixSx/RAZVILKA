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
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// A renamed copy is deliberately not a supported role. The actual cold
// observer must identify its complete image rather than trusting its argv.
func TestMihomoColdForeignCopy(t *testing.T) {
	path := os.Getenv("RAZVILKA_MIHOMO_COPY_READY")
	if path == "" {
		t.Skip("isolated copied-controller refusal helper")
	}
	if err := os.WriteFile(path, []byte("ready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Second)
}

func TestMihomoColdOriginalProducer(t *testing.T) {
	ready := os.Getenv("RAZVILKA_MIHOMO_COLD_READY")
	if ready == "" {
		t.Skip("isolated actual original producer only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	const base = "/opt/etc/razvilka"
	const state = "/opt/razvilka/state"
	for _, path := range []string{base, state} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.SafeMode = false
	configPath := filepath.Join(base, "config.json")
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("native-cold", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	layout := privaterestore.Layout{Config: configPath, CustomServices: filepath.Join(base, "custom-services.json"), Devices: filepath.Join(base, "devices.json"), StageRoot: filepath.Join(state, "staging"), ProviderRoot: filepath.Join(base, "cloudflare-private")}
	for i, generation := range []string{"private-restore", "private-restore-nodes-v1", "private-restore-native-v1", "private-restore-feeds-v1", "private-restore-strategylab-v1"} {
		if i >= 1 {
			layout.NodeRoot = filepath.Join(base, "nodes-private")
		}
		if i >= 2 {
			layout.WarpRoot = filepath.Join(state, "warp")
		}
		if i >= 3 {
			layout.FeedRoot = filepath.Join(base, "subscriptions-private")
		}
		if i >= 4 {
			layout.StrategyLabPath = filepath.Join(state, "strategy-lab.json")
		}
		layout.JournalRoot = filepath.Join(base, generation)
		coordinator, _, err := privaterestore.Open(ctx, layout)
		if err != nil {
			t.Fatal("original private startup lease", i, err)
		}
		defer coordinator.Close()
		if err := coordinator.StartRuntime(); err != nil {
			t.Fatal(err)
		}
	}
	archive, err := os.ReadFile(os.Getenv("RAZVILKA_MIHOMO_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	cm := components.New()
	cm.Client = &http.Client{Transport: mihomoServiceArchiveTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz" {
			return nil, errors.New("unreviewed archive source")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(archive))}, nil
	})}
	manager := dataplane.New(filepath.Join(installpath.State, "dataplane"))
	fresh := func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() } // Label modeled; actual process/PID/net namespace are kernel observations.
	manager.FreshProfile = fresh
	a := &App{Store: store, Components: cm, Dataplane: manager, FreshProfile: fresh, ComponentHistory: updatecheck.NewComponentHistoryAdmission(components.MihomoReleaseReadVersion), ExecutionHistory: updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion), SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: filepath.Join(state, "self-update-stop"), Directory: filepath.Join(state, "self-update-files")}}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	held, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = operationgate.InitializeSelfUpdateControl(held, a.SelfUpdateFiles.ControlRoot)
	release()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := a.installMihomo(ctx); err != nil || !result.OK {
		t.Fatal("actual installed owner", result, err)
	}
	if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	run, cancelRun := context.WithTimeout(ctx, 45*time.Second)
	defer cancelRun()
	held, release, err = a.Operations.ExclusiveContext(run)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := a.Operations.ReviewControlEpoch(held, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if err := a.ExecutionHistory.CheckWrite(held, 5); err != nil {
		t.Fatal("original reader5 admission", err)
	}
	options := backendprofile.MihomoOptions{SOCKSPort: 29460}
	profile := "vless://123e4567-e89b-12d3-a456-426614174000@1.1.1.3:443?security=tls&sni=front.example"
	compiled, err := backendprofile.Mihomo(profile, options)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(compiled.Config))
	source, err := cm.ReviewMihomoProbe(held, profile, options, hex.EncodeToString(hash[:]), "1.1.1.3", netip.MustParseAddr("1.1.1.3"), a.hevForwardGuard(store.Get(), control))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	service := catalog.Service{ID: "native-cold", Name: "Actual interrupted finite probe", ProbeURL: "https://1.1.1.2/", Strategy: []string{"mihomo"}, Probes: []catalog.Probe{{ID: "primary", Label: "Interrupted before service request", URL: "https://1.1.1.2/", Required: true}}}
	checked := dataplane.WithReviewGuard(held, control.Current)
	checked = dataplane.WithNodeResourceGuard(checked, func(c context.Context, host string, _ netip.Addr) error {
		if host == "1.1.1.2" {
			raw, err := os.ReadFile(filepath.Join(manager.StateRoot, "latest-execution.json"))
			if err != nil {
				return err
			}
			var e dataplane.Execution
			if json.Unmarshal(raw, &e) != nil || len(e.Resources) != 1 || e.Resources[0].Kind != "mihomo-probe" || e.Resources[0].Phase != "listener-ready" || e.Resources[0].MihomoProbe.Source.ParentOrigin.IsZero() {
				return errors.New("actual native COMMON readiness missing")
			}
			if err := os.WriteFile(ready, raw, 0600); err != nil {
				return err
			}
			// This is a negative-only observation boundary. No fake HTTPS PASS is
			// returned: the original process will be killed by the fault-injection
			// parent while its actual kernel listener and typed intent are retained.
			<-c.Done()
			return c.Err()
		}
		return c.Err()
	})
	a.mihomoProbe.mu.Lock()
	adapter := a.mihomoProbe.adapter
	a.mihomoProbe.mu.Unlock()
	_, err = adapter.Check(checked, manager, source, service, store.Get().Revision, "wan-0123456789ab", a.ComponentHistory, a.ExecutionHistory, control)
	t.Fatal("original producer unexpectedly returned before injected crash", err)
}
