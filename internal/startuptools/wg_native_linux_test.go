//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

// Reuse the existing original Provider/profile native fixture. This only
// proves acquisition/version/closure and unadmitted refusal, never a native
// WG route, handshake, App Ready or a fake CommandAdmission effect proof.
func TestProductionStartupWGNative(t *testing.T) {
	engine, mode := os.Getenv("RAZVILKA_STARTUP_WG_NATIVE"), os.Getenv("RAZVILKA_STARTUP_TOOLS_NATIVE")
	if engine == "" {
		t.Skip("Root WG startup source native opt-in disabled")
	}
	if engine != "wireguard" && engine != "amneziawg" || mode != "ubuntu-legacy" && mode != "stock-nc1812" {
		t.Fatal("explicit existing platform/backend profile required")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	setup, cancelSetup := context.WithTimeout(lifetime, operationTimeout)
	provider := nativeProvider(t, setup, mode)
	cancelSetup()
	t.Setenv("LD_PRELOAD", "/unreviewed-wg-preload.so")
	t.Setenv("LD_LIBRARY_PATH", "/unreviewed-wg-libraries")
	started := time.Now()
	l, err := acquireWG(lifetime, provider, wgProfile(mode == "stock-nc1812", engine))
	if err != nil {
		t.Fatalf("actual WG acquisition refused: ms=%d stages=%s", time.Since(started).Milliseconds(), nativeStages(err))
	}
	defer l.Close()
	tools, err := l.WGCommandTools(engine)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.PolicyRuntimeTools(); err != nil {
		t.Fatal("same lease lost IP/xtables", err)
	}
	read, cancelRead := context.WithTimeout(lifetime, operationTimeout)
	defer cancelRead()
	if err := tools.Runner.CheckWG(read, tools.Identity); err != nil {
		t.Fatalf("actual held closure check: %s", nativeStages(err))
	}
	primary := 0
	if engine == "amneziawg" {
		primary = 1
	}
	err = func() error {
		if err := l.lock(read); err != nil {
			return err
		}
		defer l.unlock()
		return provider.WithCurrent(read, func(held context.Context, actual netidentity.Identity) error {
			if actual != l.identity {
				return at("WG_VERSION_IDENTITY", nil)
			}
			data, err := l.execute(held, primary+3, 256, "--version")
			if err != nil || !validWGVersion(primary, data) {
				return at("WG_VERSION", err)
			}
			return held.Err()
		})
	}()
	if err != nil {
		t.Fatalf("actual held version: %s", nativeStages(err))
	}
	name := tools.WG
	if engine == "amneziawg" {
		name = tools.AWG
	}
	if out, err := tools.Runner.RunWG(read, nil, name, "show", "all", "public-key"); !errors.Is(err, ErrUnknown) || len(out) != 0 {
		t.Fatal("descriptor alone issued command", err)
	}
	// SAME actual lease/Provider and actual original Gate/control/Manager
	// issuer. The fixture profile is an imported syntax source only. This
	// executes exactly the existing numeric route-get parser, no packet/probe,
	// WG configuration, link, route/rule mutation or fake Start callback.
	root := t.TempDir()
	manager := dataplane.New(filepath.Join(root, "dataplane"))
	if err := os.MkdirAll(manager.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	configs.LiveRoot = filepath.Join(root, "live")
	profile := "[Interface]\nPrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\nEndpoint = 1.1.1.1:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
	profileID := "main"
	var adapter *dataplane.WARPWireGuardAdapter
	if engine == "wireguard" {
		adapter = dataplane.NewWireGuardAdapter(configs, manager.StateRoot)
		profiles := wireguardprofile.New(filepath.Join(root, "profiles"))
		if _, err := profiles.Put(read, "source-native", "Native read-only source fixture", profile, ""); err != nil {
			t.Fatal(err)
		}
		adapter.Profiles, profileID = profiles, "source-native"
	} else {
		adapter = dataplane.NewAmneziaWGAdapter(configs, manager.StateRoot)
		view, err := configs.ReadExpert(engine, "main")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(view.Path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(view.Path, []byte(profile), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := adapter.BindWGCommandTools(tools); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	original, release, err := gate.ExclusiveContext(read)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	controlRoot := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(original, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(original, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	source, err := dataplane.ReviewWGSourceRead(original, manager, control, engine)
	if err != nil {
		t.Fatalf("actual read-only issuer: %v", err)
	}
	defer source.Close()
	capture, err := source.CaptureProfile(original, profileID)
	if err != nil {
		t.Fatal(err)
	}
	wan, err := source.ObserveNumericEndpoint(original, capture)
	if err != nil {
		t.Fatalf("actual held numeric WAN read: %v", err)
	}
	if wan.Endpoint != "1.1.1.1:51820" || wan.Device == "" || !wan.ExpiresAt.IsZero() {
		t.Fatal("unexpected original WAN capture", wan)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := control.Current(original); err != nil {
		t.Fatal("read source closed caller control", err)
	}
	t.Logf("actual SAME-lease read-only endpoint=%s WAN=%s; consumer/traffic unavailable", wan.Endpoint, wan.Device)
	t.Logf("actual WG source acquisition-ms=%d images=%d bytes=%d review=%s; no effect admission", time.Since(started).Milliseconds(), len(l.review.images), l.review.bytes, l.digest)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tools.Runner.CheckWG(read, tools.Identity); !errors.Is(err, ErrUnknown) {
		t.Fatal("saved source survived Close", err)
	}
}
