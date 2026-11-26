//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"debug/elf"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type masqueCompanionArchiveTransport func(*http.Request) (*http.Response, error)

func (f masqueCompanionArchiveTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestAutonomyUSQUEPrivateCompanionNative(t *testing.T) {
	sidecarArchive := os.Getenv("RAZVILKA_MASQUE_NATIVE_SINGBOX_ARCHIVE")
	coreArchive := os.Getenv("RAZVILKA_MASQUE_NATIVE_USQUE_ARCHIVE")
	if sidecarArchive == "" || coreArchive == "" {
		t.Skip("isolated MASQUE companion fixture not enabled")
	}
	opt, optErr := os.ReadDir("/opt")
	ifaces, ifErr := os.ReadDir("/sys/class/net")
	mounts, mountErr := os.ReadFile("/proc/self/mountinfo")
	private := slices.ContainsFunc(strings.Split(string(mounts), "\n"), func(line string) bool {
		fields := strings.Fields(line)
		return len(fields) > 6 && fields[4] == "/opt" && strings.Contains(line, " - tmpfs ")
	})
	if optErr != nil || ifErr != nil || mountErr != nil || !private || len(opt) != 1 || opt[0].Name() != ".razvilka-masque-sidecar-lab" ||
		len(ifaces) != 1 || ifaces[0].Name() != "lo" {
		t.Fatal("fixture requires isolated tmpfs /opt and a guest with loopback only")
	}
	if err := os.MkdirAll(installpath.State, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, _, _ := autonomousIntegrationFixture(t)
	s := setAutonomyUSQUEPolicy(t, a, true)
	base := filepath.Dir(a.Dataplane.StateRoot)
	control := filepath.Join(base, "control")
	a.SelfUpdateFiles = &SelfUpdateFiles{ControlRoot: control}
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
		t.Fatal(err)
	}
	if err := a.ConfigureDefaultConsent(filepath.Join(base, "config.json"), filepath.Join(base, "nodes")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.CloseDefaultConsent() })
	a.EngineConfigs = engineconfig.New(filepath.Join(base, "stage"), filepath.Join(base, "backup"))
	a.DataplaneHost = dataplane.DiscoverHost
	a.nodeReviews.options = nil
	proxy, err := dataplane.NewProxyTunnelAdapter("usque", a.EngineConfigs, filepath.Join(base, "private-runtime"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Dataplane.Register(proxy); err != nil {
		t.Fatal(err)
	}
	pkg := &autopilotEnginePackage{name: "sing-box-go"}
	a.Components = components.New()
	a.Components.Runner = pkg
	var requests []string
	a.Components.Client = &http.Client{Transport: masqueCompanionArchiveTransport(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.Path)
		var archive string
		switch r.URL.Path {
		case "/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-" + runtime.GOARCH + "-musl.tar.gz":
			archive = sidecarArchive
		case "/Diniboy1123/usque/releases/download/v4.2.1/usque_4.2.1_linux_" + runtime.GOARCH + ".zip":
			archive = coreArchive
		default:
			t.Fatalf("unexpected component request: %s", r.URL)
		}
		file, err := os.Open(archive)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: file, Header: http.Header{}}, nil
	})}
	a.autonomy.mu.Lock()
	p := &a.autonomy.doc.Policy
	p.PreferredRoutes = []string{"usque"}
	p.SourceIDs = nil
	allow := true
	p.InstallMissingComponents = &allow
	err = a.persistAutonomyLocked(ctx)
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	service, _ := a.autonomyService(s.ID)
	network, err := a.freshNetworkProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if host := dataplane.DiscoverHost(); !host.IPCommand || !host.TUN || host.SingBox || host.MASQUESingBox {
		t.Fatalf("incorrect clean-guest requirements: %+v", host)
	}
	owned, release, err := a.scopedRuntimeOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	r, _ := a.tryAutonomyInitialUSQUE(owned, a.autonomyPolicy(), s, autonomy.Runtime{}, a.Store.Get(), service, network, false)
	if _, err := a.Dataplane.ReviewUSQUEInitialSource(ctx, a.EngineConfigs); err != nil {
		version, versionErr := exec.CommandContext(ctx, installpath.ManagedMASQUESingBox, "version").CombinedOutput()
		t.Fatalf("installed files failed actual adapter review: %v. Publication: sidecar=%v core=%v. Version: %s %v", err,
			components.CheckInitialMASQUESidecarPublication(ctx), a.Components.CheckInitialUSQUEPublication(ctx), version, versionErr)
	}
	switch r.State {
	case "masque-registration-pending", "masque-registration-timeout", "masque-session-unavailable":
		t.Logf("isolated provider registration outcome: %s", r.State)
	default:
		t.Fatalf("initial round did not reach offline registration: %+v requests=%v", r, requests)
	}
	if len(requests) != 2 || len(pkg.commands) != 0 {
		t.Fatalf("expected the companion and the native core without opkg: %v %v", requests, pkg.commands)
	}
	image, err := elf.Open(installpath.ManagedMASQUESingBox)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	for _, p := range image.Progs {
		if p.Type == elf.PT_INTERP {
			t.Fatal("pinned MASQUE TUN companion unexpectedly needs a dynamic interpreter")
		}
	}
	if host := dataplane.DiscoverHost(); host.SingBox || !host.MASQUESingBox || (engine.Detector{}).Installed("sing-box") ||
		!slices.Equal(a.autonomyPolicy().PreferredRoutes, []string{"usque"}) {
		t.Fatalf("private dependency leaked into shared discovery or permission: %+v", host)
	}
	files, err := os.ReadDir(filepath.Dir(installpath.ManagedMASQUESingBox))
	if err != nil || len(files) != 1 || files[0].Name() != "sing-box" {
		t.Fatalf("unexpected extracted material: %v %v", files, err)
	}
	for _, path := range []string{"/opt/bin/sing-box", "/opt/etc/init.d", "/opt/bin/usque"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("private installation touched vendor path %s: %v", path, err)
		}
	}
}
