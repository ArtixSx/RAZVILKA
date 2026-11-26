//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Actual official HEV/TUN/TLS/SOCKS in private mount+network namespaces.
// SOCKS upstream is an explicit local transport fixture, not a VLESS server.
// This proves the sidecar path/owned process cleanup, not Manager/LAN Apply.
func TestHEVOwnedNativeTUNLifecycle(t *testing.T) {
	binary := os.Getenv("RAZVILKA_HEV_NATIVE")
	if binary == "" {
		t.Skip("pinned official HEV2.17.1 native asset required")
	}
	if !filepath.IsAbs(binary) || runtime.GOARCH != "amd64" {
		t.Fatal("native fixture requires absolute official amd64 asset")
	}
	if os.Getenv("RAZVILKA_HEV_NATIVE_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--mount", "--fork", os.Args[0], "-test.run=^TestHEVOwnedNativeTUNLifecycle$", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_HEV_NATIVE_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("private HEV fixture failed: %v %s", err, output)
		}
		t.Log(string(output))
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("disposable root fixture required")
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03" {
		t.Fatal("native asset differs from official reviewed HEV2.17.1 amd64")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("isolated namespace setup: %v %s", err, out)
		}
		return string(out)
	}
	run("mount", "--make-rprivate", "/")
	// Device nodes exist only in this private mount namespace. Never create or
	// chmod a host /dev entry, even when the CI host does not expose TUN.
	run("mount", "-t", "tmpfs", "-o", "mode=755", "hev-fixture-dev", "/dev")
	if err = os.Mkdir("/dev/net", 0755); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mknod("/dev/net/tun", unix.S_IFCHR|0600, int(unix.Mkdev(10, 200))); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mknod("/dev/null", unix.S_IFCHR|0666, int(unix.Mkdev(1, 3))); err != nil {
		t.Fatal(err)
	}
	run("ip", "link", "set", "lo", "up")
	backend, roots, names := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "owned-hev-tls-path") })
	socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
	root := t.TempDir()
	a, err := NewProxyTunnelAdapterWithHev("sing-box", engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup")), root, binary)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(socks.address)
	if err != nil {
		t.Fatal(err)
	}
	a.SOCKSPort, err = strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	a.Interface = "rz-hev-native"
	a.TunnelCIDR = "172.27.29.1/30"
	a.IP = hevNativeExecutable(t, "ip")
	if err = os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	config, err := a.hevConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(a.sidecarConfigPath(), config, 0600); err != nil {
		t.Fatal(err)
	}
	spec := a.sidecarProcess()
	controller := OSProcessController{}
	defer func() {
		cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := controller.Stop(cleanup, spec); err != nil {
			t.Error("original HEV cleanup", err)
		}
	}()
	for round := 0; round < 2; round++ {
		t.Logf("actual HEV start round=%d", round+1)
		if err = a.startOwnedSidecar(ctx); err != nil {
			// This fixture generates only local test endpoints. Read the bounded
			// original child's log before TempDir cleanup, without retrying Start
			// or changing the process/controller's original refusal.
			if log, openErr := os.Open(spec.LogPath); openErr == nil {
				if info, statErr := log.Stat(); statErr == nil && info.Mode().IsRegular() {
					data, readErr := io.ReadAll(io.LimitReader(log, 16<<10))
					t.Logf("original HEV fixture child log read=%v output=%q", readErr, data)
				}
				_ = log.Close()
			}
			t.Fatal("owned HEV start", err)
		}
		if err = a.waitForInterface(ctx); err != nil {
			t.Fatal(err)
		}
		run("ip", "route", "add", "93.184.216.14/32", "dev", a.Interface)
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12}, DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(c, "tcp4", "93.184.216.14:443")
		}}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get("https://example.com/")
		if err != nil {
			transport.CloseIdleConnections()
			t.Fatal("actual HEV TLS/SOCKS route", err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		transport.CloseIdleConnections()
		if err != nil || string(body) != "owned-hev-tls-path" {
			t.Fatal("wrong native payload", err)
		}
		select {
		case request := <-socks.requests:
			if request.AddressType != 1 || request.Host != "93.184.216.14" || request.Port != 443 {
				t.Fatal("HEV delegated different SOCKS destination")
			}
		case <-ctx.Done():
			t.Fatal("missing actual SOCKS request")
		}
		select {
		case name := <-names:
			if name != "example.com" {
				t.Fatal("TLS origin lost")
			}
		case <-ctx.Done():
			t.Fatal("missing actual TLS origin")
		}
		if defaults := run("ip", "route", "show", "default"); strings.TrimSpace(defaults) != "" {
			t.Fatal("HEV changed namespace default route")
		}
		cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
		err = controller.Stop(cleanup, spec)
		finish()
		if err != nil {
			t.Fatal("owned stop", err)
		}
		if controller.Running(spec) {
			t.Fatal("original sidecar remained running")
		}
		if out, err := exec.CommandContext(ctx, "ip", "link", "show", "dev", a.Interface).CombinedOutput(); err == nil {
			t.Fatalf("owned TUN retained after joined process cleanup: %s", out)
		}
		if route := run("ip", "route", "show", "93.184.216.14/32"); strings.TrimSpace(route) != "" {
			t.Fatal("native target route survived TUN cleanup")
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := a.startOwnedSidecar(canceled); !errors.Is(err, context.Canceled) || controller.Running(spec) {
		t.Fatal("canceled start revived native sidecar", err)
	}
	t.Log("two actual HEV starts, numeric SOCKS/TLS path and joined PID/TUN/route cleanup; no native dry-run, production/LAN/router claim")
}
func hevNativeExecutable(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return path
}
