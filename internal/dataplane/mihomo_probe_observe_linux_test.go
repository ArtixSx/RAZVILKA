//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type mihomoNativeArchiveTransport func(*http.Request) (*http.Response, error)

func (f mihomoNativeArchiveTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMihomoOfficialOriginalKernelProcessAndListener(t *testing.T) {
	archive := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if archive == "" {
		t.Skip("requires official pinned gzip asset")
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	controlRoot := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlRoot); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(held, 35*time.Second)
	defer cancel()
	control, err := gate.ReviewControlEpoch(ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	guard := func(ctx context.Context, effect func() error) error {
		if err := control.Current(ctx); err != nil {
			return err
		}
		return errors.Join(effect(), control.Current(ctx))
	}
	m := components.New()
	m.BinDir, m.StateDir, m.Arch = filepath.Join(root, "bin"), filepath.Join(root, "components"), "amd64"
	m.Client = &http.Client{Transport: mihomoNativeArchiveTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz" {
			t.Fatal("unexpected official source")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	if result, err := m.ApplyMihomoGuarded(ctx, guard, control.WithRename, control.WithStart); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if observeMihomoProbeListenerAbsent(ctx, provider, identity, port) == nil {
		t.Fatal("foreign listener admitted as absent")
	}
	_ = reservation.Close()
	if err := observeMihomoProbeListenerAbsent(ctx, provider, identity, port); err != nil {
		t.Fatal(err)
	}
	options := backendprofile.MihomoOptions{SOCKSPort: port}
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
	profile, err := backendprofile.Mihomo(raw, options)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(profile.Config))
	source, err := m.ReviewMihomoProbe(ctx, raw, options, hex.EncodeToString(hash[:]), "edge.example", netip.MustParseAddr("1.1.1.2"), guard)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var first mihomoProbeObservation
	_, err = source.RunProbe(ctx, control, cleanup, func(ctx context.Context, child *components.MihomoProbeProcess) error {
		for {
			var err error
			first, err = observeMihomoProbeProcess(ctx, child, source.Reference(), provider, identity)
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return errors.Join(ctx.Err(), err)
			case <-time.After(25 * time.Millisecond):
			}
		}
		if first.pid != child.PID() || first.listener == 0 || first.start == "" {
			return ErrMihomoProbe
		}
		changed := source.Reference()
		changed.ConfigSHA256 = hex.EncodeToString(make([]byte, 32))
		if _, err := observeMihomoProbeProcess(ctx, child, changed, provider, identity); err == nil {
			t.Fatal("different profile issued actual association")
		}
		after, err := observeMihomoProbeProcess(ctx, child, source.Reference(), provider, identity)
		if err != nil || !first.same(after) {
			return errors.Join(ErrMihomoProbe, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal("actual held process and listener", err)
	}
	if err := observeMihomoProbeListenerAbsent(ctx, provider, identity, port); err != nil {
		t.Fatal("listener survived sole Wait", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("official native child: actual exe/argv/environment/sealed profile/home/birth/namespace/listener inode, changed-profile refusal, sole Wait and full listener absence; no service or route proof")
}
