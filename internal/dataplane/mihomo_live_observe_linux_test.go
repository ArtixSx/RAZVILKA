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

type fabricatedMihomoObservedChild struct{}

func (fabricatedMihomoObservedChild) Current(context.Context) error        { return nil }
func (fabricatedMihomoObservedChild) PID() int                             { return os.Getpid() }
func (fabricatedMihomoObservedChild) MatchesFile(string, os.FileInfo) bool { return true }

func TestMihomoLiveObservationCannotMintOriginalChild(t *testing.T) {
	if originalMihomoObservedOwner(fabricatedMihomoObservedChild{}) || originalMihomoObservedOwner((*components.MihomoLiveProcess)(nil)) || originalMihomoObservedOwner((*components.MihomoLiveObservation)(nil)) || originalMihomoObservedOwner((*components.MihomoLiveCleanupObservation)(nil)) {
		t.Fatal("fabricated comparison interface admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := observeMihomoLiveProcess(ctx, new(components.MihomoLiveProcess), netidentity.NewProcProvider(), netidentity.Identity{}); err == nil {
		t.Fatal("unissued concrete owner admitted")
	}
}

func TestMihomoLiveOfficialOriginalKernelOwnerAcrossApplyRelease(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	cleanup, err := gate.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	guard := func(c context.Context, effect func() error) error {
		if err := control.Current(c); err != nil {
			return err
		}
		return errors.Join(effect(), control.Current(c))
	}
	m := components.New()
	m.BinDir, m.StateDir, m.Arch = filepath.Join(root, "bin"), filepath.Join(root, "components"), "amd64"
	m.Client = &http.Client{Transport: mihomoNativeArchiveTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz" {
			return nil, errors.New("unexpected official source")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	if result, err := m.ApplyMihomoGuarded(held, guard, control.WithRename, control.WithStart); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	source, err := m.OpenMihomoLiveSource(held)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
	options := backendprofile.MihomoOptions{SOCKSPort: port}
	base, err := backendprofile.Mihomo(raw, options)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(base.Config))
	profile, err := source.ReviewProfile(held, raw, options, hex.EncodeToString(hash[:]), "edge.example", netip.MustParseAddr("1.1.1.2"))
	if err != nil {
		t.Fatal(err)
	}
	child, err := source.ReserveLiveChild(held, profile, control, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.Cleanup(held, cleanup) == nil {
			return
		}
		release()
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		freshHeld, releaseFresh, err := gate.ExclusiveContext(finish)
		if err != nil {
			t.Error("retained fixture cleanup admission", err)
			return
		}
		defer releaseFresh()
		freshReview, err := gate.ReviewExclusiveCleanup(freshHeld)
		if err == nil {
			err = child.Cleanup(freshHeld, freshReview)
		}
		if err != nil {
			t.Error("retained original fixture cleanup", err)
		}
	}()
	if err := child.StartAdmitted(held, func(c context.Context, begin func() error) error { return begin() }); err != nil {
		t.Fatal(err)
	}
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(held)
	if err != nil {
		t.Fatal(err)
	}
	var first mihomoProbeObservation
	for {
		first, err = observeMihomoLiveProcess(held, child, provider, identity)
		if err == nil {
			break
		}
		select {
		case <-held.Done():
			t.Fatal("original native live listener", err)
		case <-time.After(25 * time.Millisecond):
		}
	}
	if first.pid != child.PID() || first.start == "" || first.listener == 0 {
		t.Fatal("missing original kernel association")
	}
	release()
	after, err := observeMihomoLiveProcess(ctx, child, provider, identity)
	if err != nil || !first.same(after) {
		t.Fatal("release of Apply altered persistent original comparison", err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, controlRoot, "11111111111111111111111111111111", 7); err != nil {
		t.Fatal(err)
	}
	if _, err := observeMihomoLiveProcess(ctx, child, provider, identity); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Fatal("stopped owner still supplied live observation", err)
	}
	stop, releaseStop, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseStop()
	fresh, err := gate.ReviewExclusiveCleanup(stop)
	if err != nil {
		t.Fatal(err)
	}
	cleanupObservation, err := observeMihomoLiveCleanupProcess(stop, child, fresh, provider, identity)
	if err != nil || !first.same(cleanupObservation) {
		t.Fatal("stopped original kernel child lost cleanup-only comparison", err)
	}
	if _, err := observeMihomoLiveCleanupProcess(stop, child, cleanup, provider, identity); err == nil {
		t.Fatal("released original cleanup review regained kernel comparison")
	}
	if err := child.Cleanup(stop, fresh); err != nil {
		t.Fatal(err)
	}
	if err := observeMihomoProbeListenerAbsent(stop, provider, identity, port); err != nil {
		t.Fatal("listener survived original sole Wait", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("actual official held-FD child/full kernel listener association across Apply release; durable Stop revokes observation, fresh same-owner cleanup joins; no TUN/service/route proof")
}
