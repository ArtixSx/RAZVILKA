//go:build linux

package components

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Real component/process lifetime only. No LAN policy, selected-node authority,
// TUN, service or live routing claim is supplied by this fixture.
func TestMihomoLiveOriginalChildSurvivesApplyAndNeedsFreshCleanup(t *testing.T) {
	archive := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if archive == "" {
		t.Skip("official pinned native component required")
	}
	compressed, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	m, info := mihomoReleaseFixture(t)
	image, err := m.stageMihomoArtifact(context.Background(), compressed, info.PinnedSHA256, mihomoFixtureAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source, err := m.OpenMihomoLiveSource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	gate := &operationgate.Gate{}
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		release()
		t.Fatal(err)
	}
	cleanup, err := gate.ReviewExclusiveCleanup(held)
	if err != nil {
		release()
		control.Close()
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		release()
		control.Close()
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
	options := backendprofile.MihomoOptions{SOCKSPort: port}
	base, err := backendprofile.Mihomo(raw, options)
	if err != nil {
		release()
		control.Close()
		t.Fatal(err)
	}
	profile, err := source.ReviewProfile(held, raw, options, digest([]byte(base.Config)), "edge.example", netip.MustParseAddr("1.1.1.2"))
	if err != nil {
		release()
		control.Close()
		t.Fatal(err)
	}
	child, err := source.ReserveLiveChild(held, profile, control, cleanup)
	if err != nil {
		release()
		control.Close()
		t.Fatal(err)
	}
	if duplicate, err := source.ReserveLiveChild(held, profile, control, cleanup); err == nil || duplicate != nil {
		t.Fatal("same transferred control handle reserved by another child", err)
	}
	apply, stopApply := context.WithCancel(held)
	if err := child.StartAdmitted(apply, mihomoFixtureAdmission); err != nil {
		_ = child.Cleanup(held, cleanup)
		release()
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 50*time.Millisecond)
		if e == nil {
			connection.Close()
			break
		}
		if time.Now().After(deadline) {
			_ = child.Cleanup(held, cleanup)
			release()
			t.Fatal("actual native live listener not present", e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if source.Close() == nil {
		_ = child.Cleanup(held, cleanup)
		release()
		t.Fatal("active original child lost component lease")
	}
	if other, err := m.openMihomoRelease(false); err == nil {
		other.close()
		_ = child.Cleanup(held, cleanup)
		release()
		t.Fatal("live component writer leases silently replaced")
	}
	release()
	stopApply()
	if err := child.Current(ctx); err != nil {
		t.Fatal("old Apply cancellation killed or revoked original live comparison", err)
	}
	if err := child.Cleanup(ctx, cleanup); err == nil {
		t.Fatal("released Apply cleanup review reactivated")
	}
	if err := child.CurrentForCleanup(ctx, cleanup); err == nil {
		t.Fatal("released old cleanup review supplied a native comparison")
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, controlRoot, "11111111111111111111111111111111", 7); err != nil {
		t.Fatal(err)
	}
	if err := child.Current(ctx); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Fatal("durable Stop preserved live health authority", err)
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
	if err := child.CurrentForCleanup(stop, fresh); err != nil {
		t.Fatal("actual stopped original child lost cleanup-only comparison", err)
	}
	foreignGate := &operationgate.Gate{}
	foreignHeld, releaseForeign, err := foreignGate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := foreignGate.ReviewExclusiveCleanup(foreignHeld)
	if err != nil {
		releaseForeign()
		t.Fatal(err)
	}
	if err := child.CurrentForCleanup(stop, foreign); err == nil {
		releaseForeign()
		t.Fatal("foreign cleanup minted original child comparison")
	}
	releaseForeign()
	if err := child.Cleanup(stop, fresh); err != nil {
		t.Fatal("fresh actual cleanup did not retire same child", err)
	}
	if child.Current(ctx) == nil {
		t.Fatal("terminal child revived current native state")
	}
	if err := source.Close(); err != nil {
		t.Fatal("original component source did not close after joined child", err)
	}
	if source.Current(ctx) == nil || source.OwnedBy(m) {
		t.Fatal("closed source revived ownership")
	}
	t.Log("actual held-FD config validation, native listener across Apply release/cancel, stale cleanup refusal, fresh same-Gate kill/sole Wait/thread join and component leases: PASS; no TUN/routing/service claim")
}

func TestMihomoLiveManufacturedOwnerAndCancellationRefuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().OpenMihomoLiveSource(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("source cancellation lost", err)
	}
	if (&MihomoLiveSource{}).Current(context.Background()) == nil || (&MihomoLiveProcess{}).Current(context.Background()) == nil {
		t.Fatal("unissued owner became current")
	}
}
