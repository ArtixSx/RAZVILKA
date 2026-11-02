//go:build linux

package components

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
)

// Official pinned installed bytes test original file lease/source fences.
// This does not start a native process or issue scoped network evidence.
func TestMihomoProbeSourceRetainsOriginalInstalledLeaseAndReview(t *testing.T) {
	m, info := mihomoReleaseFixture(t)
	path := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if path == "" {
		t.Skip("requires official pinned gzip asset")
	}
	compressed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	image, err := m.stageMihomoArtifact(context.Background(), compressed, info.PinnedSHA256, mihomoFixtureAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil {
		t.Fatal(err)
	}
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
	options := backendprofile.MihomoOptions{SOCKSPort: 18090}
	profile, err := backendprofile.Mihomo(raw, options)
	if err != nil {
		t.Fatal(err)
	}
	current := true
	guard := func(ctx context.Context, action func() error) error {
		if !current {
			return ErrRecoveryAuthority
		}
		return mihomoFixtureAdmission(ctx, action)
	}
	if _, err := m.ReviewMihomoProbe(context.Background(), raw, options, "changed", "edge.example", netip.MustParseAddr("1.1.1.2"), guard); err == nil {
		t.Fatal("stale review admitted")
	}
	source, err := m.ReviewMihomoProbe(context.Background(), raw, options, digest([]byte(profile.Config)), "edge.example", netip.MustParseAddr("1.1.1.2"), guard)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	ref := source.Reference()
	if ref.BinarySHA256 == "" || ref.ConfigSHA256 == ref.ReviewSHA256 || ref.Endpoint.String() != "1.1.1.2" || source.Current(context.Background()) != nil {
		t.Fatal("lost original source")
	}
	if other, err := m.openMihomoRelease(false); err == nil {
		other.close()
		t.Fatal("source did not retain installed writer lease")
	}
	current = false
	if !errors.Is(source.Current(context.Background()), ErrRecoveryAuthority) {
		t.Fatal("revoked guard accepted")
	}
	current = true
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil || source.Current(context.Background()) == nil {
		t.Fatal("closed source still current", err)
	}
	if other, err := m.openMihomoRelease(false); err != nil {
		t.Fatal("original writer lease not released", err)
	} else {
		if err := other.close(); err != nil {
			t.Fatal(err)
		}
	}
}
