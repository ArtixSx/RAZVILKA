//go:build linux

package components

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
)

func TestMihomoReopenedSelfConsistentForgeryCannotExecute(t *testing.T) {
	m, info := mihomoReleaseFixture(t)
	// All retained local bytes agree and claim the supported version. Only
	// independent official raw-byte provenance can distinguish this forgery.
	image := mihomoFixtureStage(t, m, []byte("#!/bin/sh\nprintf 'Mihomo Meta v1.19.33\\n'\n"))
	if _, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil {
		t.Fatal(err)
	}
	starts := 0
	start := func(context.Context, func() error) error {
		starts++
		t.Error("forged artifact reached native Start")
		return nil
	}
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
	options := backendprofile.MihomoOptions{SOCKSPort: 18090}
	profile, err := backendprofile.Mihomo(raw, options)
	if err != nil {
		t.Fatal(err)
	}
	review := digest([]byte(profile.Config))
	result, err := m.ValidateMihomoProfileGuarded(context.Background(), raw, options, review, mihomoFixtureAdmission, start)
	if err == nil || result != (MihomoNativeValidation{}) || starts != 0 {
		t.Fatal("forged matching receipt issued native proof", result, err)
	}
	if source, err := m.ReviewMihomoProbe(context.Background(), raw, options, review, "edge.example", netip.MustParseAddr("1.1.1.2"), mihomoFixtureAdmission); err == nil || source != nil {
		t.Fatal("forged receipt issued runtime source")
	}
	_, _, artifacts, _, _ := m.mihomoReleaseLayout()
	if err := verifyMihomoArtifactRelease(context.Background(), artifacts, image, start); err == nil || starts != 0 {
		t.Fatal("low-level native leaf accepted forgery", err)
	}
	if version := mihomoInstalledReceiptVersion(context.Background(), filepath.Join(m.BinDir, "mihomo")); version != "" {
		t.Fatal("passive inventory trusted forged release", version)
	}
}

func TestMihomoRawPinRequiresSupportedArchitecture(t *testing.T) {
	for _, arch := range []string{"", "mips", "mipsle", "arm", "386"} {
		if _, err := mihomoReviewedRawArtifact(arch); err == nil {
			t.Fatal(arch)
		}
	}
}
