package dataplane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
)

func TestMihomoLiveNodeSourceIsOriginalContentOnly(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	path := filepath.Join(f.root, "nodes.private.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	r := f.review(t, "mihomo")
	if ref := r.Reference(); ref.EngineID != "mihomo" || ref.Resolved != "mihomo:"+f.id {
		t.Fatal(ref)
	}
	var borrowed []byte
	if err := r.WithMaterial(f.ctx, func(material []byte) error {
		borrowed = material
		raw, err := mihomoNodeSourceProfile(material)
		defer clear(raw)
		if err != nil {
			return err
		}
		profile, err := backendprofile.Mihomo(string(raw), backendprofile.MihomoOptions{SOCKSPort: 18083})
		if err == nil && (profile.NativeValidated || profile.ServiceVerified || profile.LiveApplied) {
			t.Fatal("content review minted runtime evidence")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	nodeDefaultSourceRequireCleared(t, borrowed)
	after, err := os.ReadFile(path)
	defer clear(after)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("content-only review changed actual store", err)
	}
	// Backend-specific health eligibility remains absent. A source review is
	// intentionally not an extension of the existing service PASS catalog.
	if services, err := f.store.RouteServicesForEngine(f.ctx, "mihomo", f.id, "wan-0123456789ab", f.now); err == nil || len(services) != 0 {
		t.Fatal("content review granted service eligibility", err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Current(f.ctx); !errors.Is(err, ErrNodeDefaultSource) {
		t.Fatal("closed original store remained current", err)
	}
}

func TestMihomoLiveNodeSourceRefusesUnsupportedOriginalTransport(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, "vless://123e4567-e89b-12d3-a456-426614174000@source-node.example:443?security=tls&sni=source-front.example&type=xhttp&path=%2Fx")
	if review, err := ReviewNodeDefaultSource(f.ctx, f.store, "mihomo:"+f.id); err == nil || review != nil {
		t.Fatal("unsupported original transport became a Mihomo source", err)
	}
}
