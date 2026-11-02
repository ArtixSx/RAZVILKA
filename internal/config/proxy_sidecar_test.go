package config

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestProxySidecarBootChoiceCASAndValidation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	if EffectiveProxySidecar(before.ProxySidecar) != "sing-box" {
		t.Fatal("legacy default changed")
	}
	if err := s.SetProxySidecar(before.Revision, "hev"); err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if got.Revision != before.Revision+1 || got.ProxySidecar != "hev" || got.AppliedRevision != before.AppliedRevision {
		t.Fatal("boot choice applied a route", got)
	}
	reloaded, err := Load(p)
	if err != nil || reloaded.Get().ProxySidecar != "hev" {
		t.Fatal("choice did not persist", err)
	}
	if err := s.SetProxySidecar(before.Revision, "sing-box"); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale intent admitted", err)
	}
	for _, value := range []string{"HEV", "/opt/bin/hev", "auto", "mihomo"} {
		if err := s.SetProxySidecar(got.Revision, value); !errors.Is(err, ErrProxySidecar) {
			t.Fatal(value, err)
		}
	}
	if s.Get().Revision != got.Revision {
		t.Fatal("invalid choice changed revision")
	}
	if _, _, err := InspectBytes([]byte(`{"schema_version":2,"proxy_sidecar":"future","services":{},"applied_services":{}}`)); !errors.Is(err, ErrProxySidecar) {
		t.Fatal("unknown stored backend accepted", err)
	}
}
