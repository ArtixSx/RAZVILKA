package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/catalog"
)

func TestWGListSourceMaterialUsesOriginalProfileCoverageAndWAN(t *testing.T) {
	f := newWGSourceReadFixture(t)
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
	profile, err := f.read.CaptureProfile(f.ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	service := catalog.Service{ID: "listed", Name: "Listed", Category: "fixture", Strategy: []string{"wireguard"}, CIDRs: []string{"1.1.1.0/24"}, ProbeURL: "https://1.1.1.1/"}
	r, err := ReviewWGListSourceMaterial(f.ctx, f.read, profile, service)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ref, err := r.Observation(f.ctx)
	if err != nil || ref.RegistryGeneration != f.manager.registryGeneration || ref.ProfileRevision != profile.revision || ref.ProfileSHA256 != profile.digest || len(ref.SourceSHA256) != 64 {
		t.Fatal(ref, err)
	}
	service.CIDRs[0], ref.SourceSHA256 = "0.0.0.0/0", "caller-copy"
	if err := r.Current(f.ctx); err != nil {
		t.Fatal("detached reference changed original material", err)
	}
	if r.service.CIDRs[0] != "1.1.1.0/24" {
		t.Fatal("service alias retained")
	}
	copy := &WGListSourceMaterial{self: r, reader: r.reader, profile: r.profile}
	if err := copy.Current(f.ctx); !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("copied owner accepted", err)
	}
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.3","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
	if err := r.Current(f.ctx); err == nil {
		t.Fatal("changed numeric WAN admitted")
	}
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
	if err := r.Current(f.ctx); err == nil {
		t.Fatal("restored WAN revived original material")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.read.Current(f.ctx); err != nil {
		t.Fatal("material closed original source", err)
	}
	if err := f.control.Current(f.ctx); err != nil {
		t.Fatal("material closed caller control", err)
	}
}

func TestWGListSourceMaterialAWGUsesFreshRawRuntimeAdmission(t *testing.T) {
	f := newWGSourceReadFixture(t)
	if err := f.read.Close(); err != nil {
		t.Fatal(err)
	}
	a := NewAmneziaWGAdapter(f.a.Configs, f.manager.StateRoot)
	caps := compatibleAWGTestCapabilities(t, a) // regular fixture CLI, never executed
	a.AWGCapabilities = func(context.Context) awgprofile.Capabilities { return caps }
	tools := *f.a.wgCommandTools
	tools.EngineID, tools.AWG = "amneziawg", a.WG
	if err := a.BindWGCommandTools(tools); err != nil {
		t.Fatal(err)
	}
	view, err := a.Configs.ReadExpert("amneziawg", "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(view.Path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(view.Path, []byte(awgNativeFixture()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Register(a); err != nil {
		t.Fatal(err)
	}
	reader, err := ReviewWGSourceRead(f.ctx, f.manager, f.control, "amneziawg")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	profile, err := reader.CaptureProfile(f.ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", `[{"dst":"8.8.4.4","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
	service := catalog.Service{ID: "listed", Name: "Listed", Category: "fixture", Strategy: []string{"amneziawg"}, CIDRs: []string{"1.1.1.0/24"}, ProbeURL: "https://1.1.1.1/"}
	r, err := ReviewWGListSourceMaterial(f.ctx, reader, profile, service)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	caps.ModuleInitState = "going"
	if err := r.Current(f.ctx); err == nil {
		t.Fatal("changed loaded module admitted")
	}
	caps.ModuleInitState = "live"
	if err := r.Current(f.ctx); err == nil {
		t.Fatal("restored module revived material")
	}
	if err := reader.Current(f.ctx); err != nil {
		t.Fatal("material retired caller source", err)
	}
}

func TestWGListSourceMaterialRefusesBroadDomainAndUncoveredFamily(t *testing.T) {
	for _, mode := range []string{"catchall", "domain", "family", "peer-coverage", "foreign-capture"} {
		t.Run(mode, func(t *testing.T) {
			f := newWGSourceReadFixture(t)
			t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
			profile, err := f.read.CaptureProfile(f.ctx, "server")
			if err != nil {
				t.Fatal(err)
			}
			service := catalog.Service{ID: "listed", Name: "Listed", Category: "fixture", Strategy: []string{"wireguard"}, CIDRs: []string{"1.1.1.0/24"}, ProbeURL: "https://1.1.1.1/"}
			switch mode {
			case "catchall":
				service.CIDRs = []string{"0.0.0.0/0"}
			case "domain":
				service.Domains = []string{"example.com"}
			case "family":
				service.CIDRs = []string{"2606:4700:4700::1111/128"}
				service.ProbeURL = "https://[2606:4700:4700::1111]/"
			case "foreign-capture":
				copy := *profile
				profile = &copy
			case "peer-coverage":
				actual, err := f.profiles.Get(f.ctx, "server")
				if err != nil {
					t.Fatal(err)
				}
				content := strings.ReplaceAll(actual.Config(), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 9.9.9.9/32")
				if _, err := f.profiles.Put(f.ctx, "server", "Uncovered", content, actual.Public().Revision); err != nil {
					t.Fatal(err)
				}
				profile, err = f.read.CaptureProfile(f.ctx, "server")
				if err != nil {
					t.Fatal(err)
				}
			}
			if r, err := ReviewWGListSourceMaterial(f.ctx, f.read, profile, service); err == nil || r != nil {
				t.Fatal("unsupported material issued", mode, err)
			}
			if wire, err := os.ReadFile(f.marker); err == nil && (strings.Contains(string(wire), "setconf") || strings.Contains(string(wire), "link add")) {
				t.Fatal("preparation issued a mutation", string(wire))
			}
		})
	}
}
