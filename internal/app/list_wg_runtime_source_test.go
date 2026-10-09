package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Only the existing App test binary's explicitly tagged child uses this WAN
// model. It is an actual child Start/Wait, not native route/traffic evidence.
func init() {
	if os.Getenv("RAZVILKA_APP_WG_SOURCE_CLI_MODEL") != "1" {
		return
	}
	file, err := os.OpenFile(os.Getenv("RAZVILKA_APP_WG_SOURCE_MARKER"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	_, err = file.WriteString(strings.Join(os.Args[1:], " ") + "\n")
	if closeErr := file.Close(); err != nil || closeErr != nil {
		os.Exit(3)
	}
	_, _ = os.Stdout.WriteString(os.Getenv("RAZVILKA_APP_WG_SOURCE_OUTPUT"))
	os.Exit(0)
}

type listWGToolSourceModel struct {
	review     string
	insideLeaf bool
	afterWait  func()
}

func (m *listWGToolSourceModel) CheckWG(ctx context.Context, _ netidentity.Identity) error {
	if m.insideLeaf {
		return errors.New("full tool check inside short Start leaf")
	}
	return ctx.Err()
}
func (m *listWGToolSourceModel) RunWG(ctx context.Context, admission dataplane.WGCommandAdmission, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var output bytes.Buffer
	command.Stdout, command.Stderr, command.WaitDelay = &output, &output, 100*time.Millisecond
	m.insideLeaf = true
	startErr := admission.WithStart(ctx, name, args, m.review, command.Start)
	m.insideLeaf = false
	if command.Process == nil {
		return nil, startErr
	}
	waitErr := command.Wait()
	if m.afterWait != nil {
		m.afterWait()
	}
	return output.Bytes(), errors.Join(startErr, waitErr)
}

type listWGSourceFixture struct {
	a                     *App
	scope                 *ListScopeBinding
	physical              *listScopePhysicalModel
	adapter               *dataplane.WARPWireGuardAdapter
	model                 *listWGToolSourceModel
	profile, path, marker string
}

func newListWGSourceFixture(t *testing.T) *listWGSourceFixture {
	t.Helper()
	f := &listWGSourceFixture{model: &listWGToolSourceModel{review: strings.Repeat("a", 64)}}
	f.a, f.scope, f.physical = listScopeFixture(t, "mac", true)
	root := t.TempDir()
	manager := dataplane.New(filepath.Join(root, "dataplane"))
	if err := os.MkdirAll(manager.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	configs.LiveRoot = filepath.Join(root, "live")
	view, err := configs.ReadExpert("wireguard", "main")
	if err != nil {
		t.Fatal(err)
	}
	f.path = view.Path
	f.profile = "[Interface]\nPrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\nEndpoint = 1.1.1.1:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
	if err := os.MkdirAll(filepath.Dir(f.path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte(f.profile), 0600); err != nil {
		t.Fatal(err)
	}
	f.adapter = dataplane.NewWireGuardAdapter(configs, manager.StateRoot)
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// SAME physical fixture's explicit identity. Provider/tool closure and
	// WAN JSON remain models; Store/catalog/live profile and all owners are real.
	tools := dataplane.WGCommandTools{EngineID: "wireguard", WG: program, IP: program, IPTables: program, IP6Tables: program, ReviewSHA256: f.model.review, Identity: f.physical.facts.Identity, Provider: netidentity.NewProcProvider(), Runner: f.model}
	if err := f.adapter.BindWGCommandTools(tools); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(f.adapter); err != nil {
		t.Fatal(err)
	}
	f.a.Dataplane = manager
	f.a.Catalog = catalog.Catalog{Services: []catalog.Service{{ID: "listed", CIDRs: []string{"1.1.1.0/24"}, ProbeURL: "https://1.1.1.1/"}}}
	f.marker = filepath.Join(root, "child-started")
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	t.Setenv("RAZVILKA_APP_WG_SOURCE_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_APP_WG_SOURCE_MARKER", f.marker)
	t.Setenv("RAZVILKA_APP_WG_SOURCE_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
	return f
}

func TestListWGSourceActualOwnersOnlyComparisonCapture(t *testing.T) {
	f := newListWGSourceFixture(t)
	listScopeOperation(t, f.a, func(ctx context.Context) {
		source, err := f.a.ReviewWGListRuntimeSource(ctx, f.scope, "listed")
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		observation, err := source.Observation(ctx)
		if err != nil || observation.ServiceID != "listed" || observation.Selected != "wireguard" || observation.Resolved != "wireguard" || observation.Profile.ProfileID != "main" || observation.Profile.Revision != "" || len(observation.Profile.ContentSHA256) != 64 || observation.Endpoint.Device != "eth0" || observation.NetworkIdentity != f.physical.facts.Identity {
			t.Fatal("actual source capture unavailable", observation, err)
		}
		observation.Profile.ContentSHA256, observation.Endpoint.Device = "caller-copy", "caller-copy"
		if err := source.Current(ctx); err != nil {
			t.Fatal("comparison copy mutated capture", err)
		}
		snapshot, err := f.scope.Observe(ctx)
		if err != nil || snapshot.Paths != nil || snapshot.ProfileGeneration != 0 || snapshot.NodeGeneration != 0 {
			t.Fatal("source created speculative consumer permission", snapshot, err)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		if err := source.Current(ctx); err == nil {
			t.Fatal("closed source survived")
		}
		if _, err := f.scope.Observe(ctx); err != nil {
			t.Fatal("source closed caller scope", err)
		}
		if f.physical.closes != 0 {
			t.Fatal("source retired shared physics")
		}
		if actual, err := os.ReadFile(f.marker); err != nil || !strings.Contains(string(actual), "-j route get 1.1.1.1 mark 0") {
			t.Fatal("actual read child missing", string(actual), err)
		}
	})
}

func TestListWGSourceRefusesUnboundInitialSubsets(t *testing.T) {
	for _, mode := range []string{"domain", "bad-cidr", "staged-main", "dns-endpoint", "private-endpoint", "absent-service", "foreign-scope", "selected-dns"} {
		t.Run(mode, func(t *testing.T) {
			f := newListWGSourceFixture(t)
			service, scope := "listed", f.scope
			switch mode {
			case "domain":
				f.a.Catalog.Services[0].Domains = []string{"example.com"}
			case "bad-cidr":
				f.a.Catalog.Services[0].CIDRs = []string{"example.com"}
			case "staged-main":
				if _, err := f.adapter.Configs.Stage("wireguard", "main", f.profile); err != nil {
					t.Fatal(err)
				}
			case "dns-endpoint", "private-endpoint":
				host := "vpn.example.com"
				if mode == "private-endpoint" {
					host = "192.168.1.1"
				}
				if err := os.WriteFile(f.path, []byte(strings.ReplaceAll(f.profile, "1.1.1.1", host)), 0600); err != nil {
					t.Fatal(err)
				}
			case "absent-service":
				service = "missing"
			case "foreign-scope":
				_, scope, _ = listScopeFixture(t, "mac", true)
			case "selected-dns":
				path := filepath.Join(t.TempDir(), "dns.json")
				if err := os.WriteFile(path, []byte(`{"schema":1,"draft":{"profile_id":"automatic"},"applied":{"profile_id":"automatic"},"service_applied":{"listed":"private"}}`), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				f.a.DNS, err = dnscontrol.New(path)
				if err != nil {
					t.Fatal(err)
				}
				if wgListBaselineDNS(f.a.DNS, "listed") {
					t.Fatal("fixture did not retain actual selected DNS")
				}
			}
			listScopeOperation(t, f.a, func(ctx context.Context) {
				if source, err := f.a.ReviewWGListRuntimeSource(ctx, scope, service); err == nil || source != nil {
					if source != nil {
						_ = source.Close()
					}
					t.Fatal("unbound subset supplied source", mode, err)
				}
			})
			if _, err := os.Stat(f.marker); !os.IsNotExist(err) {
				t.Fatal("refused subset ran read child", err)
			}
		})
	}
}

func TestListWGSourceRevokesChangedOriginalOwnersDuringRead(t *testing.T) {
	for _, mode := range []string{"store-during-wait", "profile", "catalog", "wan", "dns-owner", "control-stop"} {
		t.Run(mode, func(t *testing.T) {
			f := newListWGSourceFixture(t)
			listScopeOperation(t, f.a, func(ctx context.Context) {
				source, err := f.a.ReviewWGListRuntimeSource(ctx, f.scope, "listed")
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				switch mode {
				case "store-during-wait":
					f.model.afterWait = func() {
						f.model.afterWait = nil
						if err := f.a.Store.SetSafeMode(true); err != nil {
							t.Fatal(err)
						}
					}
				case "profile":
					if err := os.WriteFile(f.path, []byte(strings.ReplaceAll(f.profile, "1.1.1.1", "8.8.8.8")), 0600); err != nil {
						t.Fatal(err)
					}
				case "catalog":
					f.a.Catalog.Services[0].ProbeURL = "https://8.8.8.8/"
				case "wan":
					t.Setenv("RAZVILKA_APP_WG_SOURCE_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth1","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
				case "dns-owner":
					f.a.DNS, err = dnscontrol.New(filepath.Join(t.TempDir(), "new-dns.json"))
					if err != nil {
						t.Fatal(err)
					}
				case "control-stop":
					if _, err := operationgate.RequestSelfUpdateStop(context.Background(), f.a.SelfUpdateFiles.ControlRoot, strings.Repeat("a", 32), 7); err != nil {
						t.Fatal(err)
					}
				}
				observation, err := source.Observation(ctx)
				if err == nil || observation.ServiceID != "" {
					t.Fatal("changed original returned source data", observation, err)
				}
				if err := source.Current(ctx); err == nil {
					t.Fatal("observed revocation did not remain closed")
				}
			})
		})
	}
}
