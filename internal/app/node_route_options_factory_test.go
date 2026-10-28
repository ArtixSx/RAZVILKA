package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type selectorFactoryNoCommands struct{ t *testing.T }

func (r selectorFactoryNoCommands) Run(context.Context, string, ...string) ([]byte, error) {
	r.t.Fatal("selector ran a kernel command")
	return nil, nil
}

type selectorFactoryNoProcesses struct{ t *testing.T }

func (p selectorFactoryNoProcesses) Start(context.Context, dataplane.ProcessSpec) error {
	p.t.Fatal("selector started a process")
	return nil
}
func (p selectorFactoryNoProcesses) Stop(context.Context, dataplane.ProcessSpec) error {
	p.t.Fatal("selector stopped a process")
	return nil
}
func (p selectorFactoryNoProcesses) Running(dataplane.ProcessSpec) bool {
	p.t.Fatal("selector observed a process")
	return false
}

// Exercise the production factory, Manager and real private proof store, with
// no managed-list owner and no injected independent LAN witness. Linux's
// constructor-installed router verifier must be visible before the first Apply.
func TestXrayProductionFactorySelectorUsesExactFreshProofWithoutEffects(t *testing.T) {
	for _, name := range []string{"fresh", "absent", "foreign-engine", "foreign-service", "foreign-wan", "expired", "missing-materializer", "missing-profile", "wrong-engine", "generic", "missing-admission"} {
		t.Run(name, func(t *testing.T) {
			f := newManagedXraySelectorFixture(t)
			f.a.managedXraySelectedTCPList, f.a.managedListPolicy = nil, nil
			f.adapter.Runner = selectorFactoryNoCommands{t}
			f.adapter.Processes = selectorFactoryNoProcesses{t}
			record := f.pass()
			record.ServiceID = "custom-telegram-ip"
			switch name {
			case "foreign-engine":
				record.RoutePathID = "sing-box:" + f.node
			case "foreign-service":
				record.ServiceID = "another-service"
			case "foreign-wan":
				record.NetworkProfile = "wan-ffffffffffff"
			case "expired":
				record.CheckedAt, record.ExpiresAt = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			case "missing-materializer":
				f.adapter.NodeRoutes = nil
			case "missing-profile":
				f.adapter.FreshProfile = nil
			case "wrong-engine":
				f.adapter.EngineID = "sing-box"
			case "generic":
				generic, err := dataplane.NewProxyTunnelAdapter("xray", f.adapter.Configs, f.a.Dataplane.StateRoot)
				if err != nil {
					t.Fatal(err)
				}
				// Public fields alone must not impersonate either trusted constructor.
				generic.NodeRoutes, generic.FreshProfile = f.adapter.NodeRoutes, f.adapter.FreshProfile
				f.a.Dataplane.Adapters["xray"] = generic
			case "missing-admission":
				f.a.NodeHistoryWriteGuard = nil
			}
			if name != "absent" {
				f.record(t, record)
			}
			before, err := f.a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			options := f.a.appendNodeRouteOptions(context.Background(), managedXraySelectorBase())
			route := "xray:" + f.node
			want := name == "fresh" && runtime.GOOS == "linux"
			if routecatalog.ValidForServiceWithOptions(route, "custom-telegram-ip", options) != want || routecatalog.ReadyWithOptions(route, options) != want {
				t.Fatal("production exact-node selector lost constructor/platform/proof boundary", options)
			}
			if name == "fresh" {
				proof, err := f.a.Nodes.ResolveRouteForEngine(context.Background(), "xray", f.node, "custom-telegram-ip", record.NetworkProfile, "", time.Time{}, time.Now())
				if err != nil || proof.Route != route {
					t.Fatal("fresh exact proof was not independently resolvable", err)
				}
			}
			after, err := f.a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("selector changed private proof state", err)
			}
			for _, path := range []string{f.a.Dataplane.StateRoot, filepath.Join(f.root, "stage"), filepath.Join(f.root, "backup")} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("selector created runtime or staged material", path, err)
				}
			}
		})
	}
}
