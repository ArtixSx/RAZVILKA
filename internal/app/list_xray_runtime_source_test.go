package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"github.com/ArtixSx/razvilka/internal/sources"
)

type listXraySourceTransport struct{}

func (listXraySourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("# local wire fixture\n8.8.8.0/24\n1.1.1.0/24\n")), Request: req}, nil
}

type listXraySourceRejectedTransport struct{ unavailable bool }

func (tr listXraySourceRejectedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if tr.unavailable {
		return nil, errors.New("local fixture source unavailable")
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader("<html>rejected replacement 9.9.9.0/24</html>")), Request: req}, nil
}

type listXraySourceFixture struct {
	a                   *App
	scope               *ListScopeBinding
	physical            *listScopePhysicalModel
	adapter             *dataplane.ProxyTunnelAdapter
	root, nodeID, cache string
	now                 time.Time
}

// Store, control, source Refresh/cache, private node import, actual factory and
// Manager registration are production objects. Physical/WAN continuity, the
// HTTP wire response and recorded service health are explicit fixture models.
// No runtime process, DNS, router, native traffic or Telegram PASS is claimed.
func newListXraySourceFixture(t *testing.T, proofEngine string) *listXraySourceFixture {
	t.Helper()
	f := &listXraySourceFixture{root: t.TempDir(), now: time.Now().UTC()}
	configPath := filepath.Join(f.root, "config.json")
	storeConfig, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeConfig.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(f.root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
	f.a = &App{Store: storeConfig, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: control}}
	f.physical = &listScopePhysicalModel{app: f.a, network: "wan-0123456789ab", facts: physicalscope.Snapshot{
		ReviewID: strings.Repeat("2", 32),
		Identity: netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: "12345678-1234-1234-1234-123456789abc", PlatformReviewSHA256: "f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733"},
		Segments: []physicalscope.Segment{{ID: "Bridge0", NativeName: "Home", Interface: "br0", IfIndex: 3, Home: true, Prefixes: []string{"192.168.1.0/24"}, RouterNeighbors: []physicalscope.RouterNeighbor{{Address: "2001:db8::1", MAC: "02:00:00:00:00:ff", Flags: 128, Type: 1}}}},
		Devices:  []physicalscope.Device{{ID: "included", MAC: "02:00:00:00:00:01", Interface: "br0", IfIndex: 3, SegmentID: "Bridge0", Addresses: []string{"192.168.1.40"}}},
	}}
	f.a.FreshProfile = func(context.Context) (string, error) { return f.physical.network, nil }
	private := filepath.Join(f.root, "nodes")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	f.a.Nodes, err = nodestore.Open(private)
	if err != nil {
		t.Fatal(err)
	}
	store := f.a.Nodes
	t.Cleanup(func() { _ = store.Close() })
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"},
		"vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls&sni=front.example", f.now, time.Hour, false)
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatal("actual node import", err)
	}
	f.nodeID = snapshot.Nodes[0].ID
	if proofEngine != "" {
		f.record(t, proofEngine, "fixture-health", f.now)
	}
	f.cache = filepath.Join(f.root, "cache")
	if err := os.Mkdir(f.cache, 0700); err != nil {
		t.Fatal(err)
	}
	src := sources.Source{ID: "reviewed-networks", Name: "Reviewed networks", Kind: "cidrs", URL: "https://source.example/networks", Enabled: true,
		Services: []string{"listed"}, MinEntries: 2, TTLHours: 1, TrustTier: "official"}
	f.a.Sources = sources.NewManager(sources.Registry{Schema: 2, Sources: []sources.Source{src}}, f.cache)
	f.a.Sources.SetHTTPClient(&http.Client{Transport: listXraySourceTransport{}})
	if err := f.a.Sources.Refresh(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	f.a.Catalog = catalog.Catalog{Services: []catalog.Service{{ID: "listed", Name: "Listed service", Category: "fixture", Strategy: []string{"xray"},
		ProbeURL: "https://1.1.1.1/", SourceRefs: []string{src.ID}}}}
	f.a.Dataplane = dataplane.New(filepath.Join(f.root, "dataplane"))
	if err := os.Mkdir(f.a.Dataplane.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	f.adapter, err = NewXrayNodeRuntime(NodeRuntimeFactoryOptions{Configs: engineconfig.New(filepath.Join(f.root, "stage"), filepath.Join(f.root, "backup")),
		Nodes: store, StateRoot: f.a.Dataplane.StateRoot, FreshProfile: f.a.FreshProfile})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.a.Dataplane.Register(f.adapter); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "xray:" + f.nodeID}); err != nil {
		t.Fatal(err)
	}
	if err := f.a.ConfigureDefaultConsent(configPath, private); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.a.CloseDefaultConsent() })
	listScopeOperation(t, f.a, func(ctx context.Context) {
		epoch, err := f.a.Operations.ReviewControlEpoch(ctx, control)
		if err != nil {
			t.Fatal(err)
		}
		defer epoch.Close()
		policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "selected_devices", SegmentIDs: []string{"Bridge0"}, DeviceIDs: []string{"included"}, NewDevices: "base"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
		ref := epoch.Reference()
		if _, err := f.a.Store.ApproveDefaultRouteConsent(ctx, f.a.Store.Get(), policy, []config.DefaultRouteGrant{}, ref.InstallationID, ref.Sequence); err != nil {
			t.Fatal(err)
		}
		f.scope, err = newListScopeBinding(ctx, f.a, f.physical.acquire)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() { _ = f.scope.Close() })
	return f
}

func (f *listXraySourceFixture) record(t *testing.T, engine, probe string, at time.Time) {
	t.Helper()
	check := nodestore.CheckRecord{ProbeID: probe, ServiceID: "listed", NetworkProfile: f.physical.network, RoutePathID: engine + ":" + f.nodeID,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: at, ExpiresAt: at.Add(time.Hour)}
	if _, err := f.a.Nodes.RecordCheck(context.Background(), f.nodeID, check, at); err != nil {
		t.Fatal(err)
	}
}

func (f *listXraySourceFixture) review(t *testing.T, ctx context.Context) *XrayListRuntimeSource {
	t.Helper()
	r, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, "listed", f.adapter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestListXraySourceOriginalOwnersAndDetachedObservation(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	listScopeOperation(t, f.a, func(ctx context.Context) {
		before := f.a.Store.Get()
		paths := []string{filepath.Join(f.cache, "reviewed-networks.cache.json"), filepath.Join(f.root, "nodes", "nodes.private.json")}
		images := make([][]byte, len(paths))
		for i, path := range paths {
			var err error
			images[i], err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(images[i])
		}
		r := f.review(t, ctx)
		o, err := r.Observation(ctx)
		if err != nil || o.ServiceID != "listed" || o.Selected != "xray:"+f.nodeID || o.Resolved != o.Selected || o.WANProfile != f.physical.network ||
			o.Node.NodeID != f.nodeID || o.Node.NodeGeneration != 2 || len(o.RouteMaterialSHA256) != 64 || len(o.Node.MaterialSHA256) != 64 ||
			!reflect.DeepEqual(o.Sources.CIDRs, []string{"1.1.1.0/24", "8.8.8.0/24"}) || !reflect.DeepEqual(o.Service.CIDRs, o.Sources.CIDRs) ||
			len(o.Sources.Revisions) != 1 || o.Sources.Revisions[0].RawSHA256 == o.Sources.Revisions[0].ContentSHA256 || o.NetworkIdentity != f.physical.facts.Identity {
			t.Fatal("original source comparison missing", o, err)
		}
		o.Service.CIDRs[0], o.Sources.CIDRs[0], o.Sources.SourceIDs[0], o.Sources.Revisions[0].RawSHA256, o.Node.MaterialSHA256 = "0.0.0.0/0", "0.0.0.0/0", "caller", "caller", "caller"
		if err := r.Current(ctx); err != nil {
			t.Fatal("DTO changed original capture", err)
		}
		for i, path := range paths {
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(images[i]) {
				t.Fatal("source review wrote owners", path, err)
			}
			clear(after)
		}
		if !reflect.DeepEqual(before, f.a.Store.Get()) {
			t.Fatal("review wrote Store")
		}
		snapshot, err := f.scope.Observe(ctx)
		if err != nil || snapshot.Paths != nil || snapshot.ProfileGeneration != 0 || snapshot.NodeGeneration != 0 {
			t.Fatal("source minted path authority", err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal("idempotent close", err)
		}
		if err := r.Current(ctx); err == nil {
			t.Fatal("closed source admitted")
		}
		if _, err := f.scope.Observe(ctx); err != nil || f.physical.closes != 0 {
			t.Fatal("source closed shared scope", err)
		}
		if _, err := f.a.Nodes.Snapshot(ctx, time.Now()); err != nil {
			t.Fatal("source closed shared node owner", err)
		}
		if _, cidrs := f.a.Sources.EntriesForService("listed"); len(cidrs) != 2 {
			t.Fatal("source closed shared source owner")
		}
		registration, err := f.a.Dataplane.ReviewXrayRegistration(ctx, f.adapter)
		if err != nil {
			t.Fatal("source unregistered runtime", err)
		}
		_ = registration.Close()
	})
}

func TestListXraySourceRequiresExactSourceScopeAndXrayEligibility(t *testing.T) {
	for _, mode := range []string{"missing-proof", "sing-box-proof", "foreign-wan", "domain", "extra-cidr", "missing-source", "extra-source", "duplicate-source", "outside-probe", "invalid-predicate", "foreign-adapter", "foreign-scope", "raw-context"} {
		t.Run(mode, func(t *testing.T) {
			engine := "xray"
			if mode == "missing-proof" {
				engine = ""
			}
			if mode == "sing-box-proof" {
				engine = "sing-box"
			}
			f := newListXraySourceFixture(t, engine)
			listScopeOperation(t, f.a, func(ctx context.Context) {
				adapter, scope := f.adapter, f.scope
				s := &f.a.Catalog.Services[0]
				switch mode {
				case "foreign-wan":
					f.physical.network = "wan-fedcba987654"
				case "domain":
					s.Domains = []string{"service.example"}
				case "extra-cidr":
					s.CIDRs = []string{"9.9.9.0/24"}
				case "missing-source":
					s.SourceRefs = nil
				case "extra-source":
					s.SourceRefs = append(s.SourceRefs, "unheld")
				case "duplicate-source":
					s.SourceRefs = append(s.SourceRefs, s.SourceRefs[0])
				case "outside-probe":
					s.ProbeURL = "https://9.9.9.9/"
				case "invalid-predicate":
					s.Name = ""
				case "foreign-adapter":
					foreign, err := NewXrayNodeRuntime(NodeRuntimeFactoryOptions{Configs: engineconfig.New(f.root, f.root), Nodes: f.a.Nodes, StateRoot: f.a.Dataplane.StateRoot, FreshProfile: f.a.FreshProfile})
					if err != nil {
						t.Fatal(err)
					}
					adapter = foreign
				case "foreign-scope":
					scope = &ListScopeBinding{self: f.scope}
				case "raw-context":
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					defer cancel()
				}
				r, err := f.a.ReviewXrayListRuntimeSource(ctx, scope, "listed", adapter)
				if r != nil {
					_ = r.Close()
				}
				if err == nil {
					t.Fatal("unbound initial subset accepted")
				}
			})
		})
	}
}

func TestListXraySourceObservedChangesRevokePermanently(t *testing.T) {
	for _, change := range []string{"refresh", "applied-source", "node-generation", "config", "catalog-predicate", "sources-owner", "nodes-owner", "manager-owner", "registry-generation", "control-root", "stop", "wan", "physics"} {
		t.Run(change, func(t *testing.T) {
			f := newListXraySourceFixture(t, "xray")
			listScopeOperation(t, f.a, func(ctx context.Context) {
				r := f.review(t, ctx)
				restore := func() {}
				switch change {
				case "refresh":
					if err := f.a.Sources.Refresh(ctx, "reviewed-networks"); err != nil {
						t.Fatal(err)
					}
				case "applied-source":
					if err := f.a.Sources.SetDraft("reviewed-networks", false); err != nil {
						t.Fatal(err)
					}
					if err := f.a.Sources.Apply(); err != nil {
						t.Fatal(err)
					}
					restore = func() { _ = f.a.Sources.SetDraft("reviewed-networks", true); _ = f.a.Sources.Apply() }
				case "node-generation":
					f.record(t, "xray", "new-health", time.Now().UTC())
				case "config":
					state := f.a.Store.Get().Services["listed"]
					altered := state
					altered.Enabled = false
					if err := f.a.Store.UpdateService("listed", altered); err != nil {
						t.Fatal(err)
					}
					restore = func() { _ = f.a.Store.UpdateService("listed", state) }
				case "catalog-predicate":
					f.a.Catalog.Services[0].ProbeURL = "https://8.8.8.8/"
					restore = func() { f.a.Catalog.Services[0].ProbeURL = "https://1.1.1.1/" }
				case "sources-owner":
					old := f.a.Sources
					f.a.Sources = sources.NewManager(sources.Registry{}, f.cache)
					restore = func() { f.a.Sources = old }
				case "nodes-owner":
					old := f.a.Nodes
					f.a.Nodes = nil
					restore = func() { f.a.Nodes = old }
				case "manager-owner":
					old := f.a.Dataplane
					f.a.Dataplane = dataplane.New(old.StateRoot)
					restore = func() { f.a.Dataplane = old }
				case "registry-generation":
					// A process-free second registry entry changes the actual
					// generation; it supplies no runtime/readiness proof.
					if err := f.a.Dataplane.Register(&dataplane.ProxyTunnelAdapter{EngineID: "sing-box", StateRoot: f.a.Dataplane.StateRoot}); err != nil {
						t.Fatal(err)
					}
				case "control-root":
					old := f.a.SelfUpdateFiles.ControlRoot
					f.a.SelfUpdateFiles.ControlRoot = filepath.Join(f.root, "foreign-control")
					restore = func() { f.a.SelfUpdateFiles.ControlRoot = old }
				case "stop":
					if _, err := operationgate.RequestSelfUpdateStop(ctx, f.a.SelfUpdateFiles.ControlRoot, strings.Repeat("a", 32), 1); err != nil {
						t.Fatal(err)
					}
				case "wan":
					f.physical.network = "wan-fedcba987654"
					restore = func() { f.physical.network = "wan-0123456789ab" }
				case "physics":
					old := f.physical.facts.Segments[0].IfIndex
					f.physical.facts.Segments[0].IfIndex++
					restore = func() { f.physical.facts.Segments[0].IfIndex = old }
				}
				if err := r.Current(ctx); err == nil {
					t.Fatal("changed source admitted")
				}
				restore()
				if _, err := r.Observation(ctx); err == nil {
					t.Fatal("restored tuple revived invalid source")
				}
			})
		})
	}
}

func TestListXraySourceFailedRefreshKeepsSameCanonicalNodeAndScope(t *testing.T) {
	for _, unavailable := range []bool{true, false} {
		t.Run(map[bool]string{true: "unavailable", false: "rejected-bytes"}[unavailable], func(t *testing.T) {
			f := newListXraySourceFixture(t, "xray")
			listScopeOperation(t, f.a, func(ctx context.Context) {
				r := f.review(t, ctx)
				original, err := r.Observation(ctx)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(f.cache, "reviewed-networks.cache.json")
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				f.a.Sources.SetHTTPClient(&http.Client{Transport: listXraySourceRejectedTransport{unavailable: unavailable}})
				if err := f.a.Sources.Refresh(ctx, "reviewed-networks"); err == nil {
					t.Fatal("bad refresh accepted")
				}
				if err := r.Current(ctx); err != nil {
					t.Fatal("refresh failure revoked original App source", err)
				}
				o, err := r.Observation(ctx)
				if err != nil || !reflect.DeepEqual(o, original) {
					t.Fatal("failure changed source/node/scope or renewed expiry", err)
				}
				fresh := f.review(t, ctx)
				o, err = fresh.Observation(ctx)
				if err != nil || !reflect.DeepEqual(o, original) {
					t.Fatal("new App capture refused or renewed unchanged LKG", err)
				}
				after, err := os.ReadFile(path)
				if err != nil || string(after) != string(before) {
					t.Fatal("rejected bytes replaced accepted list", err)
				}
				if f.physical.closes != 0 {
					t.Fatal("candidate failure retired shared scope")
				}
			})
		})
	}
}

func TestListXraySourceReleasedOriginalOperationCannotRevive(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx, release, err := f.a.Operations.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	r := f.review(t, ctx)
	release()
	if ctx.Err() != nil {
		t.Fatal("fixture canceled instead of releasing operation")
	}
	fresh, freshRelease, err := f.a.Operations.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer freshRelease()
	if err := r.Current(fresh); err == nil {
		t.Fatal("new operation revived old source")
	}
}

func TestListXraySourceCopiesAndInvalidCallsCannotOwnOriginal(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	listScopeOperation(t, f.a, func(ctx context.Context) {
		r := f.review(t, ctx)
		copy := &XrayListRuntimeSource{self: r}
		if err := copy.Current(ctx); !errors.Is(err, ErrXrayListSource) {
			t.Fatal(err)
		}
		if err := copy.Close(); !errors.Is(err, ErrXrayListSource) {
			t.Fatal(err)
		}
		if err := r.Current(context.Background()); err == nil {
			t.Fatal("unbounded use")
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := r.Observation(canceled); err == nil {
			t.Fatal("canceled use")
		}
		if err := r.Current(ctx); err != nil {
			t.Fatal("invalid call poisoned original", err)
		}
	})
}

func TestListXraySourceRetainsCallerValuesAndOriginalDeadline(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	listScopeOperation(t, f.a, func(ctx context.Context) {
		r := f.review(t, ctx)
		type sourceKey struct{}
		caller := context.WithValue(ctx, sourceKey{}, "same-admitted-use")
		deadline, _ := ctx.Deadline()
		original := f.scope.verifyPhysical
		f.scope.verifyPhysical = func(c context.Context) error {
			actual, finite := c.Deadline()
			if c.Value(sourceKey{}) != "same-admitted-use" || !finite || actual.After(deadline) {
				return errors.New("source detached caller values or original deadline")
			}
			return original(c)
		}
		defer func() { f.scope.verifyPhysical = original }()
		if err := r.Current(caller); err != nil {
			t.Fatal(err)
		}
	})
}

func TestListXraySourceCloseCancelsAndJoinsInFlightRead(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	listScopeOperation(t, f.a, func(ctx context.Context) {
		r := f.review(t, ctx)
		entered, canceled, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
		original := f.scope.verifyPhysical
		f.scope.verifyPhysical = func(c context.Context) error { close(entered); <-c.Done(); close(canceled); <-finish; return c.Err() }
		readDone, closeDone := make(chan error, 1), make(chan error, 1)
		go func() { readDone <- r.Current(ctx) }()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("read did not enter")
		}
		go func() { closeDone <- r.Close() }()
		select {
		case <-canceled:
		case <-ctx.Done():
			t.Fatal("Close did not cancel retained read")
		}
		select {
		case <-closeDone:
			t.Fatal("Close returned before read joined")
		default:
		}
		if err := r.Current(ctx); err == nil {
			t.Fatal("new read entered closing source")
		}
		close(finish)
		if err := <-readDone; err == nil {
			t.Fatal("canceled read succeeded")
		}
		if err := <-closeDone; err != nil {
			t.Fatal(err)
		}
		f.scope.verifyPhysical = original
		if f.physical.closes != 0 {
			t.Fatal("source Close retired shared physical handle")
		}
	})
}
