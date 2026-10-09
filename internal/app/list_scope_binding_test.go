package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Store, disk, durable control, App gate and ScopeReview are actual production
// objects. ONLY physical acquisition/continuity and WAN profile are models.
// No provider, router, native runtime, path health or packet PASS is claimed.
type listScopePhysicalModel struct {
	facts          physicalscope.Snapshot
	selection      physicalscope.SelectionReader
	app            *App
	verifyErr      error
	network        string
	checks, closes int
}

func (m *listScopePhysicalModel) snapshot() physicalscope.Snapshot {
	raw, err := json.Marshal(m.facts)
	if err != nil {
		panic(err)
	}
	var out physicalscope.Snapshot
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func (m *listScopePhysicalModel) acquire(ctx context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.Snapshot, func() error, error) {
	m.selection = selection
	s, err := selection(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	m.facts.Selection = s
	verify := func(ctx context.Context) error {
		m.checks++
		if _, bounded := ctx.Deadline(); !bounded {
			return errors.New("model did not receive bounded use")
		}
		if err := m.app.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			return err
		}
		if release, err := m.app.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
			if release != nil {
				release()
			}
			return errors.New("model did not receive same original exclusive operation")
		}
		current, err := m.selection(ctx)
		if err != nil || !reflect.DeepEqual(current, m.facts.Selection) {
			return errors.Join(physicalscope.ErrUnknown, err)
		}
		return m.verifyErr
	}
	close := func() error { m.closes++; return nil }
	return verify, m.snapshot, close, nil
}

func listScopeOperation(t *testing.T, a *App, use func(context.Context)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	use(ctx)
}

func listScopeFixture(t *testing.T, membership string, routers bool) (*App, *ListScopeBinding, *listScopePhysicalModel) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	store, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "wireguard"}); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: control}}
	if err := a.ConfigureDefaultConsent(path, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.CloseDefaultConsent() })
	m := &listScopePhysicalModel{app: a, network: strings.Repeat("1", 64), facts: physicalscope.Snapshot{
		ReviewID: strings.Repeat("2", 32),
		Identity: netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: "12345678-1234-1234-1234-123456789abc", PlatformReviewSHA256: "f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733"},
		Segments: []physicalscope.Segment{{ID: "Bridge0", NativeName: "Home", Interface: "br0", IfIndex: 3, Home: true, Prefixes: []string{"192.168.1.0/24", "fd00::/64"}}},
		Devices:  []physicalscope.Device{{ID: "included", MAC: "02:00:00:00:00:01", Interface: "br0", IfIndex: 3, SegmentID: "Bridge0", Addresses: []string{"192.168.1.40", "fd00::40"}, LinkLocalAddresses: []string{"fe80::40"}}},
	}}
	if routers {
		m.facts.Segments[0].RouterNeighbors = []physicalscope.RouterNeighbor{{Address: "2001:db8::1", MAC: "02:00:00:00:00:ff", Flags: 128, Type: 1}}
	}
	a.FreshProfile = func(context.Context) (string, error) { return m.network, nil }
	var b *ListScopeBinding
	listScopeOperation(t, a, func(ctx context.Context) {
		epoch, err := a.Operations.ReviewControlEpoch(ctx, control)
		if err != nil {
			t.Fatal(err)
		}
		defer epoch.Close()
		policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "selected_devices", SegmentIDs: []string{"Bridge0"}, DeviceIDs: []string{"included"}, NewDevices: "base"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
		if membership == "all" {
			policy.Clients.Mode, policy.Clients.DeviceIDs, policy.Clients.NewDevices = "lan_except", nil, "inherit"
		}
		ref := epoch.Reference()
		if _, err := store.ApproveDefaultRouteConsent(ctx, store.Get(), policy, []config.DefaultRouteGrant{}, ref.InstallationID, ref.Sequence); err != nil {
			t.Fatal(err)
		}
		b, err = newListScopeBinding(ctx, a, m.acquire)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() { _ = b.Close() })
	return a, b, m
}

func listScopeCompilation(t *testing.T, ctx context.Context, a *App, b *ListScopeBinding) *DefaultRouteCompilation {
	t.Helper()
	snapshot, err := b.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, pathModel, _ := defaultRouteFixture()
	// Positive path proof is explicitly a separate compiler fixture model.
	snapshot.Paths = map[string]DefaultRoutePath{"listed": pathModel.Paths["listed"]}
	snapshot.ProfileGeneration = 1
	c, err := CompileDefaultRoutePolicy(a.Store.Get(), snapshot, defaultRouteListedRoutes(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestListScopeActualOwnersSupplyOnlyDetachedCompilerScope(t *testing.T) {
	a, b, m := listScopeFixture(t, "mac", true)
	listScopeOperation(t, a, func(ctx context.Context) {
		snapshot, err := b.Observe(ctx)
		if err != nil || snapshot.Authority != b.scope.Reference() || snapshot.DNSMode != "baseline" || snapshot.Paths != nil || snapshot.ProfileGeneration != 0 || snapshot.NodeGeneration != 0 || len(snapshot.AllowedDefaultRoutes) != 0 {
			t.Fatal("scope supplied path/provider authority", snapshot, err)
		}
		if len(a.Store.Get().DefaultRouteConsent.Grants) != 0 || len(snapshot.Scope.Devices) != 1 || len(snapshot.Devices[0].Addresses) != 2 {
			t.Fatal("router/link-local became a positive device/address", snapshot)
		}
		snapshot.Scope.Segments[0].Prefixes[0] = netip.MustParsePrefix("10.0.0.0/8")
		snapshot.Devices[0].Addresses[0] = netip.MustParseAddr("8.8.8.8")
		if actual, err := b.Observe(ctx); err != nil || actual.Scope.Segments[0].Prefixes[0].String() != "192.168.1.0/24" || actual.Devices[0].Addresses[0].String() != "192.168.1.40" {
			t.Fatal("caller DTO mutated original physics", actual, err)
		}
		if err := b.ScopeCheck(ctx, nil); err == nil {
			t.Fatal("unbound owner admitted a LAN plan")
		}
		c := listScopeCompilation(t, ctx, a, b)
		if err := b.BindCompilation(ctx, c); err != nil {
			t.Fatal(err)
		}
		plan := c.LAN()
		if err := b.ScopeCheck(ctx, plan); err != nil {
			t.Fatal(err)
		}
		plan.Ingress[0].Sources[0] = "10.0.0.0/8"
		if err := b.ScopeCheck(ctx, plan); err == nil {
			t.Fatal("edited plan borrowed physical proof")
		}
		foreign, err := dataplane.CompileLANPolicyRuntime(strings.Repeat("f", 64), c.LAN().Ingress)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ScopeCheck(ctx, foreign); err == nil {
			t.Fatal("different generation borrowed scope")
		}
		if err := b.ScopeCheck(ctx, c.LAN()); err != nil {
			t.Fatal("invalid proposal poisoned current original review", err)
		}
		if err := b.BindCompilation(ctx, c); err == nil {
			t.Fatal("owner rebound compilation")
		}
	})
	if m.checks == 0 {
		t.Fatal("physical model was skipped")
	}
}

func TestListScopeRequiresFreshSameBoundedOriginalOperation(t *testing.T) {
	a, b, _ := listScopeFixture(t, "mac", false)
	if _, err := b.Observe(context.Background()); err == nil {
		t.Fatal("raw lifetime context admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := b.Observe(ctx); err == nil {
		t.Fatal("bounded context without original gate admitted")
	}
	foreignGate := &operationgate.Gate{}
	foreign, release, err := foreignGate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Observe(foreign); err == nil {
		t.Fatal("foreign gate admitted")
	}
	release()
	old, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := b.Observe(old); err == nil {
		t.Fatal("released original context survived")
	}
	copy := &ListScopeBinding{self: b, app: a}
	for _, bad := range []*ListScopeBinding{nil, {}, copy} {
		if _, err := bad.Observe(ctx); err == nil {
			t.Fatal("unissued/copied binding admitted")
		}
	}
	listScopeOperation(t, a, func(ctx context.Context) {
		if _, err := b.Observe(ctx); err != nil {
			t.Fatal("fresh operation refused", err)
		}
	})
}

func TestListScopeChangedEvidenceCannotRevive(t *testing.T) {
	for _, kind := range []string{"physical-unknown", "snapshot", "wan", "disk", "store-slot", "closed-scope"} {
		t.Run(kind, func(t *testing.T) {
			a, b, m := listScopeFixture(t, "mac", false)
			listScopeOperation(t, a, func(ctx context.Context) {
				var restore func()
				switch kind {
				case "physical-unknown":
					m.verifyErr = physicalscope.ErrUnknown
					restore = func() { m.verifyErr = nil }
				case "snapshot":
					m.facts.Segments[0].IfIndex++
					restore = func() { m.facts.Segments[0].IfIndex-- }
				case "wan":
					old := m.network
					m.network = strings.Repeat("f", 64)
					restore = func() { m.network = old }
				case "closed-scope":
					_ = b.scope.Close()
					restore = func() {}
				case "store-slot":
					old := a.Store
					a.Store = nil
					restore = func() { a.Store = old }
				case "disk":
					path := a.defaultConsent.configPath
					old, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					changed := a.Store.Get()
					changed.Listen = ":9999"
					data, err := json.Marshal(changed)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						if err := os.WriteFile(path, old, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				if _, err := b.Observe(ctx); !errors.Is(err, ErrListScopeChanged) {
					t.Fatal("changed owner survived", kind, err)
				}
				restore()
				if _, err := b.Observe(ctx); !errors.Is(err, ErrListScopeChanged) {
					t.Fatal("restored evidence revived review", kind, err)
				}
			})
		})
	}
}

func TestListScopeAuthorizedCASAdvancesOriginalHandleOnly(t *testing.T) {
	a, b, _ := listScopeFixture(t, "mac", false)
	listScopeOperation(t, a, func(ctx context.Context) {
		c := listScopeCompilation(t, ctx, a, b)
		if err := b.BindCompilation(ctx, c); err != nil {
			t.Fatal(err)
		}
		before := a.Store.Get()
		started := time.Now()
		undo, err := a.Store.CommitNetworkPolicyWithRollback(before, c.Policy(), before.Services)
		finished := time.Now()
		if err != nil {
			t.Fatal(err)
		}
		after := a.Store.Get()
		if err := b.AcceptCommitted(ctx, after, started, finished); err != nil {
			t.Fatal("actual sanctioned CAS refused", err)
		}
		after.NetworkPolicy.Clients.SegmentIDs[0] = "caller-edited"
		if err := b.ScopeCheck(ctx, c.LAN()); err != nil {
			t.Fatal("committed owner borrowed caller postimage", err)
		}
		if b.scope.Reference() != b.reference || b.expected.Revision != before.Revision+1 {
			t.Fatal("CAS replaced authority or missed actual image")
		}
		if err := undo(); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Observe(ctx); !errors.Is(err, ErrListScopeChanged) {
			t.Fatal("ordinary restored preimage revived committed handle", err)
		}
	})
}

func TestListScopeRejectsUnapprovedCommitAndUnsafeRouterMembership(t *testing.T) {
	for _, kind := range []string{"postimage", "times", "router-all", "altered-compilation"} {
		t.Run(kind, func(t *testing.T) {
			mode := "mac"
			if kind == "router-all" {
				mode = "all"
			}
			a, b, _ := listScopeFixture(t, mode, true)
			listScopeOperation(t, a, func(ctx context.Context) {
				c := listScopeCompilation(t, ctx, a, b)
				if kind == "router-all" {
					gate := c.LAN().Ingress
					gate[0].ExcludedMACs = nil
					var err error
					c.lan, err = dataplane.CompileLANPolicyRuntime(c.Digest(), gate)
					if err != nil {
						t.Fatal(err)
					}
					if err := b.BindCompilation(ctx, c); err == nil {
						t.Fatal("broad membership dropped actual router negatives")
					}
					return
				}
				if kind == "altered-compilation" {
					c.snapshot.Scope.Devices[0].MAC = "02:00:00:00:00:fe"
					if err := b.BindCompilation(ctx, c); err == nil {
						t.Fatal("detached scope DTO bound a runtime")
					}
					return
				}
				before := a.Store.Get()
				started := time.Now()
				if _, err := a.Store.CommitNetworkPolicyWithRollback(before, c.Policy(), before.Services); err != nil {
					t.Fatal(err)
				}
				finished := time.Now()
				after := a.Store.Get()
				if kind == "postimage" {
					after.Listen = ":9999"
				} else {
					started, finished = started.Add(-time.Hour), finished.Add(-time.Hour)
				}
				if err := b.AcceptCommitted(ctx, after, started, finished); !errors.Is(err, ErrListScopeChanged) {
					t.Fatal("unapproved CAS was adopted", err)
				}
				if _, err := b.Observe(ctx); !errors.Is(err, ErrListScopeChanged) {
					t.Fatal("failed CAS acceptance renewed owner", err)
				}
			})
		})
	}
}

func TestListScopeCloseRetiresOwnHandlesAndConstructorFailureJoins(t *testing.T) {
	a, b, m := listScopeFixture(t, "mac", false)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil || m.closes != 1 {
		t.Fatal("physical close was not idempotent", err, m.closes)
	}
	listScopeOperation(t, a, func(ctx context.Context) {
		if _, err := b.Observe(ctx); err == nil {
			t.Fatal("closed binding survived")
		}
		fresh, err := a.ReviewListScope(ctx)
		if err != nil {
			t.Fatal("binding closed App shared consent owner", err)
		}
		_ = fresh.Close()
		m.verifyErr = physicalscope.ErrUnknown
		if _, err := newListScopeBinding(ctx, a, m.acquire); err == nil || m.closes != 2 {
			t.Fatal("failed constructor leaked physical handle", err, m.closes)
		}
		if _, err := NewReviewedStockNC1812ListScopeBinding(ctx, a, nil); err == nil {
			t.Fatal("nil actual provider accepted")
		}
	})
}

func TestListScopeCloseJoinsInFlightOriginalUse(t *testing.T) {
	a, b, m := listScopeFixture(t, "mac", false)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	original := b.verifyPhysical
	b.verifyPhysical = func(ctx context.Context) error {
		once.Do(func() { close(entered); <-proceed })
		return original(ctx)
	}
	observed, closed := make(chan error, 1), make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ctx, release, err := a.Operations.ExclusiveContext(ctx)
		if err == nil {
			defer release()
			_, err = b.Observe(ctx)
		}
		observed <- err
	}()
	select {
	case <-entered:
	case err := <-observed:
		t.Fatal("original operation did not reach physical model", err)
	}
	go func() { closed <- b.Close() }()
	select {
	case err := <-closed:
		close(proceed)
		t.Fatal("Close released handles during live original use", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(proceed)
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil || m.closes != 1 {
		t.Fatal("Close did not join and release original handles", err, m.closes)
	}
}

func TestListScopeRetainsEntireApprovedGuestSelection(t *testing.T) {
	a, old, m := listScopeFixture(t, "mac", false)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	listScopeOperation(t, a, func(ctx context.Context) {
		before := a.Store.Get()
		policy := config.CloneNetworkPolicy(before.NetworkPolicy)
		policy.Revision++
		policy.Clients.SegmentIDs = []string{"Bridge0", "Bridge1"}
		consent := before.DefaultRouteConsent
		if _, err := a.Store.ApproveDefaultRouteConsent(ctx, before, policy, consent.Grants, consent.InstallationID, consent.Sequence); err != nil {
			t.Fatal(err)
		}
		m.facts.ReviewID = strings.Repeat("3", 32)
		m.facts.Segments = append(m.facts.Segments, physicalscope.Segment{ID: "Bridge1", NativeName: "Guest", Interface: "br1", IfIndex: 4, Guest: true, Prefixes: []string{"192.168.2.0/24"}})
		b, err := newListScopeBinding(ctx, a, m.acquire)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		snapshot, err := b.Observe(ctx)
		if err != nil || len(snapshot.Scope.Segments) != 2 || !reflect.DeepEqual(snapshot.GuestSegmentIDs, []string{"Bridge1"}) || len(m.facts.Selection.SegmentIDs) != 2 {
			t.Fatal("approved guest was omitted or inferred as Home", snapshot, err)
		}
	})
}
