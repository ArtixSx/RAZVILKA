package defaultconsent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type fixture struct {
	ctx                               context.Context
	gate                              *operationgate.Gate
	store                             *config.Store
	nodes                             *nodestore.Store
	owner                             *Owner
	configPath, nodeRoot, controlRoot string
	grant                             config.DefaultRouteGrant
	policy                            *config.NetworkPolicy
	configured                        bool
	release                           func()
}

func consentFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	cfgPath := filepath.Join(base, "config.json")
	nodePath := filepath.Join(base, "nodes")
	if err := os.Mkdir(nodePath, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	now := time.Now().UTC()
	snapshot, err := nodes.Import(context.Background(), nodestore.Source{ID: "reviewed-feed", Kind: "subscription"}, "vless://123e4567-e89b-12d3-a456-426614174000@owned-fixture.example:443?security=tls&sni=owned-fixture.example", now, time.Hour, false)
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatal("actual source import", err)
	}
	control := filepath.Join(base, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	ctx, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	f := &fixture{ctx: ctx, gate: gate, store: store, nodes: nodes, configPath: cfgPath, nodeRoot: nodePath, controlRoot: control, configured: true, release: release,
		grant:  config.DefaultRouteGrant{Resolved: "xray:" + snapshot.Nodes[0].ID, ProviderClass: "node", ProviderID: snapshot.Nodes[0].ID, SourceIDs: []string{"reviewed-feed"}, SourceKinds: []string{"subscription"}, Protocols: []string{"vless"}},
		policy: &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}}
	owner, err := NewOwner(ctx, gate, &f.store, &f.nodes, cfgPath, nodePath, control, func() bool { return f.configured })
	if err != nil {
		t.Fatal("actual original owner", err)
	}
	f.owner = owner
	t.Cleanup(func() { _ = owner.Close() })
	return f
}

func (f *fixture) approve(t *testing.T) *Review {
	t.Helper()
	if _, err := f.owner.Approve(f.ctx, f.store.Get(), f.policy, []config.DefaultRouteGrant{f.grant}); err != nil {
		t.Fatal("actual approval CAS", err, "saved intent current", config.CurrentDefaultRouteConsent(f.store.Get()))
	}
	r, err := f.owner.Review(f.ctx, f.grant.Resolved)
	if err != nil {
		t.Fatal("actual approved source review", err)
	}
	return r
}

func TestConsentActualSavedOwnerReferenceAndNoLegacyGrant(t *testing.T) {
	f := consentFixture(t)
	if _, err := f.owner.Review(f.ctx, f.grant.Resolved); !errors.Is(err, ErrChanged) {
		t.Fatal("missing approval issued", err)
	}
	r := f.approve(t)
	ref := r.Reference()
	ref.NodeID = "node-forged"
	ref.Sequence++
	if r.Reference().NodeID != f.grant.ProviderID || r.Reference().NodeMaterialSHA256 == "" || !r.MatchesNodeStore(f.nodes) {
		t.Fatal("actual source not bound")
	}
	if err := r.WithCurrent(f.ctx, func() error { return r.Current(f.ctx) }); err != nil {
		t.Fatal("nested actual checks", err)
	}
	copy := &Review{self: r.self, owner: r.owner, ref: r.ref, cfg: r.cfg, grant: r.grant, node: r.node}
	if err := copy.Current(f.ctx); !errors.Is(err, ErrChanged) {
		t.Fatal("copied handle", err)
	}
	if err := r.Current(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("raw context granted", err)
	}
	if _, err := f.owner.Review(f.ctx, "xray:node-unknown"); !errors.Is(err, ErrChanged) {
		t.Fatal("unknown node automatically accepted", err)
	}
	current := f.store.Get()
	current.DefaultRouteConsent.Grants[0].SourceIDs[0] = "unknown"
	if err := r.Current(f.ctx); err != nil {
		t.Fatal("detached config changed original", err)
	}
}

func TestConsentUnknownSourceKindProtocolAndNodeCannotBeApproved(t *testing.T) {
	for _, change := range []string{"source", "kind", "protocol", "node"} {
		t.Run(change, func(t *testing.T) {
			f := consentFixture(t)
			g := f.grant
			g.SourceIDs = append([]string(nil), g.SourceIDs...)
			g.SourceKinds = append([]string(nil), g.SourceKinds...)
			g.Protocols = append([]string(nil), g.Protocols...)
			switch change {
			case "source":
				g.SourceIDs[0] = "unknown"
			case "kind":
				g.SourceKinds[0] = "manual"
			case "protocol":
				g.Protocols[0] = "shadowsocks"
			case "node":
				g.ProviderID = "node-unknown"
				g.Resolved = "xray:node-unknown"
			}
			before := f.store.Get()
			if _, err := f.owner.Approve(f.ctx, before, f.policy, []config.DefaultRouteGrant{g}); err == nil {
				t.Fatal("unknown approval accepted")
			}
			if !reflect.DeepEqual(f.store.Get(), before) {
				t.Fatal("refused approval wrote config")
			}
		})
	}
}

func TestConsentRevokesOnActualSourceConfigControlAndConfiguredOwnerChanges(t *testing.T) {
	for _, change := range []string{"node-disabled", "node-generation", "config", "disk", "stop", "configured", "slot", "close"} {
		t.Run(change, func(t *testing.T) {
			f := consentFixture(t)
			r := f.approve(t)
			switch change {
			case "node-disabled":
				_, _ = f.nodes.SetDisabled(f.ctx, f.grant.ProviderID, true, time.Now().UTC())
			case "node-generation":
				_, _ = f.nodes.SetAlias(f.ctx, f.grant.ProviderID, "local alias", time.Now().UTC())
			case "config":
				_ = f.store.UpdateService("site", config.ServiceState{Enabled: true, Route: "direct"})
			case "disk":
				raw, err := os.ReadFile(f.configPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.configPath, append(raw, ' '), 0600); err != nil {
					t.Fatal(err)
				}
			case "stop":
				if _, err := operationgate.RequestSelfUpdateStop(f.ctx, f.controlRoot, "0123456789abcdef0123456789abcdef", f.store.Get().Revision); err != nil {
					t.Fatal(err)
				}
			case "configured":
				f.configured = false
			case "slot":
				f.nodes = nil
			case "close":
				if err := f.owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Current(f.ctx); err == nil {
				t.Fatal("actual change retained grant")
			}
		})
	}
}

func TestConsentClosingReadDetectsDriftDuringCallback(t *testing.T) {
	f := consentFixture(t)
	r := f.approve(t)
	if err := r.WithCurrent(f.ctx, func() error {
		_, err := f.nodes.SetAlias(f.ctx, f.grant.ProviderID, "changed", time.Now().UTC())
		return err
	}); err == nil {
		t.Fatal("closing source drift accepted")
	}
}

func TestConsentExactCommitAdvancesOnlySanctionedPostimageWithoutRenewal(t *testing.T) {
	f := consentFixture(t)
	r := f.approve(t)
	ref := r.Reference()
	before := f.store.Get()
	started := time.Now()
	undo, err := f.store.CommitNetworkPolicyWithRollback(before, before.NetworkPolicy, before.Services)
	finished := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	after := f.store.Get()
	if err := r.Current(f.ctx); err == nil {
		t.Fatal("commit silently waived old full config check")
	}
	if err := r.AcceptCommitted(f.ctx, after, started, finished); err != nil {
		t.Fatal("exact actual CAS not consumed", err)
	}
	if err := r.Current(f.ctx); err != nil {
		t.Fatal(err)
	}
	after.DefaultRouteConsent.Policy.Clients.SegmentIDs[0] = "detached mutation"
	if err := r.Current(f.ctx); err != nil {
		t.Fatal("caller postimage retained by alias", err)
	}
	if r.Reference() != ref {
		t.Fatal("commit renewed approval/source reference")
	}
	if err := r.AcceptCommitted(f.ctx, after, started, finished); err == nil {
		t.Fatal("postimage replay accepted")
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if err := r.Current(f.ctx); err == nil {
		t.Fatal("undone postimage still current")
	}
}

func TestConsentDurablePermissionRequiresFreshActualOperationAfterRelease(t *testing.T) {
	f := consentFixture(t)
	r := f.approve(t)
	f.release()
	if err := r.Current(f.ctx); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("old operation revived", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, err := f.gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := r.Current(ctx); err != nil {
		t.Fatal("actual fresh operation cannot check same durable intent", err)
	}
}

func TestConsentActualNodeRootPathMustMatchOriginalStoreFD(t *testing.T) {
	f := consentFixture(t)
	other := filepath.Join(filepath.Dir(f.nodeRoot), "other-nodes")
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOwner(f.ctx, f.gate, &f.store, &f.nodes, f.configPath, other, f.controlRoot, func() bool { return true }); err == nil {
		t.Fatal("wrong configured source root accepted")
	}
}
