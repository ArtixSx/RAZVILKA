package usquediag

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const legacyUSQUEFixtureService = "literal-service"
const legacyUSQUEFixtureURL = "https://8.8.8.8/status"

func newLegacyUSQUEProbeTargetFixture(t *testing.T, matches []config.ResourceMatch) (context.Context, *config.Store, *operationgate.Gate, *defaultconsent.Owner, func(), catalog.Catalog) {
	t.Helper()
	root := t.TempDir()
	path, control := filepath.Join(root, "config.json"), filepath.Join(root, "control")
	store, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService(legacyUSQUEFixtureService, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	ctx, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	if matches != nil {
		if _, err := store.UpdateResourceExclusions(ctx, store.Get(), &matches, nil); err != nil {
			t.Fatal(err)
		}
	}
	var noNodes *nodestore.Store
	owner, err := defaultconsent.NewOwner(ctx, gate, &store, &noNodes, path, "", control, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	definitions := catalog.Catalog{Services: []catalog.Service{
		{ID: legacyUSQUEFixtureService, Name: "Literal", Category: "Fixture", Strategy: []string{"usque"}, CIDRs: []string{"8.8.8.8/32"}, ProbeURL: legacyUSQUEFixtureURL},
		{ID: "trace", Name: "Trace", Category: "Fixture", Strategy: []string{"direct"}, Domains: []string{"cloudflare.com"}},
		{ID: "resolver", Name: "Resolver", Category: "Fixture", Strategy: []string{"direct"}, CIDRs: []string{"1.1.1.1/32"}},
		{ID: "alias", Name: "Alias", Category: "Fixture", Strategy: []string{"direct"}, Domains: []string{"deny.example"}, CIDRs: []string{"9.9.9.9/32"}},
	}}
	return ctx, store, gate, owner, release, definitions
}

func TestOwnedLegacyUSQUETargetOriginalLeaseAndExactNetworkRequest(t *testing.T) {
	ctx, store, gate, owner, release, definitions := newLegacyUSQUEProbeTargetFixture(t, nil)
	if _, err := owner.Review(ctx, "usque"); err == nil {
		t.Fatal("legacy read acquired default consent")
	}
	if _, err := owner.ReviewLegacyUSQUEProbeTargets(ctx, store.Get(), definitions, "resolver"); err == nil {
		t.Fatal("inactive unrelated service acquired original scope")
	}
	targets, err := owner.ReviewLegacyUSQUEProbeTargets(ctx, store.Get(), definitions, legacyUSQUEFixtureService)
	if err != nil {
		t.Fatal(err)
	}
	copied := *targets
	if _, err := WithOwnedLegacyUSQUEProbeTargetReview(ctx, &copied, legacyUSQUEFixtureService, legacyUSQUEFixtureURL); !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) {
		t.Fatal("copied target view acquired access", err)
	}
	checked, err := WithOwnedLegacyUSQUEProbeTargetReview(ctx, targets, legacyUSQUEFixtureService, legacyUSQUEFixtureURL)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	visited := make(chan struct{})
	var accepted atomic.Int32
	go func() {
		defer close(visited)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-visited }()
	request := OwnedNetworkRequest{SOCKSAddress: listener.Addr().String(), Timeout: 2 * time.Second, Services: []OwnedServiceProbe{{ID: legacyUSQUEFixtureService, URL: legacyUSQUEFixtureURL}}}
	for _, service := range []OwnedServiceProbe{{ID: "resolver", URL: legacyUSQUEFixtureURL}, {ID: legacyUSQUEFixtureService, URL: "https://8.8.4.4/status"}} {
		altered := request
		altered.Services = []OwnedServiceProbe{service}
		if _, err := probeOwnedNetwork(checked, altered); !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) || OwnedUSQUEProbeRejected(err) {
			t.Fatal("altered service acquired network check", err)
		}
	}
	if accepted.Load() != 0 {
		t.Fatal("request outside target scope reached the isolated listener")
	}
	if _, err := probeOwnedNetwork(checked, request); !OwnedUSQUEProbeRejected(err) || OwnedUSQUEProbeRejected(errors.Join(err, defaultconsent.ErrChanged)) {
		t.Fatal("actual producer did not reach the isolated negative network leaf", err)
	}
	if accepted.Load() == 0 {
		t.Fatal("exact request did not reach the isolated listener")
	}
	release()
	newCtx, newRelease, err := gate.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer newRelease()
	if _, err := WithOwnedLegacyUSQUEProbeTargetReview(newCtx, targets, legacyUSQUEFixtureService, legacyUSQUEFixtureURL); !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) {
		t.Fatal("later exclusive lease reused an old target owner", err)
	}
	newTargets, err := owner.ReviewLegacyUSQUEProbeTargets(newCtx, store.Get(), definitions, legacyUSQUEFixtureService)
	if err != nil {
		t.Fatal(err)
	}
	checked, err = WithOwnedLegacyUSQUEProbeTargetReview(newCtx, newTargets, legacyUSQUEFixtureService, legacyUSQUEFixtureURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService(legacyUSQUEFixtureService, config.ServiceState{Enabled: false, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if _, err := probeOwnedNetwork(checked, request); !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) || OwnedUSQUEProbeRejected(err) {
		t.Fatal("revoked saved state retained target access", err)
	}
}

func TestOwnedLegacyUSQUEExcludesLogicalTargetsAliasesAndEveryPin(t *testing.T) {
	for _, denied := range []string{legacyUSQUEFixtureService, "trace", "resolver", "alias", "unknown"} {
		t.Run(denied, func(t *testing.T) {
			ctx, store, _, owner, _, definitions := newLegacyUSQUEProbeTargetFixture(t, []config.ResourceMatch{{Kind: "service", Value: denied}})
			targets, err := owner.ReviewLegacyUSQUEProbeTargets(ctx, store.Get(), definitions, legacyUSQUEFixtureService)
			if denied == legacyUSQUEFixtureService {
				if !errors.Is(err, defaultconsent.ErrProbeTargetExcluded) {
					t.Fatal("selected service exclusion not classified", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			checked, err := WithOwnedLegacyUSQUEProbeTargetReview(ctx, targets, legacyUSQUEFixtureService, legacyUSQUEFixtureURL)
			switch denied {
			case "trace", "resolver":
				if !errors.Is(err, defaultconsent.ErrProbeTargetExcluded) || OwnedUSQUEProbeRejected(err) {
					t.Fatal("fixed auxiliary logical exclusion skipped", err)
				}
			case "unknown":
				if !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) || OwnedUSQUEProbeRejected(err) {
					t.Fatal("unknown saved logical exclusion omitted", err)
				}
			case "alias":
				if err != nil {
					t.Fatal(err)
				}
				for _, err := range []error{
					checkOwnedProbeTarget(checked, "edge.deny.example", nil),
					checkOwnedProbeTarget(checked, "www.cloudflare.com", []netip.Addr{netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("9.9.9.9")}),
				} {
					if !errors.Is(err, defaultconsent.ErrProbeTargetExcluded) || OwnedUSQUEProbeRejected(err) {
						t.Fatal("alias or nonselected pin skipped saved negative", err)
					}
				}
			}
		})
	}
}
