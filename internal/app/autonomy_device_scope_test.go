package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

const autonomyDeviceIncluded = "mac-02-00-00-00-00-01"
const autonomyDeviceExcluded = "mac-02-00-00-00-00-02"

// Store, approved consent, original operation/control and exclusions are real.
// ONLY physical acquisition/continuity and WAN are explicit existing models.
// This exercises no factory/provider, native client traffic or path proof.
func autonomyDeviceFixture(t *testing.T, use func(*App, context.Context, autonomy.Policy, autonomy.Service, catalog.Service, *listScopePhysicalModel, *autonomyDeviceScope)) {
	t.Helper()
	a, old, model := listScopeFixture(t, "mac", false)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	service := catalog.Service{ID: "listed", Domains: []string{"example.org"}, ProbeURL: "https://example.org/"}
	a.Catalog.Services = []catalog.Service{service}
	p := autonomy.Default()
	p.Enabled, p.SetupComplete, p.Revision = true, true, 1
	spec := autonomy.Service{ID: service.ID, Enabled: true, Sources: []string{"192.168.1.40/32"}, Definition: autonomyDefinition(service)}
	a.autonomy.doc.Policy = p
	a.autonomy.doc.Services = map[string]autonomy.Service{spec.ID: spec}
	listScopeOperation(t, a, func(ctx context.Context) {
		before := a.Store.Get()
		policy := config.CloneNetworkPolicy(before.NetworkPolicy)
		policy.Revision++
		policy.Clients.DeviceIDs = []string{autonomyDeviceIncluded}
		policy.Clients.ExcludedDeviceIDs = []string{autonomyDeviceExcluded}
		consent := before.DefaultRouteConsent
		if _, err := a.Store.ApproveDefaultRouteConsent(ctx, before, policy, nil, consent.InstallationID, consent.Sequence); err != nil {
			t.Fatal(err)
		}
		model.facts.Devices[0].ID = autonomyDeviceIncluded
		model.facts.Devices = append(model.facts.Devices, physicalscope.Device{ID: autonomyDeviceExcluded, MAC: "02:00:00:00:00:02", IfIndex: 3, Interface: "br0", SegmentID: "Bridge0", Addresses: []string{"192.168.1.41", "fd00::41"}})
		control, err := a.Operations.ReviewControlEpoch(ctx, a.SelfUpdateFiles.ControlRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		owned, closeDevices, err := newAutonomyDeviceScope(ctx, a, a.Store.Get(), control.Current, model.acquire)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := closeDevices(); err != nil {
				t.Fatal(err)
			}
		}()
		d := owned.Value(autonomyDeviceScopeKey{}).(*autonomyDeviceScope)
		use(a, owned, p, spec, service, model, d)
	})
}

func TestAutonomyDeviceScopeGuardsOriginalObservedMemberAcrossOwnRouteCAS(t *testing.T) {
	autonomyDeviceFixture(t, func(a *App, ctx context.Context, p autonomy.Policy, spec autonomy.Service, service catalog.Service, model *listScopePhysicalModel, d *autonomyDeviceScope) {
		before := a.Store.Get()
		checks := model.checks
		if err := a.autonomyResourceGuard(ctx, p, spec, before, service); err != nil || model.checks < checks+2 {
			t.Fatal("actual Store leaf was not physically bookended", err, model.checks)
		}
		reviewID := d.facts.ReviewID
		undo, err := a.Store.ApplyAutonomyRouteWithRollback(spec.ID, "xray", spec.Sources, before.Revision)
		if err != nil {
			t.Fatal(err)
		}
		after := a.Store.Get()
		if err := a.autonomyResourceGuard(ctx, p, spec, after, service); err != nil || d.facts.ReviewID != reviewID || model.closes != 1 {
			t.Fatal("original physical review was replaced by own route publication", err)
		}
		if a.autonomyResourceGuard(ctx, p, spec, before, service) == nil {
			t.Fatal("physical identity waived stale full config observation")
		}
		if err := undo(); err != nil {
			t.Fatal(err)
		}
		if err := a.autonomyResourceGuard(ctx, p, spec, a.Store.Get(), service); err != nil || d.facts.ReviewID != reviewID {
			t.Fatal("original CAS undo changed physical intent or reopened review", err)
		}
	})
}

func TestAutonomyDeviceScopeRevokesPhysicalOrPolicyDriftPermanently(t *testing.T) {
	for _, mode := range []string{"physical", "same-revision-policy", "store-slot", "close", "copied", "wrong-context"} {
		t.Run(mode, func(t *testing.T) {
			autonomyDeviceFixture(t, func(a *App, ctx context.Context, p autonomy.Policy, spec autonomy.Service, service catalog.Service, model *listScopePhysicalModel, d *autonomyDeviceScope) {
				before := a.Store.Get()
				originalStore := a.Store
				var restore func()
				switch mode {
				case "physical":
					model.verifyErr = physicalscope.ErrUnknown
					restore = func() { model.verifyErr = nil }
				case "same-revision-policy":
					changed := config.CloneNetworkPolicy(before.NetworkPolicy)
					changed.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "exact", Value: "example.org"}}}
					autonomyExclusionSetup(t, a, changed)
					restore = func() { a.Store = originalStore }
				case "store-slot":
					a.Store = nil
					restore = func() { a.Store = originalStore }
				case "close":
					if err := d.Close(); err != nil {
						t.Fatal(err)
					}
				case "copied":
					copy := &autonomyDeviceScope{self: d, app: a, store: d.store}
					ctx = context.WithValue(ctx, autonomyDeviceScopeKey{}, copy)
				case "wrong-context":
					ctx = context.WithValue(context.Background(), autonomyDeviceScopeKey{}, d)
				}
				if a.autonomyResourceGuard(ctx, p, spec, before, service) == nil {
					t.Fatal("changed original owner granted a resource observation")
				}
				if restore != nil {
					restore()
					if mode == "physical" && a.autonomyResourceGuard(ctx, p, spec, before, service) == nil {
						t.Fatal("restored tuple revived an invalid physical review")
					}
				}
			})
		})
	}
}

func TestAutonomyDeviceScopeClosingDriftCannotGrantObservation(t *testing.T) {
	autonomyDeviceFixture(t, func(a *App, ctx context.Context, _ autonomy.Policy, spec autonomy.Service, _ catalog.Service, model *listScopePhysicalModel, d *autonomyDeviceScope) {
		calls := 0
		err := d.use(ctx, a.Store.Get(), spec, func(context.Context, []string) error {
			calls++
			model.verifyErr = physicalscope.ErrUnknown
			return nil
		})
		if err == nil || calls != 1 || !d.invalid {
			t.Fatal("closing physical refusal was lost", err, calls)
		}
	})
}

func TestAutonomyDeviceScopeFreshStoreModeDriftCannotBypassOriginalCarrier(t *testing.T) {
	for _, mode := range []string{"lan_except", "nil"} {
		t.Run(mode, func(t *testing.T) {
			autonomyDeviceFixture(t, func(a *App, ctx context.Context, p autonomy.Policy, spec autonomy.Service, service catalog.Service, _ *listScopePhysicalModel, d *autonomyDeviceScope) {
				originalStore := a.Store
				before := a.Store.Get()
				// Exercise the actual same Store and its file CAS. This explicit
				// restore image models concurrent local intent publication only;
				// it issues no runtime or physical permission.
				publish := func(cfg config.Config) {
					t.Helper()
					session, err := a.Store.BeginRestore(ctx)
					if err != nil {
						t.Fatal(err)
					}
					image, err := session.Read(ctx)
					if err != nil {
						_ = session.Close()
						t.Fatal(err)
					}
					next := image
					next.Data, err = json.Marshal(cfg)
					if err == nil {
						err = session.CompareAndSwap(ctx, image, next)
					}
					if err = errors.Join(err, session.Close()); err != nil {
						t.Fatal(err)
					}
				}
				changed := a.Store.Get()
				changed.NetworkPolicy = config.CloneNetworkPolicy(changed.NetworkPolicy)
				if mode == "nil" {
					changed.NetworkPolicy = nil
				} else {
					changed.NetworkPolicy.Clients.Mode = mode
					changed.NetworkPolicy.Clients.NewDevices = "inherit"
					changed.NetworkPolicy.Clients.DeviceIDs = nil
					changed.NetworkPolicy.Clients.ExcludedDeviceIDs = nil
				}
				publish(changed)
				fresh := a.Store.Get()
				if a.Store != originalStore {
					t.Fatal("mode drift replaced the original Store")
				}
				if err := a.autonomyResourceGuard(ctx, p, spec, fresh, service); err == nil || !d.invalid {
					t.Fatal("fresh nonselected Store image bypassed original carrier", err)
				}
				publish(before)
				if err := a.autonomyResourceGuard(ctx, p, spec, a.Store.Get(), service); err == nil {
					t.Fatal("restoring original intent revived refused carrier")
				}
			})
		})
	}
}

func TestAutonomyDeviceScopeCloseJoinsOriginalReadAndCannotRevive(t *testing.T) {
	autonomyDeviceFixture(t, func(a *App, ctx context.Context, _ autonomy.Policy, spec autonomy.Service, _ catalog.Service, _ *listScopePhysicalModel, d *autonomyDeviceScope) {
		entered, proceed := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- d.use(ctx, a.Store.Get(), spec, func(context.Context, []string) error {
				close(entered)
				<-proceed
				return nil
			})
		}()
		<-entered
		closed := make(chan error, 1)
		go func() { closed <- d.Close() }()
		select {
		case <-closed:
			t.Fatal("Close released original review before its actual read joined")
		case <-time.After(20 * time.Millisecond):
		}
		close(proceed)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if err := d.use(ctx, a.Store.Get(), spec, func(context.Context, []string) error { t.Fatal("closed review used"); return nil }); err == nil {
			t.Fatal("closed scope revived")
		}
	})
}

func TestAutonomyDeviceScopeUsesActualBindingsAndKeepsEveryNegative(t *testing.T) {
	autonomyDeviceFixture(t, func(a *App, ctx context.Context, _ autonomy.Policy, spec autonomy.Service, service catalog.Service, _ *listScopePhysicalModel, d *autonomyDeviceScope) {
		cfg := a.Store.Get()
		set, err := config.EffectiveConfigResourceExclusions(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := autonomyPhysicalDeviceMembers(d.facts, spec, set.Clients)
		if err != nil || !reflect.DeepEqual(ids, []string{autonomyDeviceIncluded}) {
			t.Fatal("source did not resolve through the observed binding", ids, err)
		}
		for _, raw := range []string{"192.168.1.41/32", "192.168.1.0/24", "192.168.1.99/32"} {
			other := spec
			other.Sources = []string{raw}
			if _, err := autonomyPhysicalDeviceMembers(d.facts, other, set.Clients); err == nil {
				t.Fatal("excluded, broad or unobserved source became a device identity", raw)
			}
		}
		for _, mode := range []string{"manual", "russian", "auxiliary", "conditional-device", "narrow-IP", "client-prefix"} {
			t.Run(mode, func(t *testing.T) {
				negative := set
				currentService := service
				switch mode {
				case "manual":
					negative.Manual = []config.ResourceMatch{{Kind: "service", Value: service.ID}}
				case "russian":
					negative.Russian = []config.ResourceMatch{{Kind: "suffix", Value: "example.org"}}
				case "auxiliary":
					negative.Manual = []config.ResourceMatch{{Kind: "exact", Value: "api.ipify.org"}}
				case "conditional-device":
					negative.LegacyRules = []config.NetworkRule{{ID: "negative", Kind: "service", Value: service.ID, Action: "direct", DeviceIDs: ids}}
				case "narrow-IP":
					currentService.CIDRs = []string{"93.184.216.0/24"}
					negative.LegacyRules = []config.NetworkRule{{ID: "negative", Kind: "ip", Value: "93.184.216.99", Action: "direct", DeviceIDs: ids}}
				case "client-prefix":
					negative.Clients.ExcludedCIDRs = []string{"192.168.1.0/24"}
				}
				if err := autonomyResourceEligibilityForDevices(ctx, cfg, spec, currentService, negative, ids); !errors.Is(err, errAutonomyResourceIneligible) {
					t.Fatal("an explicit negative was waived by device identity", err)
				}
			})
		}
		set.LegacyRules = []config.NetworkRule{{ID: "different-device", Kind: "service", Value: service.ID, Action: "direct", DeviceIDs: []string{autonomyDeviceExcluded}}}
		if err := autonomyResourceEligibilityForDevices(ctx, cfg, spec, service, set, ids); err != nil {
			t.Fatal("unrelated negative device replaced the observed positive identity", err)
		}
		set.LegacyRules = []config.NetworkRule{{ID: "different-IP", Kind: "cidr", Value: "93.184.216.0/24", Action: "direct", DeviceIDs: []string{autonomyDeviceExcluded}}}
		service.CIDRs = []string{"93.184.216.0/24"}
		if err := autonomyResourceEligibilityForDevices(ctx, cfg, spec, service, set, ids); err != nil {
			t.Fatal("unrelated conditional prefix excluded the observed selected member", err)
		}
		if _, err := autonomyPhysicalDeviceMembers(d.facts, autonomy.Service{AllLAN: true}, set.Clients); err == nil {
			t.Fatal("selected device witness authorized whole LAN")
		}
	})
}

func TestAutonomyDeviceProductionContextRefusesMissingStartupOwner(t *testing.T) {
	a, _, _ := listScopeFixture(t, "mac", false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if owned, close, err := a.autonomyDeviceContext(ctx, a.Store.Get()); err == nil || owned != nil || close != nil {
		t.Fatal("approved DTO replaced the actual startup registration")
	}
	// Intent-only values and a copied scope do not construct a production owner.
	copy := &autonomyDeviceScope{policy: &config.NetworkPolicy{}, consent: &config.DefaultRouteConsent{Digest: strings.Repeat("a", 64)}}
	if copy.Close() == nil {
		t.Fatal("copied scope closed as an original")
	}
}

func TestAutonomyDeviceOriginalRoundCannotBeRevivedByAnotherOperation(t *testing.T) {
	for _, mode := range []string{"released", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			a, old, model := listScopeFixture(t, "mac", false)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			window, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			original, release, err := a.Operations.ExclusiveContext(window)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			control, err := a.Operations.ReviewControlEpoch(original, a.SelfUpdateFiles.ControlRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			owned, closeDevices, err := newAutonomyDeviceScope(original, a, a.Store.Get(), control.Current, model.acquire)
			if err != nil {
				t.Fatal(err)
			}
			defer closeDevices()
			d := owned.Value(autonomyDeviceScopeKey{}).(*autonomyDeviceScope)
			if mode == "released" {
				release()
			} else {
				cancel()
			}
			var attempted context.Context
			if mode == "released" {
				fresh, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				attempted, release, err = a.Operations.ExclusiveContext(fresh)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			} else {
				attempted, cancel = context.WithTimeout(context.WithoutCancel(owned), time.Second)
				defer cancel()
			}
			attempted = context.WithValue(attempted, autonomyDeviceScopeKey{}, d)
			called := false
			err = d.use(attempted, a.Store.Get(), autonomy.Service{Sources: []string{"192.168.1.40/32"}}, func(context.Context, []string) error { called = true; return nil })
			if err == nil || called || !d.invalid {
				t.Fatal("another operation or WithoutCancel renewed the original round", err)
			}
			if mode == "released" && !errors.Is(err, operationgate.ErrBusy) {
				t.Fatal("original released operation was not checked", err)
			}
		})
	}
}
