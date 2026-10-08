package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/sources"
)

// Uses the original Store/disk/control/scope from listScopeFixture. Its physics
// and WAN remain explicitly private models; no native DNS/path PASS is claimed.
func listDNSResourcesFixture(t *testing.T) (*App, *ListScopeBinding, *ListDNSResourceBinding) {
	t.Helper()
	a, scope, _ := listScopeFixture(t, "mac", false)
	a.Catalog.Services = []catalog.Service{
		{ID: "listed", Name: "Listed", Category: "test", Domains: []string{"example.org"}, Strategy: []string{"direct"}},
		{ID: "disabled", Name: "Disabled", Category: "test", Domains: []string{"discordsays.com", "xn--e1afmkfd.xn--p1ai"}, Strategy: []string{"direct"}},
		{ID: "overlap", Name: "Overlap", Category: "test", Domains: []string{"discordsays.com"}, Strategy: []string{"direct"}},
	}
	var binding *ListDNSResourceBinding
	listScopeOperation(t, a, func(ctx context.Context) {
		var err error
		binding, err = NewListDNSResourceBinding(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
	})
	return a, scope, binding
}

func TestListDNSResourcesActualCatalogIncludesDisabledAndLabelBoundaries(t *testing.T) {
	a, _, b := listDNSResourcesFixture(t)
	if a.Store.Get().Services["disabled"].Enabled || b.Exclusions() == nil || len(a.Store.Get().DefaultRouteConsent.Grants) != 0 {
		t.Fatal("negative participant created a positive grant")
	}
	listScopeOperation(t, a, func(ctx context.Context) {
		for name, want := range map[string][]string{
			"DISCORDSAYS.COM.":          {"disabled", "overlap"},
			"a.discordsays.com":         {"disabled", "overlap"},
			"notdiscordsays.com":        nil,
			"discordsays.com.other.org": nil,
			"ПРИМЕР.РФ.":                {"disabled"},
			"a.xn--e1afmkfd.xn--p1ai":   {"disabled"},
			"unknown.org":               nil,
		} {
			ids, err := b.serviceIdentities(ctx, name)
			if err != nil || !reflect.DeepEqual(ids, want) {
				t.Fatal(name, ids, want, err)
			}
			if len(ids) > 0 {
				ids[0] = "caller-mutated"
			}
		}
		if _, err := b.serviceIdentities(ctx, "https://discordsays.com"); err == nil {
			t.Fatal("malformed observed identity accepted")
		}
		ids, err := b.serviceIdentities(ctx, "discordsays.com")
		if err != nil || !reflect.DeepEqual(ids, []string{"disabled", "overlap"}) {
			t.Fatal("caller changed retained catalog", ids, err)
		}
	})
	copy := &ListDNSResourceBinding{self: b, scope: b.scope, expected: b.expected, catalog: b.catalog, identities: b.identities, exclusions: b.exclusions}
	if copy.Exclusions() != nil || copy.Guard(context.Background()) == nil {
		t.Fatal("detached binding reconstructed participant")
	}
}

func TestListDNSResourcesRequiresFreshSameFiniteOperation(t *testing.T) {
	a, _, b := listDNSResourcesFixture(t)
	if b.Guard(context.Background()) == nil {
		t.Fatal("listener lifetime context accepted")
	}
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	foreign, release, err := (&operationgate.Gate{}).ExclusiveContext(bounded)
	if err != nil {
		t.Fatal(err)
	}
	if b.Guard(foreign) == nil {
		t.Fatal("foreign operation accepted")
	}
	release()
	var old context.Context
	listScopeOperation(t, a, func(ctx context.Context) {
		old = ctx
		if err := b.Guard(ctx); err != nil {
			t.Fatal(err)
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if err := b.Guard(cancelled); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	if b.Guard(old) == nil {
		t.Fatal("released operation accepted")
	}
	listScopeOperation(t, a, func(ctx context.Context) {
		if err := b.Guard(ctx); err != nil {
			t.Fatal("invalid caller/cancellation poisoned current resources", err)
		}
	})
}

func TestListDNSResourcesObservedDriftCannotRevive(t *testing.T) {
	for _, kind := range []string{"catalog", "custom-owner", "source-owner", "store-slot", "disk", "closed-scope"} {
		t.Run(kind, func(t *testing.T) {
			a, scope, b := listDNSResourcesFixture(t)
			listScopeOperation(t, a, func(ctx context.Context) {
				var restore func()
				switch kind {
				case "catalog":
					old := a.Catalog.Services[1].Domains
					a.Catalog.Services[1].Domains = []string{"changed.org"}
					restore = func() { a.Catalog.Services[1].Domains = old }
				case "custom-owner":
					m, err := customservices.Load(filepath.Join(t.TempDir(), "custom.json"))
					if err != nil {
						t.Fatal(err)
					}
					a.CustomServices = m
					restore = func() { a.CustomServices = nil }
				case "source-owner":
					a.Sources = sources.NewManager(sources.Registry{}, t.TempDir())
					restore = func() { a.Sources = nil }
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
					if err != nil || os.WriteFile(path, data, 0600) != nil {
						t.Fatal("could not change actual disk", err)
					}
					restore = func() {
						if err := os.WriteFile(path, old, 0600); err != nil {
							t.Fatal(err)
						}
					}
				case "closed-scope":
					_ = scope.Close()
					restore = func() {}
				}
				if err := b.Guard(ctx); !errors.Is(err, ErrListDNSResourcesChanged) {
					t.Fatal("changed resources remained current", err)
				}
				restore()
				if b.Guard(ctx) == nil || b.Exclusions() != nil {
					t.Fatal("restoration revived old participant")
				}
			})
		})
	}
}

func TestListDNSResourcesSanctionedCASRequiresNewParticipant(t *testing.T) {
	a, scope, old := listDNSResourcesFixture(t)
	participant := old.Exclusions()
	listScopeOperation(t, a, func(ctx context.Context) {
		before := a.Store.Get()
		started := time.Now()
		_, err := a.Store.CommitNetworkPolicyWithRollback(before, before.NetworkPolicy, before.Services)
		finished := time.Now()
		if err != nil {
			t.Fatal(err)
		}
		if err := scope.AcceptCommitted(ctx, a.Store.Get(), started, finished); err != nil {
			t.Fatal(err)
		}
		if old.Guard(ctx) == nil || old.Exclusions() != nil {
			t.Fatal("old resource participant adopted scope CAS")
		}
		fresh, err := NewListDNSResourceBinding(ctx, scope)
		if err != nil || fresh.Exclusions() == participant || fresh.Exclusions().Stamp().ConfigRevision != a.Store.Get().Revision {
			t.Fatal("new actual postimage participant unavailable", err)
		}
		if err := fresh.Guard(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestListDNSResourcesActualCustomDefinitionsParticipate(t *testing.T) {
	a, scope, _ := listDNSResourcesFixture(t)
	m, err := customservices.Load(filepath.Join(t.TempDir(), "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := m.Create(catalog.Service{ID: "custom-site", Name: "Custom", Category: "test", Domains: []string{"custom.example.org"}, Strategy: []string{"direct"}}, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	a.CustomServices = m
	listScopeOperation(t, a, func(ctx context.Context) {
		b, err := NewListDNSResourceBinding(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := b.serviceIdentities(ctx, "sub.custom.example.org")
		if err != nil || !reflect.DeepEqual(ids, []string{service.ID, "listed"}) || a.Store.Get().Services[service.ID].Enabled {
			t.Fatal("actual disabled custom definition missing", ids, err)
		}
	})
}

func TestListDNSResourcesDisabledServiceExclusionUsesActualStore(t *testing.T) {
	a, prior, model := listScopeFixture(t, "mac", false)
	a.Catalog.Services = []catalog.Service{{ID: "disabled", Name: "Disabled", Category: "test", Domains: []string{"discordsays.com"}, Strategy: []string{"direct"}}}
	_ = prior.Close()
	listScopeOperation(t, a, func(ctx context.Context) {
		epoch, err := a.Operations.ReviewControlEpoch(ctx, a.SelfUpdateFiles.ControlRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer epoch.Close()
		manual := []config.ResourceMatch{{Kind: "service", Value: "disabled"}}
		before, err := a.Store.UpdateResourceExclusions(ctx, a.Store.Get(), &manual, nil)
		if err != nil {
			t.Fatal(err)
		}
		policy := config.CloneNetworkPolicy(before.NetworkPolicy)
		policy.Revision++
		ref := epoch.Reference()
		if _, err := a.Store.ApproveDefaultRouteConsent(ctx, before, policy, nil, ref.InstallationID, ref.Sequence); err != nil {
			t.Fatal(err)
		}
		scope, err := newListScopeBinding(ctx, a, model.acquire)
		if err != nil {
			t.Fatal(err)
		}
		defer scope.Close()
		resources, err := NewListDNSResourceBinding(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := resources.serviceIdentities(ctx, "sub.discordsays.com")
		if err != nil || !reflect.DeepEqual(ids, []string{"disabled"}) {
			t.Fatal(ids, err)
		}
		if err := a.Store.WithResourceExclusionObservation(ctx, a.Store.Get(), func(set config.EffectiveExclusionSet) error {
			excluded, err := set.Matches(config.ResourceTarget{Domain: "sub.discordsays.com", ServiceID: ids[0]})
			if err != nil || !excluded {
				t.Fatal("disabled service negative did not win", excluded, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestListDNSResourcesMissingAppliedSourceCannotBecomeCatalogMiss(t *testing.T) {
	a, scope, _ := listDNSResourcesFixture(t)
	a.Sources = sources.NewManager(sources.Registry{Schema: 2, Sources: []sources.Source{{
		ID: "disabled-domains", Name: "Disabled service definitions", Kind: "domains", Format: "lines", URL: "https://example.org/domains", Enabled: true, Services: []string{"disabled"},
	}}}, t.TempDir())
	listScopeOperation(t, a, func(ctx context.Context) {
		if _, err := NewListDNSResourceBinding(ctx, scope); !errors.Is(err, ErrListDNSResourcesChanged) {
			t.Fatal("unknown applied source silently disappeared from negative catalog", err)
		}
	})
}

func TestListDNSResourcesMissingOrMalformedCatalogRefuses(t *testing.T) {
	for _, kind := range []string{"missing", "duplicate", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			a, scope, _ := listDNSResourcesFixture(t)
			switch kind {
			case "missing":
				a.Catalog.Services = nil
			case "duplicate":
				a.Catalog.Services = append(a.Catalog.Services, a.Catalog.Services[0])
			case "malformed":
				a.Catalog.Services[1].Domains = []string{"https://invalid.org"}
			}
			listScopeOperation(t, a, func(ctx context.Context) {
				if _, err := NewListDNSResourceBinding(ctx, scope); !errors.Is(err, ErrListDNSResourcesChanged) {
					t.Fatal("incomplete catalog supplied negative identities", kind, err)
				}
			})
		})
	}
}
