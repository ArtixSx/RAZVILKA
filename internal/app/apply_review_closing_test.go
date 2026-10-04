package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func TestApplyReviewRejectsSourceChangeDuringFinalWANRead(t *testing.T) {
	for _, change := range []string{"config", "catalog", "draft-content", "draft-discard", "dns-selection", "node-generation", "cancel-nil", "none"} {
		t.Run(change, func(t *testing.T) {
			a, target, options := usquePlanFixture(t, "usque")
			scope := changeScopeServices
			node := ""
			if strings.HasPrefix(change, "draft-") {
				if _, err := a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"info"}}`); err != nil {
					t.Fatal(err)
				}
				scope = changeScopeAll
				options = append(options, routecatalog.Option{ID: "sing-box", Installed: true, Selectable: true})
			} else if change == "dns-selection" {
				a = dnsRuntimeFixture(t)
				target, options = a.Store.Get(), nil
			} else if change == "node-generation" {
				a, node, _ = nodeApplyFixture(t)
				target = nodeRouteConfigForScope(a.Store.Get(), "telegram", node, []string{"192.168.1.2/32"})
				options, scope = a.nodeRouteOptions(), changeScopeNode
			}
			a.FreshProfile = stableNodeProfile
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), usquePlanContextKey{}, "closing-sources"), time.Minute)
			defer cancel()
			plan, err := a.buildDataplanePlanForScopeContext(ctx, target, options, scope, "")
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(change, "draft-") && !slices.Contains(plan.EngineDrafts, "sing-box/main") {
				t.Fatal("fixture did not review the changed draft")
			}
			before := a.Store.Get()
			binding, err := a.bindApplyReview(ctx, before, plan, scope, "")
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			a.FreshProfile = func(c context.Context) (string, error) {
				calls++
				if c != ctx || calls != 1 {
					t.Fatal("guard escaped context or recursively reread WAN")
				}
				var mutationErr error
				switch change {
				case "config":
					mutationErr = a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct"})
				case "catalog":
					a.Catalog.Services[0].Domains = []string{"changed.example"}
				case "draft-content":
					_, mutationErr = a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"debug"}}`)
				case "draft-discard":
					mutationErr = a.EngineConfigs.Discard("sing-box", "main")
				case "dns-selection":
					mutationErr = a.DNS.SetServiceDraft("telegram", "unfiltered")
				case "node-generation":
					_, mutationErr = a.Nodes.SetAlias(c, node, "Changed while reading WAN", time.Now())
				case "cancel-nil":
					cancel()
				}
				if mutationErr != nil {
					t.Fatal(mutationErr)
				}
				return "wan-0123456789ab", nil
			}
			err = binding.guard(a, ctx)
			wanted := dataplane.ErrReviewChanged
			if change == "cancel-nil" {
				wanted = context.Canceled
			}
			if change == "none" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, wanted) {
				t.Fatal("matching WAN authorized changed reviewed source", err)
			}
			after := a.Store.Get()
			if calls != 1 || len(binding.committedAdapters) != 0 || after.AppliedRevision != before.AppliedRevision || !reflect.DeepEqual(after.AppliedServices, before.AppliedServices) {
				t.Fatal("closing refusal changed working intent or commit bookkeeping")
			}
		})
	}
}

func TestApplyReviewBlockedWANReadCannotAuthorizeChangedDraft(t *testing.T) {
	a, cfg, options := usquePlanFixture(t, "usque")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a.FreshProfile = stableNodeProfile
	plan, err := a.buildDataplanePlanForScopeContext(ctx, cfg, options, changeScopeServices, "")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := a.bindApplyReview(ctx, cfg, plan, changeScopeServices, "")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	a.FreshProfile = func(c context.Context) (string, error) {
		if c != ctx {
			return "", context.Canceled
		}
		close(entered)
		select {
		case <-release:
			return "wan-0123456789ab", nil
		case <-c.Done():
			return "", c.Err()
		}
	}
	done := make(chan error, 1)
	go func() { done <- binding.guard(a, ctx) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("guard did not reach WAN read")
	}
	err = a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct"})
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, dataplane.ErrReviewChanged) || len(binding.committedAdapters) != 0 {
			t.Fatal("blocked WAN read hid a concurrent draft change", err)
		}
	case <-ctx.Done():
		t.Fatal("guard did not finish after WAN read")
	}
}
