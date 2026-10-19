package app

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func TestNetworkPolicyCannotFallThroughLegacyExecutor(t *testing.T) {
	for _, kind := range []string{"desired", "applied", "inactive"} {
		cfg := config.Default()
		if kind == "inactive" {
			cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "service", Value: "video"}}}
		} else if kind == "applied" {
			cfg.AppliedNetworkPolicy = &config.NetworkPolicy{Schema: 1}
		} else {
			cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 1}
		}
		for _, scope := range []changeScope{changeScopeAll, changeScopeServices, changeScopeDevices, changeScopeEngine} {
			// No detector, manager or catalog is available: refusal must precede reads
			// and must not silently drop a preserved policy during partial Apply.
			_, err := (&App{}).buildDataplanePlanForScope(cfg, nil, scope, "nfqws2")
			if err == nil || !strings.Contains(err.Error(), "NETWORK_POLICY_EXECUTOR_REQUIRED") {
				t.Fatalf("kind=%v scope=%v err=%v", kind, scope, err)
			}
		}
	}
}

// An earlier release kept an emptied "sites without bypass" document. It has
// no negative to honour, so it must not close legacy Apply for good.
func TestEmptyInactiveExclusionsDoNotCloseLegacyExecutor(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services["telegram"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}}}}}
	options := []routecatalog.Option{{ID: "nfqws2", Installed: true, Selectable: true}}
	for _, doc := range []*config.ResourceExclusions{
		{Schema: 1, Revision: 3, Manual: []config.ResourceMatch{}},
		{Schema: 1, Revision: 3},
	} {
		cfg.InactiveResourceExclusions = doc
		if _, err := a.buildDataplanePlanForScope(cfg, options, changeScopeServices, ""); err != nil && strings.Contains(err.Error(), "NETWORK_POLICY_EXECUTOR_REQUIRED") {
			t.Fatalf("empty inactive document closed legacy Apply: %v", err)
		}
	}
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 3, Manual: []config.ResourceMatch{{Kind: "suffix", Value: "example.com"}}}
	if _, err := a.buildDataplanePlanForScope(cfg, options, changeScopeServices, ""); err == nil || !strings.Contains(err.Error(), "NETWORK_POLICY_EXECUTOR_REQUIRED") {
		t.Fatalf("stored negative was ignored by legacy Apply: %v", err)
	}
}
