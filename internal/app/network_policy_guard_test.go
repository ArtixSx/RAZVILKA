package app

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
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
