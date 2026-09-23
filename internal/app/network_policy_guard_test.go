package app

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestNetworkPolicyCannotFallThroughLegacyExecutor(t *testing.T) {
	for _, applied := range []bool{false, true} {
		cfg := config.Default()
		if applied {
			cfg.AppliedNetworkPolicy = &config.NetworkPolicy{Schema: 1}
		} else {
			cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 1}
		}
		for _, scope := range []changeScope{changeScopeAll, changeScopeServices, changeScopeDevices, changeScopeEngine} {
			// No detector, manager or catalog is available: refusal must precede reads
			// and must not silently drop a preserved policy during partial Apply.
			_, err := (&App{}).buildDataplanePlanForScope(cfg, nil, scope, "nfqws2")
			if err == nil || !strings.Contains(err.Error(), "NETWORK_POLICY_EXECUTOR_REQUIRED") {
				t.Fatalf("applied=%v scope=%v err=%v", applied, scope, err)
			}
		}
	}
}
