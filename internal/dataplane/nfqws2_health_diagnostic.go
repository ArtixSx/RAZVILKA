package dataplane

import (
	"fmt"
	"strings"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// Failure-only diagnostics reuse the captured Health observations. No command,
// raw config, inventory row or underlying error text escapes this vocabulary.
func nfqws2HealthRulesDiagnostic(data []byte, inventoryErr error, config []byte, configExists bool, configErr error, running []byte, runningExists bool, runningErr error, lease *nfqws2Lease) error {
	reason := nfqws2HealthRulesReason(data, inventoryErr, config, configExists, configErr, running, runningExists, runningErr, lease)
	return fmt.Errorf("active NFQWS2 NFQUEUE rules were not confirmed: %s", reason)
}

func nfqws2HealthRulesReason(data []byte, inventoryErr error, config []byte, configExists bool, configErr error, running []byte, runningExists bool, runningErr error, lease *nfqws2Lease) string {
	if inventoryErr != nil {
		return "inventory-command-failed"
	}
	if configErr != nil {
		return "config-read-failed"
	}
	if !configExists {
		return "config-missing"
	}
	if runningErr != nil {
		return "run-read-failed"
	}
	if !runningExists {
		return "run-missing"
	}
	if lease != nil && nfqws2Hash(config) != lease.ConfigHash {
		return "lease-config-hash-drift"
	}
	if _, ok := nfqws2LiteralQueue(config); !ok {
		return "main-scope-mismatch"
	}
	image, ok := nfqws2SaveMangleImage(data)
	if !ok {
		return "inventory-parse-failed"
	}
	closed := lease != nil && lease.FirstStart != nil
	effective := config
	if closed {
		text, err := engineconfig.NFQWSFirstStartEffectiveConfig(config, lease.Owner)
		if err != nil {
			return "main-scope-mismatch"
		}
		if engineconfig.NFQWSFirstStartRunningAllLAN(config, lease.Owner, running) != nil {
			return "main-run-scope-mismatch"
		}
		effective = []byte(text)
	}
	if _, ok := nfqws2StockHookScopeOf(effective, running); !ok {
		return "main-run-scope-mismatch"
	}
	if nfqws2PostroutingReaches(image, false) != nil {
		return "post-hook-unreachable"
	}
	if !nfqws2ExpertReachableQueueRule(data, effective, running) {
		return "post-body-mismatch"
	}
	if closed {
		if nfqws2PreroutingReaches(image, false) != nil {
			return "pre-hook-unreachable"
		}
		graph, err := nfqws2FirstStartHookGraph(config, running, lease.Owner)
		if err != nil || len(graph.Families) == 0 {
			return "main-run-scope-mismatch"
		}
		var actual []string
		for _, rule := range image.rules[nfqws2HookPreChain] {
			actual = append(actual, strings.Join(rule, " "))
		}
		if !nfqws2HealthRulesMatch(actual, graph.Families[0].bodyText(nfqws2HookPreChain)) {
			return "pre-body-mismatch"
		}
	}
	// This routine is called only after the unchanged acceptance predicate failed.
	return "rules-unconfirmed"
}
