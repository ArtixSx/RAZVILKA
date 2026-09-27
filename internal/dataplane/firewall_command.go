package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"
)

func isIPTablesCommand(binary string) bool {
	switch filepath.Base(binary) {
	case "iptables", "ip6tables", "iptables-legacy", "ip6tables-legacy", "iptables-nft", "ip6tables-nft":
		return true
	}
	return false
}

// Older Entware iptables does not have a portable timed -w option. Retry
// ONLY its explicit lock refusal before mutation, within one shared deadline.
// An exit code alone, partial output or an ambiguous write failure is not retryable.
func runFirewallCommand(ctx context.Context, runner NFQWS2Runner, binary string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for attempt := 0; ; attempt++ {
		data, err := runner.Run(bounded, binary, args...)
		// Preserve an acknowledged write if cancellation races with its return.
		// The owner must record the new rule before its later cancellation check,
		// otherwise cleanup could mistake a created chain for an absent one.
		if err == nil {
			return data, nil
		}
		busy := strings.HasPrefix(strings.TrimSpace(string(data)), "Another app is currently holding the xtables lock.")
		if attempt >= 7 || !busy {
			if err != nil && busy {
				err = errors.Join(errors.New("firewall lock remained busy"), err)
			}
			return data, errors.Join(err, bounded.Err())
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 50 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
			return nil, bounded.Err()
		case <-timer.C:
		}
	}
}
