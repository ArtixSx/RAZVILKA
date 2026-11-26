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
// ONLY its explicit lock refusal before mutation, within a three-second window.
// An exit code alone, partial output or an ambiguous write failure is not retryable.
func runFirewallCommand(ctx context.Context, runner NFQWS2Runner, binary string, args ...string) ([]byte, error) {
	// Do not confuse the lock retry budget with the command deadline. Reading
	// a large firmware ruleset can take longer than three seconds under load.
	// The caller's shorter deadline always wins; the first command remains bounded.
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	retry, cancelRetry := context.WithTimeout(bounded, 3*time.Second)
	defer cancelRetry()
	for attempt := 0; ; attempt++ {
		attemptContext := bounded
		if attempt > 0 {
			attemptContext = retry
		}
		data, err := runner.Run(attemptContext, binary, args...)
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
			return data, errors.Join(err, attemptContext.Err())
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 50 * time.Millisecond)
		select {
		case <-retry.Done():
			timer.Stop()
			return nil, retry.Err()
		case <-timer.C:
		}
	}
}
