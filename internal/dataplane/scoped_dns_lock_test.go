package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

type scopedDNSLockRunner struct {
	attempts int
	failures int
	message  string
}

func (f *scopedDNSLockRunner) Run(ctx context.Context, _ string, _ ...string) ([]byte, error) {
	f.attempts++
	if f.attempts <= f.failures {
		return []byte(f.message), errors.New("exit status 4")
	}
	return nil, ctx.Err()
}
func TestScopedDNSFirewallRetriesOnlyExplicitLockRefusal(t *testing.T) {
	for _, mode := range []string{"busy", "ambiguous", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := &scopedDNSLockRunner{failures: 2, message: "Another app is currently holding the xtables lock."}
			if mode == "ambiguous" {
				f.message = "unexpected error after write"
			}
			ctx := context.Background()
			if mode == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}
			a := &ScopedDNSAdapter{Runner: f, IPTables: "iptables"}
			_, err := a.firewall(ctx, "-I", "PREROUTING")
			if mode == "busy" {
				if err != nil || f.attempts != 3 {
					t.Fatal("lock refusal was not retried", err, f.attempts)
				}
			} else if err == nil || f.attempts != 1 {
				t.Fatal("uncertain mutation or canceled call retried", err, f.attempts)
			}
		})
	}
}
