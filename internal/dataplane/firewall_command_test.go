package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFirewallSlowFirstCommandKeepsItsOwnBudget(t *testing.T) {
	for _, operation := range []string{"-S", "-A"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			runner := nfqws2RunFunc(func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
				calls++
				timer := time.NewTimer(3100 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-timer.C:
					return []byte("acknowledged"), nil
				}
			})
			data, err := runFirewallCommand(context.Background(), runner, "iptables", "-t", "filter", operation)
			if err != nil || string(data) != "acknowledged" || calls != 1 {
				t.Fatal("lock retry budget killed or repeated an ordinary command", err, calls)
			}
		})
	}
}

func TestFirewallFirstDeadlineAndRetryBudgetAreIndependent(t *testing.T) {
	for _, mode := range []string{"cancel-first", "ambiguous", "lock-retry"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			runner := nfqws2RunFunc(func(command context.Context, _ string, _ ...string) ([]byte, error) {
				calls++
				if mode == "ambiguous" {
					return []byte("partial write"), errors.New("exit status 4")
				}
				if mode == "lock-retry" && calls == 1 {
					return []byte("Another app is currently holding the xtables lock."), errors.New("exit status 4")
				}
				<-command.Done()
				return nil, command.Err()
			})
			_, err := runFirewallCommand(ctx, runner, "iptables", "-A", "RZ_OWN")
			want := 1
			if mode == "lock-retry" {
				want = 2
			}
			if err == nil || calls != want {
				t.Fatal("unsafe retry or ignored caller budget", err, calls)
			}
			if mode != "ambiguous" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyFirewallRetriesOnlyLockRefusal(t *testing.T) {
	for _, mode := range []string{"read", "write", "ambiguous", "partial-output", "other-command", "canceled", "exhausted"} {
		t.Run(mode, func(t *testing.T) {
			r := &scopedDNSLockRunner{failures: 2, message: "Another app is currently holding the xtables lock. Perhaps you want to use the -w option?"}
			binary, args := "/opt/sbin/iptables", []string{"-t", "nat", "-S"}
			if mode == "write" {
				args = []string{"-t", "nat", "-A", "RZ_OWN", "-j", "ACCEPT"}
			}
			if mode == "ambiguous" {
				r.message = "Resource problem after write"
			}
			if mode == "partial-output" {
				r.message = "rule added\n" + r.message
			}
			if mode == "other-command" {
				binary = "ip"
			}
			if mode == "exhausted" {
				r.failures = 100
			}
			ctx := context.Background()
			if mode == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}
			a := &ProxyTunnelAdapter{Runner: r}
			_, err := a.run(ctx, binary, args...)
			switch mode {
			case "read", "write":
				if err != nil || r.attempts != 3 {
					t.Fatal(err, r.attempts)
				}
			case "exhausted":
				if err == nil || r.attempts != 8 {
					t.Fatal(err, r.attempts)
				}
			case "canceled":
				if !errors.Is(err, context.DeadlineExceeded) || r.attempts != 1 {
					t.Fatal(err, r.attempts)
				}
			default:
				if err == nil || r.attempts != 1 {
					t.Fatal("unsafe retry", err, r.attempts)
				}
			}
		})
	}
}
