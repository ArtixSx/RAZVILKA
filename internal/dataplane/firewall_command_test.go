package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

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
