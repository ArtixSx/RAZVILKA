package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestExactNodeCleanupStatusComesFromOriginalCleanup(t *testing.T) {
	for _, fault := range []string{"transport", "prepare", "egress", "cleanup", "cancel", "resource"} {
		t.Run(fault, func(t *testing.T) {
			c := fakeExactNodeChecker(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			blocked := false
			c.cleanup = func(clean context.Context, _ exactNodeSession) error {
				calls++
				if clean.Err() != nil {
					t.Error("parent cancellation poisoned independent cleanup")
				}
				if _, finite := clean.Deadline(); !finite {
					t.Error("cleanup lost bound")
				}
				if fault == "cleanup" {
					return errors.New("private runtime still present")
				}
				return nil
			}
			switch fault {
			case "transport":
				c.dialTransport = func(context.Context, exactNodeEndpoint, []netip.Addr) (bool, error) { return false, nil }
			case "prepare":
				c.prepare = func(context.Context, exactNodeSession, NodeCheckRequest, exactNodeEndpoint) (exactNodeSession, error) {
					return exactNodeSession{}, errors.New("partial private config")
				}
			case "egress":
				c.proxyEgress = func(context.Context, string) (string, error) { return "", nodeEgressFailure("tls_timeout") }
			case "cancel":
				c.proxyEgress = func(context.Context, string) (string, error) { cancel(); return "", context.Canceled }
			case "resource":
				ctx = WithNodeResourceGuard(ctx, func(context.Context, string, netip.Addr) error {
					if blocked {
						return ErrNodeResourceDenied
					}
					return nil
				})
				original := c.prepare
				c.prepare = func(x context.Context, s exactNodeSession, r NodeCheckRequest, e exactNodeEndpoint) (exactNodeSession, error) {
					s, err := original(x, s, r, e)
					blocked = true
					return s, err
				}
			}
			result, err := c.Check(ctx, checkedNodeRequest())
			want := NodeCleanupVerified
			if fault == "transport" {
				want = NodeCleanupNotRequired
				if calls != 0 {
					t.Fatal("screen created cleanup work")
				}
			} else if calls != 1 {
				t.Fatal("original cleanup not joined once", calls)
			}
			if fault == "cleanup" {
				want = NodeCleanupFailed
				if !c.poisoned.Load() || result.ErrorCode != "node-cleanup-failed" || result.Available {
					t.Fatal("cleanup fence weakened", result)
				}
			}
			if result.CleanupStatus != want {
				t.Fatalf("status %q want %q; result=%+v err=%v", result.CleanupStatus, want, result, err)
			}
			if fault == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			if fault == "resource" && !errors.Is(err, ErrNodeResourceDenied) {
				t.Fatal("resource refusal lost", err)
			}
			if fault == "egress" && (result.ErrorCode != "node-egress-failed" || result.Stage != "egress" || result.Available) {
				t.Fatal("cleanup promoted timeout", result)
			}
		})
	}
}
