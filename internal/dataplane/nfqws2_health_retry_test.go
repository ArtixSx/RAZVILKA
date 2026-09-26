package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestNFQWS2HealthRetriesOnlyTransientDNS(t *testing.T) {
	dnsTimeout := &url.Error{Op: "Get", URL: "https://example.com", Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "timeout", IsTimeout: true}}}
	permanent := errors.New("TLS or HTTP response rejected")
	for _, tc := range []struct {
		name          string
		first, second error
		calls         int
	}{
		{"success", nil, nil, 1},
		{"dns-timeout-recovers", dnsTimeout, nil, 2},
		{"dns-temporary-recovers", fmt.Errorf("lookup: %w", &net.DNSError{IsTemporary: true}), nil, 2},
		{"dns-still-fails", dnsTimeout, dnsTimeout, 2},
		{"retry-response-rejected", dnsTimeout, permanent, 2},
		{"nxdomain", &net.DNSError{IsNotFound: true, IsTemporary: true}, nil, 1},
		{"permanent-dns", &net.DNSError{}, nil, 1},
		{"tls-http-error", permanent, nil, 1},
		{"canceled-request", context.Canceled, nil, 1},
		{"non-dns-timeout", context.DeadlineExceeded, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			err := probeNFQWS2Health(ctx, "https://example.com", func(actual context.Context, target string) error {
				calls++
				if actual != ctx || target != "https://example.com" {
					t.Fatal("retry changed the target or renewed its deadline")
				}
				if calls == 1 {
					return tc.first
				}
				return tc.second
			})
			want := tc.first
			if tc.calls == 2 {
				want = tc.second
			}
			if calls != tc.calls || !errors.Is(err, want) {
				t.Fatalf("calls=%d, error=%v; want %d, %v", calls, err, tc.calls, want)
			}
		})
	}
}

func TestNFQWS2HealthRetryHonorsOriginalCancellation(t *testing.T) {
	for _, phase := range []string{"before-probe", "after-probe", "during-delay"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "before-probe" {
				cancel()
			}
			calls := 0
			err := probeNFQWS2Health(ctx, "https://example.com", func(context.Context, string) error {
				calls++
				if phase == "after-probe" {
					cancel()
				} else {
					time.AfterFunc(10*time.Millisecond, cancel)
				}
				return &net.DNSError{IsTimeout: true}
			})
			wantCalls := 1
			if phase == "before-probe" {
				wantCalls = 0
			}
			if !errors.Is(err, context.Canceled) || calls != wantCalls {
				t.Fatalf("cancellation: calls=%d error=%v", calls, err)
			}
		})
	}
}
