package netresolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func withLookup(t *testing.T, fake func(context.Context, string, string) ([]netip.Addr, error)) {
	t.Helper()
	previous := lookup
	lookup = fake
	t.Cleanup(func() { lookup = previous })
}

func TestTimeoutIsRetriedUntilTheCachedAnswer(t *testing.T) {
	calls := 0
	withLookup(t, func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		if calls < 3 {
			return nil, &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true, IsTemporary: true}
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	})
	addresses, err := LookupNetIP(context.Background(), "ip", "example.com")
	if err != nil || len(addresses) != 1 || calls != 3 {
		t.Fatalf("addresses=%v err=%v calls=%d", addresses, err, calls)
	}
}

func TestDefiniteAnswersAreNotRetried(t *testing.T) {
	for name, failure := range map[string]error{
		"missing name": &net.DNSError{Err: "no such host", Name: "missing.example", IsNotFound: true},
		"other error":  errors.New("invalid address"),
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			withLookup(t, func(context.Context, string, string) ([]netip.Addr, error) { calls++; return nil, failure })
			if _, err := LookupNetIP(context.Background(), "ip", "missing.example"); !errors.Is(err, failure) || calls != 1 {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestRetriesAreBoundedAndRespectTheCaller(t *testing.T) {
	calls := 0
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	withLookup(t, func(context.Context, string, string) ([]netip.Addr, error) { calls++; return nil, timeout })
	if _, err := LookupNetIP(context.Background(), "ip", "slow.example"); !errors.Is(err, timeout) || calls != attempts {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	calls = 0
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := LookupNetIP(ctx, "ip", "slow.example"); err == nil || calls != 1 {
		t.Fatalf("retried past the caller's deadline: calls=%d", calls)
	}
}
