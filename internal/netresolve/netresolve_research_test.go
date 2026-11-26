package netresolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestResearchCancelledBeforeLookup(t *testing.T) {
	old := lookup
	defer func() { lookup = old }()
	called := 0
	lookup = func(context.Context, string, string) ([]netip.Addr, error) { called++; return nil, nil }
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LookupNetIP(c, "ip", "example.test"); !errors.Is(err, context.Canceled) || called != 0 {
		t.Fatal(err, called)
	}
}
func TestResearchCancelledLateSuccessNotEvidence(t *testing.T) {
	old := lookup
	defer func() { lookup = old }()
	c, cancel := context.WithCancel(context.Background())
	lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
	}
	got, err := LookupNetIP(c, "ip", "example.test")
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal(got, err)
	}
}
func TestResearchCancellationNotPreviousDNSTimeout(t *testing.T) {
	old := lookup
	defer func() { lookup = old }()
	c, cancel := context.WithCancel(context.Background())
	lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		cancel()
		return nil, &net.DNSError{IsTimeout: true}
	}
	if _, err := LookupNetIP(c, "ip", "example.test"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestResearchRetriesBoundedAndNotFoundNotRetried(t *testing.T) {
	old := lookup
	defer func() { lookup = old }()
	for _, tt := range []struct {
		name  string
		err   error
		calls int
	}{{"timeout", &net.DNSError{IsTimeout: true}, 3}, {"notfound", &net.DNSError{IsNotFound: true, IsTemporary: true}, 1}, {"permanent", errors.New("permanent"), 1}} {
		calls := 0
		lookup = func(context.Context, string, string) ([]netip.Addr, error) { calls++; return nil, tt.err }
		if _, err := LookupNetIP(context.Background(), "ip", "example.test"); err == nil || calls != tt.calls {
			t.Fatalf("%s: %d %v", tt.name, calls, err)
		}
	}
}
