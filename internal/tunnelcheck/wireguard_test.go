package tunnelcheck

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestColdWireGuardSendsBeforeHandshake(t *testing.T) {
	var events []string
	err := WireGuard(context.Background(), []Service{{"site", "https://site.example/"}}, time.Second, false,
		func(context.Context, string) error { events = append(events, "packet"); return nil },
		func(context.Context) error {
			events = append(events, "handshake")
			if len(events) < 2 {
				return errors.New("cold peer")
			}
			return nil
		})
	if err != nil || !reflect.DeepEqual(events, []string{"packet", "handshake"}) {
		t.Fatal(events, err)
	}
}
func TestGenericAndAWGHaveNoProviderDependency(t *testing.T) {
	for _, name := range []string{"wireguard", "amneziawg"} {
		t.Run(name, func(t *testing.T) {
			var urls []string
			err := WireGuard(context.Background(), []Service{{"site", "https://site.example/"}}, time.Second, false,
				func(_ context.Context, u string) error { urls = append(urls, u); return nil }, func(context.Context) error { return nil })
			if err != nil || !reflect.DeepEqual(urls, []string{"https://site.example/"}) {
				t.Fatal(urls, err)
			}
		})
	}
}
func TestWarpStillRequiresProviderTrace(t *testing.T) {
	var urls []string
	err := WireGuard(context.Background(), []Service{{"site", "https://site.example/"}}, time.Second, true,
		func(_ context.Context, u string) error { urls = append(urls, u); return nil }, func(context.Context) error { return nil })
	if err != nil || !reflect.DeepEqual(urls, []string{"https://www.cloudflare.com/cdn-cgi/trace", "https://site.example/"}) {
		t.Fatal(urls, err)
	}
}
func TestHandshakeIsNotServiceSuccess(t *testing.T) {
	denied := errors.New("denied")
	err := WireGuard(context.Background(), []Service{{"site", "https://site.example/"}}, time.Second, false,
		func(context.Context, string) error { return denied }, func(context.Context) error { return nil })
	if !errors.Is(err, ErrService) || !errors.Is(err, denied) || errors.Is(err, ErrHandshake) {
		t.Fatal(err)
	}
}
func TestHandshakeFailurePreservesBothCauses(t *testing.T) {
	requestErr, handshakeErr := errors.New("request"), errors.New("handshake")
	err := WireGuard(context.Background(), []Service{{"site", "https://site.example/"}}, time.Second, false,
		func(context.Context, string) error { return requestErr }, func(context.Context) error { return handshakeErr })
	if !errors.Is(err, ErrHandshake) || !errors.Is(err, requestErr) || !errors.Is(err, handshakeErr) {
		t.Fatal(err)
	}
}
func TestCandidateAllServicesCheckedAndDeduplicated(t *testing.T) {
	var urls []string
	err := WireGuard(context.Background(), []Service{{"a", "https://a.example/"}, {"b", "https://b.example/"}, {"b-copy", "https://b.example/"}}, time.Second, false,
		func(_ context.Context, u string) error { urls = append(urls, u); return nil }, func(context.Context) error { return nil })
	if err != nil || !reflect.DeepEqual(urls, []string{"https://a.example/", "https://b.example/"}) {
		t.Fatal(urls, err)
	}
}
func TestCandidateCancellationStopsWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var handshakes int
	err := WireGuard(ctx, []Service{{"a", "https://a.example/"}}, time.Second, false,
		func(context.Context, string) error { cancel(); return nil }, func(context.Context) error { handshakes++; return nil })
	if !errors.Is(err, context.Canceled) || handshakes != 0 {
		t.Fatal(err, handshakes)
	}
}
func TestCandidateNoSafeServiceRefusesBeforeIO(t *testing.T) {
	called := false
	err := WireGuard(context.Background(), nil, time.Second, false,
		func(context.Context, string) error { called = true; return nil }, func(context.Context) error { called = true; return nil })
	if !errors.Is(err, ErrNoService) || called {
		t.Fatal(err, called)
	}
}
func TestCandidateTimeoutNotSuccess(t *testing.T) {
	err := WireGuard(context.Background(), []Service{{"a", "https://a.example/"}}, time.Millisecond, false,
		func(c context.Context, _ string) error { <-c.Done(); return nil }, func(context.Context) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrService) {
		t.Fatal(err)
	}
}
