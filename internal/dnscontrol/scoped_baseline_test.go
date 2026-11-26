package dnscontrol

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestScopedBaselinePreservesLocalAnswersAndNeverLeaksSelectedQueries(t *testing.T) {
	r, key := scopedFixture(t)
	calls := 0
	r.baseline = func(ctx context.Context, q []byte) ([]byte, error) {
		calls++
		answer := scopedResponse(t, q)
		answer.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}}
		return scopedPack(t, answer), nil
	}
	query := scopedQuery(t, "router.home.arpa", dnsmessage.TypeA)
	answer, _, err := r.resolveClient(context.Background(), key.client, query)
	if err != nil || calls != 1 || !bytes.Equal(answer, scopedPack(t, func() dnsmessage.Message {
		a := scopedResponse(t, query)
		a.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}}
		return a
	}())) {
		t.Fatalf("local baseline changed: calls=%d err=%v", calls, err)
	}
	if _, _, err := r.resolveClient(context.Background(), netip.MustParseAddr("127.0.0.2"), query); err == nil || calls != 1 {
		t.Fatal("unknown client reached baseline")
	}
	scopedExchange(r, key, func(context.Context, []byte) (dohResponse, error) { return dohResponse{}, context.DeadlineExceeded })
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.Type(65)} {
		if _, _, err := r.resolveClient(context.Background(), key.client, scopedQuery(t, key.host, typ)); err == nil {
			t.Fatal("selected request unexpectedly passed")
		}
	}
	if calls != 1 {
		t.Fatal("selected domain silently used baseline")
	}
}

func TestScopedBaselineFencesEpochAndReplyIdentity(t *testing.T) {
	for _, mode := range []string{"epoch", "id", "question", "query", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			r, key := scopedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changed := false
			r.guard = func(ctx context.Context) error {
				if changed {
					return ErrServiceDNSChanged
				}
				return ctx.Err()
			}
			r.baseline = func(_ context.Context, q []byte) ([]byte, error) {
				a := scopedResponse(t, q)
				switch mode {
				case "epoch":
					changed = true
				case "id":
					a.ID++
				case "question":
					a.Questions[0].Name = dnsmessage.MustNewName("different.example.")
				case "query":
					a.Response = false
				case "error":
					return nil, errors.New("upstream unavailable")
				case "cancel":
					cancel()
				}
				return scopedPack(t, a), nil
			}
			if _, _, err := r.resolveClient(ctx, key.client, scopedQuery(t, "other.example", dnsmessage.TypeA)); err == nil {
				t.Fatal("invalid baseline reply accepted")
			}
		})
	}
}

func TestScopedBaselineOnlyExplicitLoopbackDNS(t *testing.T) {
	r, _ := scopedFixture(t)
	for _, endpoint := range []string{"1.1.1.1:53", "192.168.1.1:53", "127.0.0.1:1053", "[::ffff:127.0.0.1]:53"} {
		if r.UseLocalBaseline(netip.MustParseAddrPort(endpoint)) == nil {
			t.Fatal(endpoint)
		}
	}
	if err := r.UseLocalBaseline(netip.MustParseAddrPort("127.0.0.1:53")); err != nil {
		t.Fatal(err)
	}
}
