package dnscontrol

import (
	"context"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Socket-free upstream/admission models; actual cache and wire serializer.
func TestSyntheticDNSCachedClosingResidenceCannotBecomeFreshReceipt(t *testing.T) {
	for _, stage := range []string{"guard", "answer-check"} {
		for _, timing := range []struct {
			ttl   uint32
			delay time.Duration
		}{{2, 5 * time.Second}, {5, 2 * time.Second}} {
			t.Run(stage+time.Duration(timing.ttl).String(), func(t *testing.T) {
				r, key := scopedFixture(t)
				now := time.Now()
				r.cache.now = func() time.Time { return now }
				calls := 0
				scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
					calls++
					answer := scopedResponse(t, q)
					answer.Answers[0].Header.TTL = timing.ttl
					return dohResponse{wire: scopedPack(t, answer)}, nil
				})
				q := scopedQuery(t, key.host, dnsmessage.TypeA)
				if _, err := r.Resolve(context.Background(), key.client, q); err != nil {
					t.Fatal(err)
				}
				checks := 0
				r.guard = func(ctx context.Context) error {
					checks++
					if stage == "guard" && checks == 2 {
						now = now.Add(timing.delay)
					}
					return ctx.Err()
				}
				wire, err := r.resolve(context.Background(), key.client, q, func([]byte) error {
					if stage == "answer-check" {
						now = now.Add(timing.delay)
					}
					return nil
				})
				var reply dnsmessage.Message
				want := uint32(0)
				if timing.delay < time.Duration(timing.ttl)*time.Second {
					want = timing.ttl - uint32(timing.delay/time.Second)
				}
				if err != nil || reply.Unpack(wire) != nil || len(reply.Answers) != 1 || reply.Answers[0].Header.TTL != want || calls != 1 {
					t.Fatal("cached closing residence renewed TTL", err, reply, calls)
				}
			})
		}
	}
}

func TestSyntheticDNSCachedNegativeResidenceCannotRenewSOATTL(t *testing.T) {
	r, key := scopedFixture(t)
	now := time.Now()
	r.cache.now = func() time.Time { return now }
	scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
		answer := scopedResponse(t, q)
		answer.Answers = nil
		answer.RCode = dnsmessage.RCodeNameError
		answer.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: answer.Questions[0].Name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 2}, Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.com."), MBox: dnsmessage.MustNewName("hostmaster.example.com."), MinTTL: 2}}}
		return dohResponse{wire: scopedPack(t, answer)}, nil
	})
	q := scopedQuery(t, key.host, dnsmessage.TypeA)
	if _, err := r.Resolve(context.Background(), key.client, q); err != nil {
		t.Fatal(err)
	}
	wire, err := r.resolve(context.Background(), key.client, q, func([]byte) error { now = now.Add(5 * time.Second); return nil })
	var reply dnsmessage.Message
	if err != nil || reply.Unpack(wire) != nil || reply.RCode != dnsmessage.RCodeNameError || len(reply.Authorities) != 1 || reply.Authorities[0].Header.TTL != 0 || reply.Authorities[0].Body.(*dnsmessage.SOAResource).MinTTL != 2 {
		t.Fatal("expired negative cached TTL renewed or signed RDATA changed", err, reply)
	}
}

func TestSyntheticDNSExpiredCachedGuardCannotAllocateNewOriginalMapping(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	now := time.Now()
	f.r.now = func() time.Time { return now }
	f.r.service.cache.now = f.r.now
	scopedExchange(f.r.service, scopedDNSKey{f.client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
		answer := scopedResponse(t, q)
		answer.Answers[0].Header.TTL = 2
		return dohResponse{wire: scopedPack(t, answer)}, nil
	})
	s := f.source(t, nil)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	original, err := s.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	guard := f.r.service.guard
	checks := 0
	f.r.service.guard = func(ctx context.Context) error {
		checks++
		if checks == 2 {
			now = now.Add(5 * time.Second)
		}
		return guard(ctx)
	}
	if _, err := s.Reserve(context.Background(), f.client, q); err == nil || len(s.ledger.Reservations) != 1 {
		t.Fatal("expired cached wire created fresh mapping", err, len(s.ledger.Reservations))
	}
	if err := original.Current(context.Background()); err == nil {
		t.Fatal("old mapping expiry renewed")
	}
}
