package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestEndpointReviewPinsPublicDNSAnswerWithoutReresolving(t *testing.T) {
	profile := reviewedWGFixture("engage.cloudflareclient.com:2408")
	lookups := 0
	review, err := ReviewWireGuardEndpoint(context.Background(), profile, func(_ context.Context, host string) ([]netip.Addr, error) {
		lookups++
		if host != "engage.cloudflareclient.com" {
			t.Fatal("unexpected review host", host)
		}
		return []netip.Addr{netip.MustParseAddr("162.159.192.2"), netip.MustParseAddr("162.159.192.1"), netip.MustParseAddr("162.159.192.1")}, nil
	})
	if err != nil || lookups != 1 || strings.Join(review.Addresses, ",") != "162.159.192.1,162.159.192.2" || !review.valid {
		t.Fatalf("review=%+v lookups=%d err=%v", review.Public(), lookups, err)
	}
	tampered := review
	tampered.Addresses = []string{"1.1.1.1"}
	tampered.Port = 53
	tampered.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	if err := WithResolvedWireGuardCandidate(context.Background(), profile, tampered, "1.1.1.1", true, CandidateOptions{}, func(context.Context, WireGuardCandidate) error { return nil }); !errors.Is(err, ErrEndpointReview) {
		t.Fatal("edited display fields authorized a candidate", err)
	}
	var retained WireGuardCandidate
	err = WithResolvedWireGuardCandidate(context.Background(), profile, review, "162.159.192.2", true, CandidateOptions{}, func(_ context.Context, candidate WireGuardCandidate) error {
		retained = candidate
		if candidate.Public().Endpoint != "162.159.192.2:2408" {
			t.Fatal("candidate was not pinned", candidate.Public())
		}
		return nil
	})
	if err != nil || lookups != 1 {
		t.Fatalf("pinned candidate err=%v lookups=%d", err, lookups)
	}
	if !bytes.Equal(retained.privateKey, make([]byte, 32)) {
		t.Fatal("pinned candidate secret survived callback")
	}
	encoded, _ := json.Marshal(review)
	var restored WireGuardEndpointReview
	if json.Unmarshal(encoded, &restored) != nil {
		t.Fatal("public review JSON failed to decode")
	}
	if err := WithResolvedWireGuardCandidate(context.Background(), profile, restored, "162.159.192.2", true, CandidateOptions{}, func(context.Context, WireGuardCandidate) error { return nil }); !errors.Is(err, ErrEndpointReview) {
		t.Fatal("restored public review authorized a candidate", err)
	}
}

func TestEndpointReviewRejectsMixedPrivateStaleOrChangedEvidence(t *testing.T) {
	profile := reviewedWGFixture("engage.cloudflareclient.com:2408")
	mixed, err := ReviewWireGuardEndpoint(context.Background(), profile, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("162.159.192.1"), netip.MustParseAddr("192.168.1.1")}, nil
	})
	if !errors.Is(err, ErrEndpointReview) || mixed.valid {
		t.Fatal("mixed private DNS answer accepted", mixed, err)
	}
	review, err := ReviewWireGuardEndpoint(context.Background(), profile, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("162.159.192.1")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	review.validUntil = time.Now().UTC().Add(-time.Second)
	consume := func(context.Context, WireGuardCandidate) error {
		t.Fatal("invalid review reached candidate")
		return nil
	}
	if err := WithResolvedWireGuardCandidate(context.Background(), profile, review, "162.159.192.1", true, CandidateOptions{}, consume); !errors.Is(err, ErrEndpointReview) {
		t.Fatal("expired review accepted", err)
	}
	review.validUntil = time.Now().UTC().Add(time.Minute)
	changed := append(append([]byte(nil), profile...), []byte("# changed\n")...)
	if err := WithResolvedWireGuardCandidate(context.Background(), changed, review, "162.159.192.1", true, CandidateOptions{}, consume); !errors.Is(err, ErrEndpointReview) {
		t.Fatal("changed profile accepted", err)
	}
	if err := WithResolvedWireGuardCandidate(context.Background(), profile, review, "162.159.192.3", true, CandidateOptions{}, consume); !errors.Is(err, ErrEndpointReview) {
		t.Fatal("unreviewed address accepted", err)
	}
}
