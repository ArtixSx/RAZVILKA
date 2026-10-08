package strategylab

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestSelectedCandidateTrafficRestrictsSavedFamilyAndTransport(t *testing.T) {
	selection := Selection{Protocol: "tcp", IPFamily: "ipv4"}
	traffic, err := selectedCandidateTraffic(selection, []string{"--filter-tcp=443,80-81", "--lua-desync=fake:blob=tls_clienthello", "--new", "--filter-tcp=81-82"})
	wanted := []SelectedCandidateTraffic{{Protocol: "tcp", IPFamily: "ipv4", First: 80, Last: 82}, {Protocol: "tcp", IPFamily: "ipv4", First: 443, Last: 443}}
	if err != nil || !slices.Equal(traffic, wanted) {
		t.Fatal("explicit profile union changed protocol/family/ports", traffic, err)
	}
	selection = Selection{Protocol: "quic", IPFamily: "ipv6"}
	traffic, err = selectedCandidateTraffic(selection, []string{"--filter-udp=443"})
	if err != nil || !slices.Equal(traffic, []SelectedCandidateTraffic{{Protocol: "udp", IPFamily: "ipv6", First: 443, Last: 443}}) {
		t.Fatal("QUIC selection did not restrict actual UDP/IPv6 coverage", traffic, err)
	}
}

func TestSelectedCandidateTrafficRefusesMissingAmbiguousAndMixedProfiles(t *testing.T) {
	for _, arguments := range [][]string{
		{}, {"--lua-desync=fake:blob=tls_clienthello"}, {"--filter-udp=443"},
		{"--filter-tcp=443", "--filter-udp=443"}, {"--filter-tcp=443", "--new", "--filter-udp=443"},
		{"--filter-tcp=443", "--new"}, {"--new", "--filter-tcp=443"}, {"--filter-tcp=443", "--filter-tcp=80"},
		{"--filter-tcp=~443"}, {"--filter-tcp=https"}, {"--filter-tcp=*"}, {"--filter-tcp=0"},
		{"--filter-tcp=65536"}, {"--filter-tcp=0443"}, {"--filter-tcp=443-80"}, {"--filter-tcp=80-"}, {"--filter-tcp=443,"},
	} {
		if _, err := selectedCandidateTraffic(Selection{Protocol: "tcp", IPFamily: "ipv4"}, arguments); err == nil {
			t.Fatal("ambiguous native coverage granted", arguments)
		}
	}
}

func TestSelectedCandidateReferenceRejectsUncontrolledCopiedClosedSource(t *testing.T) {
	_, original := selectedReviewSourceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, review := range []*SelectedCandidateReview{nil, {}, {self: original, binding: original.binding}, original} {
		ref, err := review.Reference(ctx)
		if err == nil || ref.CandidateID != "" || ref.SourceDigest != "" || len(ref.Traffic) != 0 {
			t.Fatal("uncontrolled source model issued comparison proof", ref, err)
		}
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	if ref, err := original.Reference(ctx); err == nil || ref.CandidateID != "" {
		t.Fatal("closed source produced a reference", ref, err)
	}
}
