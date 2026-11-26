package strategylab

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

func TestCandidateProbeScopeDoesNotWidenTransportOrTarget(t *testing.T) {
	valid := CandidateProbeScope{Target: ProbeTarget{ServiceID: "service", ProbeURL: "https://service.example/path", Protocol: "tcp", IPFamily: "ipv4"}, Address: netip.MustParseAddr("1.1.1.1"), CriteriaDigest: strings.Repeat("a", 64)}
	if !candidateProbeScopeValid(valid) {
		t.Fatal("supported tuple refused")
	}
	for _, edit := range []func(*CandidateProbeScope){
		func(s *CandidateProbeScope) { s.Target.Protocol = "quic" }, func(s *CandidateProbeScope) { s.Target.IPFamily = "ipv6" }, func(s *CandidateProbeScope) { s.Target.ProbeURL = "http://service.example/" }, func(s *CandidateProbeScope) { s.Target.ProbeURL = "https://service.example:8443/" }, func(s *CandidateProbeScope) { s.Address = netip.MustParseAddr("127.0.0.1") }, func(s *CandidateProbeScope) { s.Address = netip.MustParseAddr("192.168.1.1") }, func(s *CandidateProbeScope) { s.CriteriaDigest = "" }, func(s *CandidateProbeScope) { s.Target.ServiceID = "service|other" },
	} {
		scope := valid
		edit(&scope)
		if candidateProbeScopeValid(scope) {
			t.Fatal("unsupported scope widened", scope)
		}
	}
}

func TestCandidateProbeReviewRequiresOriginalManagedOwners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, review := range []*CandidateProbeReview{nil, {}, {material: &SelectedCandidateReview{}}} {
		if review.Current(ctx) == nil {
			t.Fatal("detached source became probe authority")
		}
	}
	m, _ := New("")
	scope := CandidateProbeScope{Target: ProbeTarget{ServiceID: "service", ProbeURL: "https://service.example/", Protocol: "tcp", IPFamily: "ipv4"}, Address: netip.MustParseAddr("1.1.1.1"), CriteriaDigest: strings.Repeat("a", 64)}
	if _, err := m.RetainCandidateProbeReview(ctx, "candidate", scope, &components.ManagedNFQWSRuntimeLease{}); err == nil {
		t.Fatal("component DTO became runtime owner")
	}
	if len(m.Snapshot().Selections) != 0 {
		t.Fatal("probe saved a prospective selection")
	}
}
