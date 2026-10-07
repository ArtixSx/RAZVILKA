package dataplane

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func nfqwsScopedTypedSpec(t *testing.T, kind netidentity.Kind) (Plan, NFQWSScopedSpec) {
	t.Helper()
	plan, spec, _ := nfqwsScopedFixture(t)
	identity := netidentity.Identity{Version: netidentity.Version, Kind: kind, BootID: spec.BootID, Inode: 12345}
	if kind == netidentity.ReviewedSingleInitNet {
		identity.Inode = 0
		identity.PlatformReviewSHA256 = backendNFTStockScopeSHA256
		spec.NetNamespace = ""
	}
	spec.NetworkIdentity = &identity
	return plan, spec
}

func TestNFQWSScopedTypedIdentityFrozenAndDigestBound(t *testing.T) {
	for _, kind := range []netidentity.Kind{netidentity.ProcNetInode, netidentity.ReviewedSingleInitNet} {
		t.Run(string(kind), func(t *testing.T) {
			plan, spec := nfqwsScopedTypedSpec(t, kind)
			want := spec.Clone()
			p, err := CompileNFQWSScopedPlan(plan, spec)
			if err != nil {
				t.Fatal(err)
			}
			r, detached := p.Resources(), p.Spec()
			if r.NetworkIdentity == nil || *r.NetworkIdentity != *want.NetworkIdentity || !reflect.DeepEqual(detached, want) {
				t.Fatal("typed scope omitted from frozen metadata")
			}
			spec.NetworkIdentity.Version = 99
			spec.Candidate.Traffic[0].First = 1
			r.NetworkIdentity.Inode = 77
			detached.NetworkIdentity.BootID = ""
			if !reflect.DeepEqual(p.Spec(), want) || *p.Resources().NetworkIdentity != *want.NetworkIdentity {
				t.Fatal("caller/accessor metadata aliases compiler input")
			}
			wire, err := json.Marshal(p.Spec())
			var decoded NFQWSScopedSpec
			if err != nil || json.Unmarshal(wire, &decoded) != nil || !reflect.DeepEqual(decoded, want) {
				t.Fatal("canonical typed spec roundtrip failed", err)
			}
			rebuilt, err := CompileNFQWSScopedPlan(plan, decoded)
			if err != nil || rebuilt.Digest() != p.Digest() {
				t.Fatal("typed reconstruction changed exact effects", err)
			}
			other := decoded.Clone()
			other.BootID = "11234567-89ab-cdef-0123-456789abcdef"
			other.NetworkIdentity.BootID = other.BootID
			changed, err := CompileNFQWSScopedPlan(plan, other)
			if err != nil || changed.Digest() == p.Digest() || slices.Equal(changed.Resources().Chains, p.Resources().Chains) {
				t.Fatal("changed typed boot retained effect identity", err)
			}
		})
	}
	plan, proc := nfqwsScopedTypedSpec(t, netidentity.ProcNetInode)
	_, stock := nfqwsScopedTypedSpec(t, netidentity.ReviewedSingleInitNet)
	p, _ := CompileNFQWSScopedPlan(plan, proc)
	s, _ := CompileNFQWSScopedPlan(plan, stock)
	legacy := proc.Clone()
	legacy.NetworkIdentity = nil
	l, _ := CompileNFQWSScopedPlan(plan, legacy)
	if p.Digest() == s.Digest() || p.Digest() == l.Digest() || slices.Equal(p.Resources().Chains, s.Resources().Chains) {
		t.Fatal("typed kind or legacy distinction missing from effect digest")
	}
}

func TestNFQWSScopedTypedIdentityRejectsMixedOrUnknownScope(t *testing.T) {
	for name, change := range map[string]func(*NFQWSScopedSpec){
		"unknown version":      func(s *NFQWSScopedSpec) { s.NetworkIdentity.Version++ },
		"unknown kind":         func(s *NFQWSScopedSpec) { s.NetworkIdentity.Kind = "boot-only" },
		"different boot":       func(s *NFQWSScopedSpec) { s.NetworkIdentity.BootID = "11234567-89ab-cdef-0123-456789abcdef" },
		"mixed inode":          func(s *NFQWSScopedSpec) { s.NetworkIdentity.Inode = 12345 },
		"unknown profile":      func(s *NFQWSScopedSpec) { s.NetworkIdentity.PlatformReviewSHA256 = strings.Repeat("a", 64) },
		"fabricated namespace": func(s *NFQWSScopedSpec) { s.NetNamespace = "net:[12345]" },
		"old string singleton": func(s *NFQWSScopedSpec) { s.NetworkIdentity = nil },
	} {
		t.Run(name, func(t *testing.T) {
			plan, spec := nfqwsScopedTypedSpec(t, netidentity.ReviewedSingleInitNet)
			change(&spec)
			if _, err := CompileNFQWSScopedPlan(plan, spec); err == nil {
				t.Fatal("unknown/mixed/saved scope acquired compiler intent")
			}
		})
	}
	for _, change := range []func(*NFQWSScopedSpec){
		func(s *NFQWSScopedSpec) { s.NetworkIdentity.Inode = 0 },
		func(s *NFQWSScopedSpec) { s.NetworkIdentity.Inode++ },
		func(s *NFQWSScopedSpec) { s.NetworkIdentity.PlatformReviewSHA256 = backendNFTStockScopeSHA256 },
		func(s *NFQWSScopedSpec) { s.NetNamespace = "" },
		func(s *NFQWSScopedSpec) { s.NetNamespace = "net:[012345]" },
	} {
		plan, spec := nfqwsScopedTypedSpec(t, netidentity.ProcNetInode)
		change(&spec)
		if _, err := CompileNFQWSScopedPlan(plan, spec); err == nil {
			t.Fatal("mixed/noncanonical typed proc input accepted")
		}
	}
}
