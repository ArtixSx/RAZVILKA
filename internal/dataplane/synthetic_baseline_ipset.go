package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrSyntheticIPSet = errors.New("synthetic baseline ipset observation unsupported")

type syntheticIPSetError struct{ stage string }

func (e syntheticIPSetError) Error() string    { return "synthetic baseline ipset: " + e.stage }
func (e syntheticIPSetError) Unwrap() error    { return ErrSyntheticIPSet }
func syntheticIPSetFailure(stage string) error { return syntheticIPSetError{stage} }

// SyntheticIPSetReadScope retains the original StartupTools lifetime and checks
// its source before/after use. Source checks must stay OUTSIDE Provider's
// same-thread bracket: Lease.Check itself uses that provider.
type SyntheticIPSetReadScope func(context.Context, func(context.Context) error) error

// SyntheticBaselineIPSetReader can only read the actual current namespace's
// kernel socket. It has no injectable runner/opener, membership map, persisted
// receipt, or cached authority. Success compares two destinations only; it is
// not permission to publish DNS, capture traffic, or alter a rule.
type SyntheticBaselineIPSetReader struct {
	self     *SyntheticBaselineIPSetReader
	provider *netidentity.Provider
	identity netidentity.Identity
	scope    SyntheticIPSetReadScope
}

func NewSyntheticBaselineIPSetReader(provider *netidentity.Provider, identity netidentity.Identity, scope SyntheticIPSetReadScope) (*SyntheticBaselineIPSetReader, error) {
	if provider == nil || identity.Validate() != nil || scope == nil {
		return nil, syntheticIPSetFailure("source")
	}
	r := &SyntheticBaselineIPSetReader{provider: provider, identity: identity, scope: scope}
	r.self = r
	return r, nil
}

func (r *SyntheticBaselineIPSetReader) EquivalentDestinations(ctx context.Context, set string, real, synthetic netip.Addr) error {
	if ctx == nil || r == nil || r.self != r || r.provider == nil || r.scope == nil || !syntheticIPSetName(set) || !real.Is4() || real.Is4In6() || !synthetic.Is4() || !domainPolicyTCPSyntheticPool.Contains(synthetic) || domainPolicyTCPSyntheticPool.Contains(real) {
		return syntheticIPSetFailure("input")
	}
	if _, finite := ctx.Deadline(); !finite {
		return syntheticIPSetFailure("deadline")
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := domainPolicyTCPSynchronousScope(bounded, func(consume func(context.Context) error) error {
		return r.scope(bounded, consume)
	}, func(held context.Context) error {
		return r.provider.WithCurrent(held, func(native context.Context, actual netidentity.Identity) error {
			if actual != r.identity {
				return syntheticIPSetFailure("network")
			}
			socket, err := openSyntheticIPSetSession(native)
			if err != nil {
				return err
			}
			result := syntheticIPSetCompare(native, socket, set, real, synthetic)
			return errors.Join(result, socket.Close(), native.Err())
		})
	})
	if err == nil || errors.Is(err, ErrSyntheticIPSet) {
		return err
	}
	stage := "source"
	if errors.Is(err, context.DeadlineExceeded) {
		stage = "timeout"
	}
	return errors.Join(syntheticIPSetFailure(stage), err)
}

func syntheticIPSetName(name string) bool {
	if len(name) == 0 || len(name) > 31 || strings.ContainsAny(name, "\x00\r\n") {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_@.-", c)) {
			return false
		}
	}
	return true
}

type syntheticIPSetHeader struct {
	name, kind                 string
	protocol, family, revision byte
}
type syntheticIPSetSession interface {
	header(context.Context, string) (syntheticIPSetHeader, error)
	test(context.Context, string, netip.Addr, bool) (bool, error)
	Close() error
}

func syntheticIPSetCompare(ctx context.Context, s syntheticIPSetSession, set string, real, synthetic netip.Addr) error {
	before, err := s.header(ctx, set)
	if err != nil {
		return err
	}
	// Netcraze's observed DNS route set is hash:net/inet revision 2. Later
	// upstream revisions through 7 preserve its one-dimensional nomatch test.
	if before.name != set || before.kind != "hash:net" || before.family != 2 || before.revision < 2 || before.revision > 7 || before.protocol < 6 || before.protocol > 7 {
		return syntheticIPSetFailure("type-family-revision")
	}
	var first [4]bool
	for round := 0; round < 2; round++ {
		index := 0
		for _, address := range []netip.Addr{real, synthetic} {
			for _, nomatch := range []bool{false, true} {
				value, err := s.test(ctx, set, address, nomatch)
				if err != nil {
					return err
				}
				if round == 0 {
					first[index] = value
				} else if value != first[index] {
					return syntheticIPSetFailure("membership-drift")
				}
				index++
			}
		}
	}
	after, err := s.header(ctx, set)
	if err != nil {
		return err
	}
	if after != before {
		return syntheticIPSetFailure("header-drift")
	}
	if first[0] && first[1] || first[2] && first[3] {
		return syntheticIPSetFailure("ambiguous-membership")
	}
	if first[0] != first[2] || first[1] != first[3] {
		return syntheticIPSetFailure("destination-differs")
	}
	return ctx.Err()
}
