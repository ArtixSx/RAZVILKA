package dnscontrol

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"golang.org/x/net/dns/dnsmessage"
)

var ErrSyntheticDNSMappingRequired = errors.New("positive synthetic DNS requires original retained mapping and ready baseline transition")

// This original resolver's real-answer slice precedes synthetic publication.
// A managed positive A cannot be released by this slice. An actual excluded
// QNAME/CNAME/address may instead keep the reviewed firmware DNS reply. A
// provider failure, changed owner or failed exclusion read never becomes miss.
type syntheticDNSRealAnswer struct {
	resolver     *NetworkPolicyDNSResolver
	client       netip.Addr
	name         string
	admission    NetworkPolicyDNSAdmission
	wire         []byte
	resolvedAt   time.Time
	negativeWire []byte // ORIGINAL selected answer, retained only for negatives
}

// UseSyntheticLoopbackBaseline selects only the existing router loopback DNS.
// Trusted adapter wiring must prove its exact client/physical redirect cannot
// loop to this local TCP53 exchange. No client endpoint or fallback is accepted.
func (r *NetworkPolicyDNSResolver) UseSyntheticLoopbackBaseline() error {
	if r == nil || r.operations == nil {
		return ErrNetworkPolicyDNS
	}
	local := &ScopedDNSResolver{}
	if err := local.UseLocalBaseline(netip.MustParseAddrPort("127.0.0.1:53")); err != nil {
		return err
	}
	return r.UseReviewedBaseline(local.baseline)
}

func (r *NetworkPolicyDNSResolver) resolveSyntheticReal(ctx context.Context, client netip.Addr, query []byte) (*syntheticDNSRealAnswer, error) {
	return r.resolveSyntheticAnswer(ctx, client, query, false)
}

func (r *NetworkPolicyDNSResolver) resolveSyntheticAnswer(ctx context.Context, client netip.Addr, query []byte, reservePositive bool) (*syntheticDNSRealAnswer, error) {
	if r == nil || ctx == nil {
		return nil, ErrNetworkPolicyDNS
	}
	q, _, err := scopedBaselineQuestion(query)
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(strings.TrimSuffix(q.Questions[0].Name.String(), "."))
	before, err := r.admission(ctx, client, name)
	if err != nil {
		return nil, err
	}
	answer := &syntheticDNSRealAnswer{resolver: r, client: client, name: name, admission: before}
	var selected []byte
	if before.Kind == "baseline" {
		answer.wire, err = r.syntheticBaseline(ctx, query)
	} else if r.service != nil {
		if _, match := r.service.choices[scopedDNSKey{client, name}]; match {
			answer.wire, err = r.service.resolve(ctx, client, query, func(wire []byte) error {
				selected = slicesDNSWire(wire)
				return r.checkAnswer(ctx, before, name, wire)
			})
		} else {
			answer.wire, err = r.resolveDefault(ctx, query, q)
		}
	} else {
		answer.wire, err = r.resolveDefault(ctx, query, q)
	}
	if err != nil && (!errors.Is(err, ErrNetworkPolicyDNSExcluded) || selected == nil) {
		return nil, err
	}
	if selected == nil && err == nil && before.Kind == "managed" {
		selected = slicesDNSWire(answer.wire)
	}
	if selected != nil {
		targets, targetErr := r.answerTargets(ctx, before, name, selected)
		if targetErr != nil {
			return nil, targetErr
		}
		excluded, exclusionErr := r.exclusions.observe(ctx, targets, nil)
		if exclusionErr != nil {
			return nil, exclusionErr
		}
		if excluded {
			answer.negativeWire = selected
			answer.wire, err = r.syntheticBaseline(ctx, query)
			if err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	if err := networkPolicyDNSAnswer(query, answer.wire); err != nil {
		return nil, err
	}
	closing, err := r.admission(ctx, client, name)
	if err != nil || closing != before {
		return nil, errors.Join(ErrNetworkPolicyDNS, err)
	}
	if before.Kind == "managed" && answer.negativeWire == nil {
		if err := r.checkAnswer(ctx, before, name, answer.wire); err != nil {
			return nil, err
		}
		var actual dnsmessage.Message
		if actual.Unpack(answer.wire) != nil {
			return nil, errDNSAnswer
		}
		// There is no synthetic mapping/transition owner in this real-answer
		// slice. Never publish a managed positive A as pretend D07 authority.
		if q.Questions[0].Type == dnsmessage.TypeA {
			details, err := dnsAnswerDetails(query, answer.wire)
			if err == nil && len(details.Addresses) != 0 && details.TTLSeconds != nil && *details.TTLSeconds != 0 && !reservePositive {
				return nil, ErrSyntheticDNSMappingRequired
			}
			if err != nil && !scopedNegative(err) {
				return nil, err
			}
		}
	}
	answer.resolvedAt = r.now()
	return answer, nil
}

func (r *NetworkPolicyDNSResolver) syntheticBaseline(ctx context.Context, query []byte) ([]byte, error) {
	if r.baseline == nil {
		return nil, ErrNetworkPolicyDNS
	}
	bounded, cancel := context.WithTimeout(ctx, endpointProbeTimeout)
	defer cancel()
	return r.baseline(bounded, slicesDNSWire(query))
}

func (r *NetworkPolicyDNSResolver) prepareSyntheticRealPublication(ctx context.Context, answer *syntheticDNSRealAnswer, send func([]byte) error) (func(func() error) error, func() error, error) {
	if answer == nil || answer.resolver != r || send == nil {
		return nil, nil, ErrNetworkPolicyDNS
	}
	current, err := r.admission(ctx, answer.client, answer.name)
	if err != nil || current != answer.admission {
		return nil, nil, errors.Join(ErrNetworkPolicyDNS, err)
	}
	if answer.negativeWire == nil {
		return r.preparePublication(ctx, answer.client, answer.name, answer.admission, answer.wire, answer.resolvedAt, send)
	}
	// A baseline derived from actual negative alias/address facts is distinct
	// from the original positive admission. Recompute catalog identities BEFORE
	// Store/Stop locks, then require that SAME actual negative under Store RLock.
	targets, err := r.answerTargets(ctx, answer.admission, answer.name, answer.negativeWire)
	if err != nil {
		return nil, nil, err
	}
	observe := func(write func() error) error {
		missing, err := r.exclusions.observeDecision(ctx, func(ctx context.Context, set config.EffectiveExclusionSet) (bool, error) {
			matched := false
			for _, target := range targets {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				negative, err := set.Matches(target)
				if err != nil {
					return false, err
				}
				matched = matched || negative
			}
			return !matched, nil
		}, write)
		if missing {
			return errors.Join(ErrNetworkPolicyDNS, err)
		}
		return err
	}
	write := func() error {
		wire, err := r.ageResidence(answer.wire, answer.resolvedAt)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return send(wire)
	}
	return observe, write, nil
}

// PublishSyntheticRealWithOperations executes the actual resolver→negative
// decision→reviewed baseline→original Store/Stop/send path. Positive synthetic
// publication stays closed until the SAME mapping/transition producer is bound.
func (r *NetworkPolicyDNSResolver) PublishSyntheticRealWithOperations(ctx context.Context, client netip.Addr, query []byte, publish NetworkPolicyDNSReplyPublisher, send func([]byte) error) error {
	if r == nil || r.operations == nil || publish == nil || send == nil {
		return ErrNetworkPolicyDNS
	}
	answer, err := r.resolveSyntheticReal(ctx, client, query)
	if err != nil {
		return err
	}
	return networkPolicyDNSOperation(ctx, r.operations, func(held context.Context) error {
		observe, write, err := r.prepareSyntheticRealPublication(held, answer, send)
		if err != nil {
			return err
		}
		return publish(held, answer.admission, observe, write)
	})
}

// ServeSyntheticRealWithOperations retains the existing bounded UDP/TCP worker
// lifecycle. It is an actual real-answer consumer, not a synthetic Ready grant.
func (r *NetworkPolicyDNSResolver) ServeSyntheticRealWithOperations(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener, publish NetworkPolicyDNSReplyPublisher) error {
	if r == nil || ctx == nil || r.operations == nil || publish == nil {
		return ErrNetworkPolicyDNS
	}
	if r.service != nil {
		defer r.service.cache.clear()
	}
	return ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler{
		Admit: func(ctx context.Context, client netip.Addr) error { _, err := r.admission(ctx, client, ""); return err },
		Exchange: func(ctx context.Context, client netip.Addr, query []byte, send func([]byte) error) error {
			bounded, cancel := context.WithTimeout(ctx, networkPolicyDNSOperationTimeout)
			defer cancel()
			return r.PublishSyntheticRealWithOperations(bounded, client, query, publish, send)
		},
	})
}
