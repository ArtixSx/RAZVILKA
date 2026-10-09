package dnscontrol

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Publish resolves through the actual retained resolver before obtaining any
// finite publication lease. An ORIGINAL reservation plus SAME concrete ready
// transition/capture owner are required before possibly-issued is persisted.
// The existing Store/Stop boundary encloses only the bounded final socket send.
func (s *NetworkPolicyDNSSyntheticResolver) Publish(ctx context.Context, client netip.Addr, query []byte, send func([]byte) error) error {
	if send == nil {
		return ErrSyntheticDNSMapping
	}
	return s.withRequest(ctx, func(ctx context.Context) error {
		if err := s.current(ctx); err != nil {
			return err
		}
		answer, err := s.resolver.resolveSyntheticAnswer(ctx, client, query, true)
		if err != nil {
			return err
		}
		question, _, err := scopedBaselineQuestion(query)
		if err != nil {
			return err
		}
		details, detailErr := dnsAnswerDetails(query, answer.wire)
		positive := question.Questions[0].Type == dnsmessage.TypeA && detailErr == nil && details.TTLSeconds != nil && *details.TTLSeconds != 0 && len(details.Addresses) != 0
		if answer.admission.Kind == "baseline" || answer.negativeWire != nil || !positive {
			return networkPolicyDNSOperation(ctx, s.resolver.operations, func(held context.Context) error {
				observe, write, err := s.resolver.prepareSyntheticRealPublication(held, answer, send)
				if err != nil {
					return err
				}
				return s.control.WithDNSReply(held, observe, write)
			})
		}
		if s.publication == nil {
			return ErrSyntheticDNSMappingRequired
		}
		mapping, err := s.reserveAnswer(ctx, client, query, answer)
		if err != nil {
			return err
		}
		var mu sync.Mutex
		open, entered, misuse := true, false, false
		var revoke context.CancelFunc
		done := make(chan struct{})
		var publicationErr error
		ownerErr := s.publication.WithSyntheticPublication(ctx, mapping, func(ready context.Context) error {
			mu.Lock()
			if !open || entered || ready == nil {
				misuse = true
				mu.Unlock()
				return ErrSyntheticDNSMapping
			}
			entered = true
			// Freeze cancellation before exposing entry to the owner. A
			// concurrently returning owner must be able to revoke and join.
			deadline, bounded := ctx.Deadline()
			if !bounded {
				publicationErr = ErrSyntheticDNSMapping
				mu.Unlock()
				close(done)
				return publicationErr
			}
			life, cancel := context.WithDeadline(ready, deadline)
			revoke = cancel
			mu.Unlock()
			defer close(done)
			// Cancellation cannot be detached by the coordinator. Its ready
			// lease remains revocable through the actual final publication.
			defer cancel()
			stop := context.AfterFunc(ctx, cancel)
			defer stop()
			publicationErr = networkPolicyDNSOperation(life, s.resolver.operations, func(held context.Context) error {
				if err := mapping.Current(held); err != nil {
					return err
				}
				if err := s.publication.CurrentSyntheticMapping(held, mapping); err != nil {
					return err
				}
				s.mu.Lock()
				now := s.resolver.now().UTC()
				remaining := s.ledger.Reservations[mapping.index].ExpiresAt.Sub(now)
				if remaining <= 0 || remaining/time.Second > 0x7fffffff {
					s.mu.Unlock()
					return ErrSyntheticDNSMapping
				}
				row := &s.ledger.Reservations[mapping.index]
				row.PossiblyIssued = true
				row.LastPossiblyIssuedAt = now
				row.LastPossiblyIssuedTTLBound = uint32((remaining + time.Second - 1) / time.Second)
				err := s.writeLedger(held) // fsync/rename BEFORE Store/Stop/send
				record := s.ledger.Reservations[mapping.index]
				s.mu.Unlock()
				if err != nil {
					return err
				}
				observe, write, err := s.resolver.preparePublication(held, client, answer.name, answer.admission, answer.wire, answer.resolvedAt, func(real []byte) error {
					wire, err := syntheticDNSRewrite(query, real, record, s.resolver.now())
					if err != nil {
						return err
					}
					return send(wire)
				})
				if err != nil {
					return err
				}
				return s.control.WithDNSReply(held, observe, write)
			})
			return publicationErr
		})
		mu.Lock()
		open = false
		didEnter, cancel := entered, revoke
		mu.Unlock()
		if didEnter {
			select {
			case <-done:
			default:
				mu.Lock()
				misuse = true
				mu.Unlock()
				if cancel != nil {
					cancel()
				}
				<-done
			}
		}
		mu.Lock()
		bad := misuse
		mu.Unlock()
		if bad {
			s.invalid.Store(true)
			s.cancel()
		}
		if !didEnter || bad {
			return errors.Join(ErrSyntheticDNSMapping, ownerErr, publicationErr)
		}
		return errors.Join(ownerErr, publicationErr)
	})
}

func syntheticDNSRewrite(query, original []byte, record SyntheticDNSMappingObservation, now time.Time) ([]byte, error) {
	q, _, err := scopedBaselineQuestion(query)
	if err != nil || q.Questions[0].Type != dnsmessage.TypeA || !record.PossiblyIssued || !netip.MustParsePrefix("198.18.0.0/15").Contains(record.Synthetic) || strings.ToLower(strings.TrimSuffix(q.Questions[0].Name.String(), ".")) != record.QName {
		return nil, ErrSyntheticDNSMapping
	}
	if err := networkPolicyDNSAnswer(query, original); err != nil {
		return nil, err
	}
	details, err := dnsAnswerDetails(query, original)
	if err != nil || len(details.Addresses) != 1 || details.Addresses[0] != record.RealIPv4 || details.TTLSeconds == nil {
		return nil, ErrSyntheticDNSMapping
	}
	remaining := record.ExpiresAt.Sub(now) / time.Second
	if remaining <= 0 || remaining > 0x7fffffff {
		return nil, ErrSyntheticDNSMapping
	}
	ttl := min(uint32(remaining), *details.TTLSeconds)
	if ttl == 0 {
		return nil, ErrSyntheticDNSMapping
	}
	var actual dnsmessage.Message
	if actual.Unpack(original) != nil {
		return nil, errDNSAnswer
	}
	actual.AuthenticData = false // synthetic data cannot retain upstream AD/RRSIG
	actual.Truncated = false
	actual.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: record.Synthetic.As4()}}}
	actual.Authorities = nil
	actual.Additionals = q.Additionals // preserve original client EDNS; no signatures/glue
	return actual.Pack()
}

// Serve uses the SAME ScopedDNS listener/workers. It never creates sockets,
// redirects, a positive flow identity or a separate daemon/cache owner.
func (s *NetworkPolicyDNSSyntheticResolver) Serve(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener) error {
	if s == nil || s.self != s || ctx == nil {
		return ErrSyntheticDNSMapping
	}
	if s.resolver.service != nil {
		defer s.resolver.service.cache.clear()
	}
	return ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler{
		Admit: func(ctx context.Context, client netip.Addr) error {
			if err := s.current(ctx); err != nil {
				return err
			}
			_, err := s.resolver.admission(ctx, client, "")
			return err
		},
		Exchange: func(ctx context.Context, client netip.Addr, query []byte, send func([]byte) error) error {
			return s.Publish(ctx, client, query, send)
		},
	})
}
