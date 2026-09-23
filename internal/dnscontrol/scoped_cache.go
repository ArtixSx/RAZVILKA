package dnscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const scopedCacheEntries = 256
const scopedCacheBytes = 1 << 20
const scopedCacheTTL = 5 * time.Minute
const scopedNegativeTTL = time.Minute
const scopedLedgerGrace = 2 * time.Minute

type scopedAnswerKey struct {
	scopedDNSKey
	typ    dnsmessage.Type
	cd, do bool
}

type scopedAnswerEntry struct {
	request                            uint64
	query                              [32]byte
	wire                               []byte
	details                            AnswerDetails
	observed, expires, forget, touched time.Time
	failure                            string
}

// The ledger belongs to one immutable, guarded resolver instance. It is not a
// second configuration store and never survives process/owner replacement.
// Grace retains diagnostic metadata only: expired wire data is never served.
type scopedAnswerCache struct {
	mu       sync.Mutex
	entries  map[scopedAnswerKey]*scopedAnswerEntry
	sequence uint64
	now      func() time.Time
}

// ScopedDNSObservation is a detached owner-facing readout. None of these DNS
// answers is route authority, evidence of HTTPS access or a service PASS.
type ScopedDNSObservation struct {
	Client                             netip.Addr
	Domain, Family, State, LastFailure string
	ProviderID                         string
	CheckingDisabled, DNSSECRequested  bool
	ObservedAt, ExpiresAt, ForgetAt    time.Time
	Details                            AnswerDetails
}

func scopedAnswerIdentity(key scopedDNSKey, q dnsmessage.Message, wire []byte) (scopedAnswerKey, [32]byte) {
	do := len(q.Additionals) == 1 && q.Additionals[0].Header.TTL&0x8000 != 0
	// Preserve the exact question case and EDNS semantics. Only the caller's
	// transaction ID may differ on a cache hit; RDATA is never repacked.
	copy := append([]byte(nil), wire...)
	copy[0], copy[1] = 0, 0
	return scopedAnswerKey{key, q.Questions[0].Type, q.CheckingDisabled, do}, sha256.Sum256(copy)
}

func (c *scopedAnswerCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *scopedAnswerCache) pruneLocked(now time.Time) {
	for key, entry := range c.entries {
		if !entry.forget.IsZero() && !now.Before(entry.forget) {
			delete(c.entries, key)
			continue
		}
		if !now.Before(entry.expires) {
			entry.wire = nil
		}
	}
}

func (c *scopedAnswerCache) trimLocked() {
	for {
		bytes := 0
		var oldest scopedAnswerKey
		var at time.Time
		for key, entry := range c.entries {
			bytes += len(entry.wire)
			if at.IsZero() || entry.touched.Before(at) {
				oldest, at = key, entry.touched
			}
		}
		if len(c.entries) <= scopedCacheEntries && bytes <= scopedCacheBytes {
			return
		}
		delete(c.entries, oldest)
	}
}

func (c *scopedAnswerCache) begin(key scopedAnswerKey, query [32]byte, id uint16) (uint64, time.Time, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if c.entries == nil {
		c.entries = map[scopedAnswerKey]*scopedAnswerEntry{}
	}
	c.pruneLocked(now)
	e := c.entries[key]
	if e != nil && e.query == query && len(e.wire) > 0 && !now.Before(e.observed) && now.Before(e.expires) {
		// Round up local residence time, so a fractional second cannot extend
		// an upstream lifetime when the next client starts its own timer.
		age := uint64((now.Sub(e.observed) + time.Second - 1) / time.Second)
		wire, err := ageDNSWire(e.wire, age, e.details.NegativeKind != "")
		if err == nil {
			binary.BigEndian.PutUint16(wire, id)
			e.touched = now
			return 0, now, wire
		}
	}
	c.sequence++
	if e == nil {
		e = &scopedAnswerEntry{}
		c.entries[key] = e
	}
	e.request, e.touched = c.sequence, now
	// Even a canceled request with no accepted answer has bounded retention.
	if e.forget.IsZero() {
		e.forget = now.Add(scopedLedgerGrace)
	}
	c.trimLocked()
	return c.sequence, now, nil
}

func (c *scopedAnswerCache) fail(key scopedAnswerKey, ticket uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil && e.request == ticket {
		e.failure = serviceDNSErrorCode(err)
		// Do not renew either the positive lifetime or diagnostic grace.
	}
}

func (c *scopedAnswerCache) accept(key scopedAnswerKey, query [32]byte, ticket uint64, started time.Time, wire []byte, details AnswerDetails) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil || e.request != ticket {
		return
	}
	// A fresh NXDOMAIN contradicts all address families for this exact name.
	// Do not allow an older in-flight answer to restore its former addresses.
	for other, previous := range c.entries {
		if other.scopedDNSKey != key.scopedDNSKey || other == key {
			continue
		}
		if details.NegativeKind == "nxdomain" || previous.details.NegativeKind == "nxdomain" {
			if previous.request > ticket {
				return
			}
		}
	}
	for other, previous := range c.entries {
		if other != key && other.scopedDNSKey == key.scopedDNSKey && (details.NegativeKind == "nxdomain" || previous.details.NegativeKind == "nxdomain") {
			delete(c.entries, other)
		}
	}
	lifetime, limit := details.TTLSeconds, scopedCacheTTL
	if details.NegativeKind != "" {
		lifetime, limit = details.NegativeTTLSeconds, scopedNegativeTTL
	}
	var duration time.Duration
	if lifetime != nil {
		duration = min(time.Duration(*lifetime)*time.Second, limit)
	}
	e.query, e.details = query, cloneAnswerDetails(details)
	e.observed, e.expires, e.failure = started, started.Add(duration), ""
	e.forget = e.expires
	if details.NegativeKind == "" {
		e.forget = e.forget.Add(scopedLedgerGrace)
	}
	e.wire = nil
	if duration > 0 && c.clock().Before(e.expires) {
		e.wire = append([]byte(nil), wire...)
	}
	c.trimLocked()
}

func cloneAnswerDetails(d AnswerDetails) AnswerDetails {
	d.Addresses = append([]netip.Addr(nil), d.Addresses...)
	d.CNAMEChain = append([]string(nil), d.CNAMEChain...)
	if d.TTLSeconds != nil {
		v := *d.TTLSeconds
		d.TTLSeconds = &v
	}
	if d.NegativeTTLSeconds != nil {
		v := *d.NegativeTTLSeconds
		d.NegativeTTLSeconds = &v
	}
	return d
}

func (c *scopedAnswerCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil // pending tickets cannot publish into the former generation
}

// Observations rechecks the owner's epoch and every provider before returning
// a detached snapshot. Expired positives are labeled stale for a bounded grace;
// they are never returned by Resolve as a fallback. Negative expiry is separate.
func (r *ScopedDNSResolver) Observations(ctx context.Context) ([]ScopedDNSObservation, error) {
	for _, choice := range r.choices {
		if err := r.check(ctx, choice); err != nil {
			return nil, err
		}
	}
	out := r.cache.observations(r.choices)
	for _, choice := range r.choices {
		if err := r.check(ctx, choice); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *scopedAnswerCache) observations(choices map[scopedDNSKey]scopedDNSChoice) []ScopedDNSObservation {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	c.pruneLocked(now)
	out := []ScopedDNSObservation{}
	for key, e := range c.entries {
		if e.observed.IsZero() {
			continue
		}
		state := "fresh"
		if !now.Before(e.expires) || now.Before(e.observed) {
			state = "stale"
		}
		family := "ipv4"
		if key.typ == dnsmessage.TypeAAAA {
			family = "ipv6"
		}
		out = append(out, ScopedDNSObservation{Client: key.client, Domain: key.host, Family: family, State: state, LastFailure: e.failure, ProviderID: choices[key.scopedDNSKey].provider.ID, CheckingDisabled: key.cd, DNSSECRequested: key.do, ObservedAt: e.observed, ExpiresAt: e.expires, ForgetAt: e.forget, Details: cloneAnswerDetails(e.details)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Client != out[j].Client {
			return out[i].Client.Less(out[j].Client)
		}
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		if out[i].CheckingDisabled != out[j].CheckingDisabled {
			return !out[i].CheckingDisabled
		}
		return !out[i].DNSSECRequested && out[j].DNSSECRequested
	})
	return out
}

func scopedNegative(err error) bool {
	return errors.Is(err, errDNSNoAddress) || errors.Is(err, errDNSNameError)
}
