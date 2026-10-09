package dnscontrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrSyntheticDNSMapping = errors.New("original synthetic DNS reservation unavailable or changed")
var ErrSyntheticDNSTransitionPending = errors.New("retained synthetic publication requires original baseline/cache/conntrack settlement")

const syntheticDNSLedgerName = "synthetic-reservations.json"
const syntheticDNSLedgerOwner = "razvilka-synthetic-dns-reservations-v1"
const syntheticDNSMaxReservations = 256

// Detached transport definition, never a physical binding or publication
// grant. CORE derives it from the actual frozen DomainPolicyRuntimePlan and
// binds the original source/transition/capture owners in the SAME Manager.
type SyntheticDNSDefinition struct {
	Client                 netip.Addr
	DeviceID, MAC, Ingress string
	ExactNames             []string
}

type SyntheticDNSMappingObservation struct {
	Authority                     NetworkPolicyDNSAuthority
	PublicationID                 string
	Client                        netip.Addr
	DeviceID, MAC, Ingress, QName string
	CNAMEChain                    []string // negative facts ONLY, never alternative FlowName
	Synthetic, RealIPv4           netip.Addr
	ExpiresAt                     time.Time
	PossiblyIssued                bool
	LastPossiblyIssuedAt          time.Time
	LastPossiblyIssuedTTLBound    uint32
}

// Actual coordinator receiver, not a Ready boolean/callback or receipt DTO.
// Production binds the SAME existing ScopedDNSAdapter's concrete owner of
// original baseline transition AND prepared capture/backend. The callback is
// synchronous once, retained through actual publication, never upstream IO.
type NetworkPolicyDNSSyntheticPublicationOwner interface {
	WithSyntheticPublication(context.Context, *SyntheticDNSMapping, func(context.Context) error) error
	CurrentSyntheticMapping(context.Context, *SyntheticDNSMapping) error
}

// Original resolver and protected reservation root remain private. Persisted
// records reserve addresses only; loading metadata cannot recreate a source,
// a published mapping handle, capture, FlowName or forward lease.
type NetworkPolicyDNSSyntheticResolver struct {
	self        *NetworkPolicyDNSSyntheticResolver
	mu          sync.Mutex
	barrier     sync.RWMutex
	closed      atomic.Bool
	invalid     atomic.Bool
	closeDone   chan struct{}
	closeErr    error
	ctx         context.Context
	cancel      context.CancelFunc
	resolver    *NetworkPolicyDNSResolver
	control     *operationgate.ControlEpochReview
	definition  SyntheticDNSDefinition
	root        string
	anchor      os.FileInfo
	owned       *ownedfs.Root
	ledger      syntheticDNSLedger
	mappings    map[netip.Addr]*SyntheticDNSMapping
	publication NetworkPolicyDNSSyntheticPublicationOwner
}

type syntheticDNSLedger struct {
	Schema       int                              `json:"schema"`
	Owner        string                           `json:"owner"`
	Reservations []SyntheticDNSMappingObservation `json:"reservations"`
}

type SyntheticDNSMapping struct {
	self   *SyntheticDNSMapping
	source *NetworkPolicyDNSSyntheticResolver
	index  int
	answer *syntheticDNSRealAnswer
	query  []byte
}

func (*SyntheticDNSMapping) String() string                 { return "[original synthetic DNS reservation]" }
func (*SyntheticDNSMapping) GoString() string               { return "[original synthetic DNS reservation]" }
func (*NetworkPolicyDNSSyntheticResolver) String() string   { return "[original synthetic DNS source]" }
func (*NetworkPolicyDNSSyntheticResolver) GoString() string { return "[original synthetic DNS source]" }

func validSyntheticDNSDefinition(d SyntheticDNSDefinition) bool {
	mac, err := net.ParseMAC(d.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != d.MAC || d.MAC == "00:00:00:00:00:00" || !d.Client.Is4() || !d.Client.IsPrivate() || d.DeviceID == "" || len(d.DeviceID) > 128 || strings.ContainsAny(d.DeviceID+d.Ingress, "\x00\r\n") || d.Ingress == "" || d.Ingress == "lo" || len(d.Ingress) > 15 || strings.ContainsAny(d.Ingress, " /\\\t") || len(d.ExactNames) == 0 || len(d.ExactNames) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, name := range d.ExactNames {
		host, err := normalizeCandidateHostname(name)
		_, literal := netip.ParseAddr(host)
		if err != nil || host != name || literal == nil || host == "home.arpa" || strings.HasSuffix(host, ".home.arpa") || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

// Trusted SAME-adapter factory only: root is its existing protected StateRoot,
// lifetime is its actual listener owner, resolver/control are original objects.
// No Ready flag or mapping snapshot is accepted. Missing coordinator permits
// real baseline answers/reservations only; it cannot publish a synthetic A.
func NewNetworkPolicyDNSSyntheticResolver(ctx, lifetime context.Context, resolver *NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview, root string, definition SyntheticDNSDefinition, publication NetworkPolicyDNSSyntheticPublicationOwner) (*NetworkPolicyDNSSyntheticResolver, error) {
	if ctx == nil || lifetime == nil || lifetime.Err() != nil || resolver == nil || resolver.operations == nil || control == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !validSyntheticDNSDefinition(definition) {
		return nil, ErrSyntheticDNSMapping
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, ErrSyntheticDNSMapping
	}
	if publication != nil {
		value := reflect.ValueOf(publication)
		if !value.Comparable() || value.Kind() == reflect.Pointer && value.IsNil() {
			return nil, ErrSyntheticDNSMapping
		}
	}
	var admit NetworkPolicyDNSAdmission
	err := networkPolicyDNSOperation(ctx, resolver.operations, func(held context.Context) error {
		if err := control.Current(held); err != nil {
			return err
		}
		var err error
		admit, err = resolver.admission(held, definition.Client, "")
		return err
	})
	if err != nil || admit.DeviceID != definition.DeviceID || admit.Ingress != definition.Ingress || admit.Authority.ControlEpoch != control.Reference().Sequence {
		return nil, errors.Join(ErrSyntheticDNSMapping, err)
	}
	before, err := os.Lstat(root)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrSyntheticDNSMapping, err)
	}
	owned, err := ownedfs.Open(root)
	if err != nil {
		return nil, errors.Join(ErrSyntheticDNSMapping, err)
	}
	after, err := os.Lstat(root)
	if err != nil || !os.SameFile(before, after) {
		_ = owned.Close()
		return nil, errors.Join(ErrSyntheticDNSMapping, err)
	}
	def := definition
	def.ExactNames = slices.Clone(def.ExactNames)
	slices.Sort(def.ExactNames)
	life, cancel := context.WithCancel(lifetime)
	s := &NetworkPolicyDNSSyntheticResolver{ctx: life, cancel: cancel, resolver: resolver, control: control, root: root, anchor: before, owned: owned, definition: def, mappings: map[netip.Addr]*SyntheticDNSMapping{}, publication: publication, closeDone: make(chan struct{}), ledger: syntheticDNSLedger{Schema: 1, Owner: syntheticDNSLedgerOwner}}
	s.self = s
	keep := false
	defer func() {
		if !keep {
			_ = s.Close()
		}
	}()
	if wire, err := owned.ReadLimited(syntheticDNSLedgerName, 1<<20); err == nil {
		if s.ledger, err = decodeSyntheticDNSLedger(wire); err != nil {
			return nil, err
		}
		for _, record := range s.ledger.Reservations {
			if record.PossiblyIssued {
				return nil, ErrSyntheticDNSTransitionPending
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Join(ErrSyntheticDNSMapping, err)
	}
	if err := s.current(ctx); err != nil {
		return nil, err
	}
	keep = true
	return s, nil
}

func decodeSyntheticDNSLedger(wire []byte) (syntheticDNSLedger, error) {
	var ledger syntheticDNSLedger
	decoder := json.NewDecoder(strings.NewReader(string(wire)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ledger) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateSyntheticDNSLedger(ledger) != nil {
		return ledger, ErrSyntheticDNSMapping
	}
	return ledger, nil
}

func validateSyntheticDNSLedger(l syntheticDNSLedger) error {
	if l.Schema != 1 || l.Owner != syntheticDNSLedgerOwner || len(l.Reservations) > syntheticDNSMaxReservations {
		return ErrSyntheticDNSMapping
	}
	ids := map[string]bool{}
	for i, r := range l.Reservations {
		definition := SyntheticDNSDefinition{Client: r.Client, DeviceID: r.DeviceID, MAC: r.MAC, Ingress: r.Ingress, ExactNames: []string{r.QName}}
		if !validSyntheticDNSDefinition(definition) || r.Synthetic != syntheticDNSAddress(i) || len(r.PublicationID) != 32 || strings.Trim(r.PublicationID, "0123456789abcdef") != "" || ids[r.PublicationID] || !publicDNSAddress(r.RealIPv4) || !r.RealIPv4.Is4() || len(r.CNAMEChain) > 128 || r.ExpiresAt.IsZero() || !networkPolicyDNSHash(r.Authority.Generation) || r.Authority.ControlEpoch == 0 || r.Authority.BindingRevision == 0 || !networkPolicyDNSHash(r.Authority.Exclusions.Digest) {
			return ErrSyntheticDNSMapping
		}
		for _, name := range r.CNAMEChain {
			host, err := normalizeCandidateHostname(name)
			if err != nil || host != name {
				return ErrSyntheticDNSMapping
			}
		}
		if r.PossiblyIssued {
			if r.LastPossiblyIssuedAt.IsZero() || !r.LastPossiblyIssuedAt.Before(r.ExpiresAt) || r.LastPossiblyIssuedTTLBound == 0 || r.LastPossiblyIssuedTTLBound > 0x7fffffff {
				return ErrSyntheticDNSMapping
			}
		} else if !r.LastPossiblyIssuedAt.IsZero() || r.LastPossiblyIssuedTTLBound != 0 {
			return ErrSyntheticDNSMapping
		}
		ids[r.PublicationID] = true
	}
	return nil
}

func syntheticDNSAddress(index int) netip.Addr {
	return netip.AddrFrom4([4]byte{198, 18, byte((index + 1) >> 8), byte(index + 1)})
}

func (s *NetworkPolicyDNSSyntheticResolver) current(ctx context.Context) error {
	if s == nil || s.self != s || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || s.closed.Load() || s.invalid.Load() {
		return ErrSyntheticDNSMapping
	}
	info, err := os.Lstat(s.root)
	if err != nil || !os.SameFile(s.anchor, info) {
		s.invalid.Store(true)
		s.cancel()
		return errors.Join(ErrSyntheticDNSMapping, err)
	}
	err = networkPolicyDNSOperation(ctx, s.resolver.operations, func(held context.Context) error {
		if err := s.control.Current(held); err != nil {
			return err
		}
		a, err := s.resolver.admission(held, s.definition.Client, "")
		if err != nil || a.DeviceID != s.definition.DeviceID || a.Ingress != s.definition.Ingress {
			return errors.Join(ErrSyntheticDNSMapping, err)
		}
		return nil
	})
	if err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		s.invalid.Store(true)
		s.cancel()
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	wire, err := s.owned.ReadLimited(syntheticDNSLedgerName, 1<<20)
	if errors.Is(err, os.ErrNotExist) && len(s.ledger.Reservations) == 0 && !s.closed.Load() && s.ctx.Err() == nil {
		return nil
	}
	disk, decodeErr := decodeSyntheticDNSLedger(wire)
	if err != nil || decodeErr != nil || !reflect.DeepEqual(disk, s.ledger) || s.closed.Load() || s.ctx.Err() != nil {
		s.invalid.Store(true)
		s.cancel()
		return errors.Join(ErrSyntheticDNSMapping, err, decodeErr)
	}
	return nil
}

func (s *NetworkPolicyDNSSyntheticResolver) writeLedger(ctx context.Context) error {
	data, err := json.Marshal(s.ledger)
	if err != nil || len(data) > 1<<20 {
		return ErrSyntheticDNSMapping
	}
	_, err = s.owned.WriteAtomicWithRenameAdmission(syntheticDNSLedgerName, data, 0600, func(rename func() error) error { return s.control.WithRename(ctx, rename) }, nil)
	if err != nil {
		s.invalid.Store(true)
		s.cancel()
	}
	return err
}

// Reserve reads the actual selected answer. This is an ORIGINAL private
// reservation, not publication or a flow grant; VLESS may use it to prepare
// actual capture/transition resources before DNS can expose its address.
func (s *NetworkPolicyDNSSyntheticResolver) Reserve(ctx context.Context, client netip.Addr, query []byte) (*SyntheticDNSMapping, error) {
	var mapping *SyntheticDNSMapping
	err := s.withRequest(ctx, func(ctx context.Context) error {
		if err := s.current(ctx); err != nil {
			return err
		}
		answer, err := s.resolver.resolveSyntheticAnswer(ctx, client, query, true)
		if err != nil {
			return err
		}
		mapping, err = s.reserveAnswer(ctx, client, query, answer)
		return err
	})
	if err != nil {
		return nil, err
	}
	return mapping, nil
}

func (s *NetworkPolicyDNSSyntheticResolver) withRequest(ctx context.Context, use func(context.Context) error) error {
	if s == nil || s.self != s || ctx == nil || use == nil {
		return ErrSyntheticDNSMapping
	}
	s.barrier.RLock()
	defer s.barrier.RUnlock()
	c, cancel := context.WithTimeout(ctx, networkPolicyDNSOperationTimeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if s.closed.Load() || s.ctx.Err() != nil {
		return ErrSyntheticDNSMapping
	}
	return errors.Join(use(c), c.Err())
}

func (s *NetworkPolicyDNSSyntheticResolver) reserveAnswer(ctx context.Context, client netip.Addr, query []byte, answer *syntheticDNSRealAnswer) (*SyntheticDNSMapping, error) {
	if err := s.current(ctx); err != nil {
		return nil, err
	}
	if answer == nil || answer.resolver != s.resolver || client != s.definition.Client || answer.admission.Kind != "managed" || answer.negativeWire != nil || !slices.Contains(s.definition.ExactNames, answer.name) {
		return nil, ErrSyntheticDNSMapping
	}
	details, err := dnsAnswerDetails(query, answer.wire)
	if err != nil || len(details.Addresses) != 1 || !details.Addresses[0].Is4() || !publicDNSAddress(details.Addresses[0]) || details.TTLSeconds == nil || *details.TTLSeconds == 0 {
		return nil, errors.Join(ErrSyntheticDNSMapping, err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	var mapping *SyntheticDNSMapping
	err = networkPolicyDNSOperation(ctx, s.resolver.operations, func(held context.Context) error {
		if err := s.current(held); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.ledger.Reservations) >= syntheticDNSMaxReservations {
			return ErrSyntheticDNSMapping
		}
		index := len(s.ledger.Reservations)
		record := SyntheticDNSMappingObservation{Authority: answer.admission.Authority, PublicationID: hex.EncodeToString(nonce[:]), Client: client, DeviceID: s.definition.DeviceID, MAC: s.definition.MAC, Ingress: s.definition.Ingress, QName: answer.name, CNAMEChain: slices.Clone(details.CNAMEChain), Synthetic: syntheticDNSAddress(index), RealIPv4: details.Addresses[0], ExpiresAt: answer.resolvedAt.Add(time.Duration(*details.TTLSeconds) * time.Second).UTC()}
		s.ledger.Reservations = append(s.ledger.Reservations, record)
		if err := s.writeLedger(held); err != nil {
			return err
		}
		mapping = &SyntheticDNSMapping{source: s, index: index, answer: answer, query: slicesDNSWire(query)}
		mapping.self = mapping
		s.mappings[record.Synthetic] = mapping
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.current(ctx); err != nil {
		return nil, err
	}
	return mapping, nil
}

func (m *SyntheticDNSMapping) Current(ctx context.Context) error {
	if m == nil || m.self != m || m.source == nil || m.answer == nil {
		return ErrSyntheticDNSMapping
	}
	s := m.source
	if err := s.current(ctx); err != nil {
		return err
	}
	a, err := s.resolver.admission(ctx, m.answer.client, m.answer.name)
	if err != nil || a != m.answer.admission {
		if ctx.Err() == nil {
			s.invalid.Store(true)
			s.cancel()
		}
		return errors.Join(ErrSyntheticDNSMapping, err)
	}
	if err := s.resolver.checkAnswer(ctx, a, m.answer.name, m.answer.wire); err != nil {
		if ctx.Err() == nil {
			s.invalid.Store(true)
			s.cancel()
		}
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.index < 0 || m.index >= len(s.ledger.Reservations) {
		return ErrSyntheticDNSMapping
	}
	record := s.ledger.Reservations[m.index]
	if s.mappings[record.Synthetic] != m || !s.resolver.now().Before(record.ExpiresAt) {
		return ErrSyntheticDNSMapping
	}
	wire, err := s.owned.ReadLimited(syntheticDNSLedgerName, 1<<20)
	disk, decodeErr := decodeSyntheticDNSLedger(wire)
	if err != nil || decodeErr != nil || !reflect.DeepEqual(disk, s.ledger) || s.closed.Load() || s.ctx.Err() != nil {
		s.invalid.Store(true)
		s.cancel()
		return errors.Join(ErrSyntheticDNSMapping, err, decodeErr)
	}
	return nil
}

// Done reports revocation of the original source lifetime only. An open
// channel is never publication, capture or forward permission.
func (m *SyntheticDNSMapping) Done() <-chan struct{} {
	if m != nil && m.self == m && m.source != nil && m.source.self == m.source {
		return m.source.ctx.Done()
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

func (m *SyntheticDNSMapping) Observation(ctx context.Context) (SyntheticDNSMappingObservation, error) {
	if err := m.Current(ctx); err != nil {
		return SyntheticDNSMappingObservation{}, err
	}
	s := m.source
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() || s.ctx.Err() != nil {
		return SyntheticDNSMappingObservation{}, ErrSyntheticDNSMapping
	}
	copy := s.ledger.Reservations[m.index]
	copy.CNAMEChain = slices.Clone(copy.CNAMEChain)
	return copy, nil
}

func (s *NetworkPolicyDNSSyntheticResolver) LookupPublished(ctx context.Context, client, synthetic netip.Addr) (*SyntheticDNSMapping, error) {
	if err := s.current(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	mapping := s.mappings[synthetic]
	s.mu.Unlock()
	observation, err := mapping.Observation(ctx)
	if err != nil || observation.Client != client || !observation.PossiblyIssued || s.publication == nil {
		return nil, errors.Join(ErrSyntheticDNSMapping, err)
	}
	if err := s.publication.CurrentSyntheticMapping(ctx, mapping); err != nil {
		return nil, err
	}
	if err := mapping.Current(ctx); err != nil {
		return nil, err
	}
	return mapping, nil
}

func (s *NetworkPolicyDNSSyntheticResolver) Close() error {
	if s == nil || s.self != s {
		return ErrSyntheticDNSMapping
	}
	if !s.closed.CompareAndSwap(false, true) {
		<-s.closeDone
		return s.closeErr
	}
	defer close(s.closeDone)
	s.cancel()
	s.barrier.Lock()
	defer s.barrier.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeErr = s.owned.Close()
	// Protected reservations remain. TTL/Close/restart never permit alias
	// reuse or claim the external baseline/cache/conntrack cleanup completed.
	return s.closeErr
}
