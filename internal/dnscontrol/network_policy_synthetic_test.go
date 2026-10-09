package dnscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/net/dns/dnsmessage"
)

// No sockets, network processes or native effects. Store, protected files,
// operation Gate and durable Stop owner are actual; upstream, physical/MAC
// admission and prepared transition/capture receiver are explicit models.
type syntheticDNSFixture struct {
	r                 *NetworkPolicyDNSResolver
	client            netip.Addr
	gate              *operationgate.Gate
	control           *operationgate.ControlEpochReview
	controlRoot, root string
	definition        SyntheticDNSDefinition
}

func syntheticDNSModelFixture(t *testing.T, negatives []config.ResourceMatch) syntheticDNSFixture {
	t.Helper()
	base, _ := networkDNSFixture(t)
	networkDNSStoredNegatives(t, base, negatives, nil)
	client := netip.MustParseAddr("192.168.1.40")
	gate := &operationgate.Gate{}
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlRoot); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	authority := base.authority
	authority.ControlEpoch = control.Reference().Sequence
	guard := func(ctx context.Context) error { return networkPolicyDNSOperation(ctx, gate, control.Current) }
	identities := base.exclusions.identities
	base.exclusions.identities = func(ctx context.Context, name string) ([]string, error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		return identities(ctx, name)
	}
	plan, err := base.defaultDNS.manager.FreezeNetworkPolicyDNSPlan(held, authority.Generation, "private", []ClientDNSBinding{{Client: client, Domain: "service.example.com", ProfileID: "private"}}, base.exclusions)
	if err != nil {
		t.Fatal(err)
	}
	r, err := base.defaultDNS.manager.NewNetworkPolicyDNSResolverForPlanWithOperations(held, plan, authority, gate, guard, func(ctx context.Context, c netip.Addr, name string) (NetworkPolicyDNSAdmission, error) {
		if err := guard(ctx); err != nil {
			return NetworkPolicyDNSAdmission{}, err
		}
		if c != client {
			return NetworkPolicyDNSAdmission{}, ErrNetworkPolicyDNSOutside
		}
		kind := "managed"
		if name != "" && name != "service.example.com" {
			kind = "baseline"
		}
		return NetworkPolicyDNSAdmission{Authority: authority, Ingress: "br0", DeviceID: "selected", Kind: kind}, nil
	}, base.exclusions)
	if err != nil {
		t.Fatal(err)
	}
	r.now, r.service.cache.now = time.Now, time.Now
	scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	if err := r.UseReviewedBaseline(func(_ context.Context, q []byte) ([]byte, error) {
		answer := scopedResponse(t, q)
		if answer.Questions[0].Type == dnsmessage.TypeAAAA {
			answer.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700::1001").As16()}
		} else if answer.Questions[0].Type == dnsmessage.TypeA {
			answer.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}
		} else {
			answer.Answers = nil
		}
		return scopedPack(t, answer), nil
	}); err != nil {
		t.Fatal(err)
	}
	return syntheticDNSFixture{r: r, client: client, gate: gate, control: control, controlRoot: controlRoot, root: t.TempDir(), definition: SyntheticDNSDefinition{Client: client, DeviceID: "selected", MAC: "02:00:00:00:00:40", Ingress: "br0", ExactNames: []string{"service.example.com"}}}
}

func (f syntheticDNSFixture) source(t *testing.T, owner NetworkPolicyDNSSyntheticPublicationOwner) *NetworkPolicyDNSSyntheticResolver {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := NewNetworkPolicyDNSSyntheticResolver(ctx, context.Background(), f.r, f.control, f.root, f.definition, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSyntheticDNSOriginalReservationDetachedObservationAndClose(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	m, err := s.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	o, err := m.Observation(context.Background())
	if err != nil || o.Synthetic != netip.MustParseAddr("198.18.0.1") || o.RealIPv4 != netip.MustParseAddr("93.184.215.14") || o.PossiblyIssued || o.QName != "service.example.com" {
		t.Fatal(o, err)
	}
	o.QName, o.MAC = "forged.example.com", "02:00:00:00:00:99"
	o.CNAMEChain = append(o.CNAMEChain, "forged.example.com")
	if actual, err := m.Observation(context.Background()); err != nil || actual.QName != "service.example.com" || len(actual.CNAMEChain) != 0 {
		t.Fatal("observation changed original", actual, err)
	}
	copy := *m
	if err := copy.Current(context.Background()); !errors.Is(err, ErrSyntheticDNSMapping) {
		t.Fatal("copy replaced original", err)
	}
	if _, err := s.LookupPublished(context.Background(), f.client, netip.MustParseAddr("198.18.0.1")); !errors.Is(err, ErrSyntheticDNSMapping) {
		t.Fatal("reservation became published", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.Done():
	default:
		t.Fatal("Close did not revoke lifetime")
	}
	if err := m.Current(context.Background()); err == nil {
		t.Fatal("closed mapping revived")
	}
	if _, err := os.Stat(filepath.Join(f.root, syntheticDNSLedgerName)); err != nil {
		t.Fatal("Close removed reservation", err)
	}
	if err := networkPolicyDNSOperation(context.Background(), f.gate, f.control.Current); err != nil {
		t.Fatal("Close closed shared control", err)
	}
}

func TestSyntheticDNSMissingPreparedOwnerCannotPublishOrReserve(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	sends := 0
	err := s.Publish(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA), func([]byte) error { sends++; return nil })
	if !errors.Is(err, ErrSyntheticDNSMappingRequired) || sends != 0 || len(s.ledger.Reservations) != 0 {
		t.Fatal(err, sends, len(s.ledger.Reservations))
	}
}

func TestSyntheticDNSAnswerNegativesUseActualBaseline(t *testing.T) {
	for _, match := range []config.ResourceMatch{{Kind: "exact", Value: "cdn.example.com"}, {Kind: "ip", Value: "93.184.215.14"}} {
		t.Run(match.Kind, func(t *testing.T) {
			f := syntheticDNSModelFixture(t, []config.ResourceMatch{match})
			s := f.source(t, nil)
			scopedExchange(f.r.service, scopedDNSKey{f.client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
				answer := scopedResponse(t, q)
				alias := dnsmessage.MustNewName("cdn.example.com.")
				answer.Answers[0].Header.Name = alias
				answer.Answers = append([]dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: answer.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}}, answer.Answers...)
				return dohResponse{wire: scopedPack(t, answer)}, nil
			})
			var wire []byte
			err := s.Publish(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA), func(w []byte) error { wire = slices.Clone(w); return nil })
			var answer dnsmessage.Message
			if err != nil || answer.Unpack(wire) != nil || len(answer.Answers) != 1 || answer.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{1, 1, 1, 1} || len(s.ledger.Reservations) != 0 {
				t.Fatal("negative became positive mapping", err, answer)
			}
		})
	}
}

func TestSyntheticDNSProviderExcludedErrorWithoutActualAnswerCannotFallback(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	scopedExchange(f.r.service, scopedDNSKey{f.client, "service.example.com"}, func(context.Context, []byte) (dohResponse, error) { return dohResponse{}, ErrNetworkPolicyDNSExcluded })
	f.r.baseline = func(context.Context, []byte) ([]byte, error) {
		t.Fatal("provider error became actual negative")
		return nil, nil
	}
	err := s.Publish(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA), func([]byte) error { t.Fatal("provider error sent"); return nil })
	if !errors.Is(err, ErrNetworkPolicyDNSExcluded) {
		t.Fatal(err)
	}
}

func TestSyntheticDNSBaselineStopOrStoreChangeCannotSend(t *testing.T) {
	for _, change := range []string{"stop", "store"} {
		t.Run(change, func(t *testing.T) {
			f := syntheticDNSModelFixture(t, nil)
			s := f.source(t, nil)
			f.r.baseline = func(ctx context.Context, q []byte) ([]byte, error) {
				if change == "stop" {
					_, err := operationgate.RequestSelfUpdateStop(ctx, f.controlRoot, "11111111111111111111111111111111", 1)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					manual := []config.ResourceMatch{{Kind: "exact", Value: "changed.example.com"}}
					_, err := f.r.exclusions.store.UpdateResourceExclusionsPatch(ctx, f.r.exclusions.store.Get(), config.ResourceExclusionsPatch{Manual: &manual})
					if err != nil {
						t.Fatal(err)
					}
				}
				return scopedPack(t, scopedResponse(t, q)), nil
			}
			if err := s.Publish(context.Background(), f.client, scopedQuery(t, "unmatched.example.com", dnsmessage.TypeA), func([]byte) error { t.Fatal("changed owner sent"); return nil }); err == nil {
				t.Fatal("change accepted")
			}
		})
	}
}

func TestSyntheticDNSProtectedDriftIsStickyAndCannotOverwrite(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	m, err := s.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, syntheticDNSLedgerName)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve(context.Background(), f.client, q); err == nil {
		t.Fatal("drift overwritten by next reservation")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Current(context.Background()); err == nil {
		t.Fatal("restored metadata revived original")
	}
	select {
	case <-m.Done():
	default:
		t.Fatal("drift did not revoke")
	}
}

func TestSyntheticDNSRestartRetainsAddressAndCannotHydratePublication(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	m, err := s.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	one, err := m.Observation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	second := f.source(t, nil)
	if _, err := second.LookupPublished(context.Background(), f.client, one.Synthetic); err == nil {
		t.Fatal("metadata reconstructed original")
	}
	m2, err := second.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	two, err := m2.Observation(context.Background())
	if err != nil || two.Synthetic == one.Synthetic {
		t.Fatal("restart reused retained address", two, err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	// Explicit persisted comparison model of an unknown send. It is not a
	// production send receipt and cannot reconstruct capture/baseline owners.
	second.ledger.Reservations[0].PossiblyIssued = true
	second.ledger.Reservations[0].LastPossiblyIssuedAt = time.Now().UTC()
	second.ledger.Reservations[0].LastPossiblyIssuedTTLBound = 120
	data, err := json.Marshal(second.ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, syntheticDNSLedgerName), data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := NewNetworkPolicyDNSSyntheticResolver(ctx, context.Background(), f.r, f.control, f.root, f.definition, nil); !errors.Is(err, ErrSyntheticDNSTransitionPending) {
		t.Fatal("possibly-issued restart became permission", err)
	}
}

func TestSyntheticDNSUnsupportedReservationAndExpiry(t *testing.T) {
	for _, kind := range []string{"multiple", "private", "zero", "negative", "aaaa", "unmatched", "wrong-client"} {
		t.Run(kind, func(t *testing.T) {
			f := syntheticDNSModelFixture(t, nil)
			s := f.source(t, nil)
			scopedExchange(f.r.service, scopedDNSKey{f.client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
				answer := scopedResponse(t, q)
				switch kind {
				case "multiple":
					extra := answer.Answers[0]
					extra.Body = &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}
					answer.Answers = append(answer.Answers, extra)
				case "private":
					answer.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}}
				case "zero":
					answer.Answers[0].Header.TTL = 0
				case "negative":
					answer.Answers = nil
					answer.RCode = dnsmessage.RCodeNameError
				}
				return dohResponse{wire: scopedPack(t, answer)}, nil
			})
			name, typ, client := "service.example.com", dnsmessage.TypeA, f.client
			if kind == "aaaa" {
				typ = dnsmessage.TypeAAAA
			}
			if kind == "unmatched" {
				name = "unmatched.example.com"
			}
			if kind == "wrong-client" {
				client = netip.MustParseAddr("192.168.1.41")
			}
			if _, err := s.Reserve(context.Background(), client, scopedQuery(t, name, typ)); err == nil || len(s.ledger.Reservations) != 0 {
				t.Fatal("unsupported source reserved", err)
			}
		})
	}
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	m, err := s.Reserve(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	o, err := m.Observation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.r.now = func() time.Time { return o.ExpiresAt }
	if err := m.Current(context.Background()); err == nil {
		t.Fatal("expired reservation remained current")
	}
}

// Only a boundary model: success does NOT prove DNAT, capture, native
// physical scope or Xray readiness. Production coordinator remains unbound.
type syntheticDNSPublicationModel struct {
	use     func(context.Context, *SyntheticDNSMapping, func(context.Context) error) error
	current func(context.Context, *SyntheticDNSMapping) error
}

func (m *syntheticDNSPublicationModel) WithSyntheticPublication(ctx context.Context, mapping *SyntheticDNSMapping, use func(context.Context) error) error {
	return m.use(ctx, mapping, use)
}
func (m *syntheticDNSPublicationModel) CurrentSyntheticMapping(ctx context.Context, mapping *SyntheticDNSMapping) error {
	if m.current != nil {
		return m.current(ctx, mapping)
	}
	return mapping.Current(ctx)
}

func TestSyntheticDNSPublicationModelDurableBeforeSendAndExactLookup(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	var original *SyntheticDNSMapping
	owner := &syntheticDNSPublicationModel{use: func(ctx context.Context, m *SyntheticDNSMapping, use func(context.Context) error) error {
		original = m
		return use(ctx)
	}}
	s := f.source(t, owner)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	err := s.Publish(context.Background(), f.client, q, func(w []byte) error {
		data, err := os.ReadFile(filepath.Join(f.root, syntheticDNSLedgerName))
		if err != nil {
			return err
		}
		ledger, err := decodeSyntheticDNSLedger(data)
		if err != nil || !ledger.Reservations[0].PossiblyIssued {
			t.Fatal("send preceded durable unknown-send record", err)
		}
		var reply dnsmessage.Message
		if reply.Unpack(w) != nil || reply.AuthenticData || len(reply.Answers) != 1 || reply.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{198, 18, 0, 1} || reply.Answers[0].Header.TTL == 0 || reply.Answers[0].Header.TTL > 120 {
			t.Fatal(reply)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.LookupPublished(context.Background(), f.client, netip.MustParseAddr("198.18.0.1"))
	if err != nil || m != original {
		t.Fatal("lookup replaced original", err)
	}
	if _, err := s.LookupPublished(context.Background(), netip.MustParseAddr("192.168.1.41"), netip.MustParseAddr("198.18.0.1")); err == nil {
		t.Fatal("another client borrowed publication")
	}
	owner.current = func(context.Context, *SyntheticDNSMapping) error { return ErrSyntheticDNSTransitionPending }
	if _, err := s.LookupPublished(context.Background(), f.client, netip.MustParseAddr("198.18.0.1")); !errors.Is(err, ErrSyntheticDNSTransitionPending) {
		t.Fatal("lost prepared owner accepted", err)
	}
	// Mapping.Current must never recurse through owner.Current.
	if err := original.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticDNSPublicationModelRefusesEscapedOrRepeatedLease(t *testing.T) {
	for _, kind := range []string{"escaped", "repeated", "lost-ready"} {
		t.Run(kind, func(t *testing.T) {
			f := syntheticDNSModelFixture(t, nil)
			var escaped func(context.Context) error
			owner := &syntheticDNSPublicationModel{use: func(ctx context.Context, _ *SyntheticDNSMapping, use func(context.Context) error) error {
				if kind == "escaped" {
					escaped = use
					return nil
				}
				if err := use(ctx); err != nil {
					return err
				}
				return use(ctx)
			}}
			if kind == "lost-ready" {
				owner.current = func(context.Context, *SyntheticDNSMapping) error { return ErrSyntheticDNSTransitionPending }
			}
			s := f.source(t, owner)
			sends := 0
			err := s.Publish(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA), func([]byte) error { sends++; return nil })
			if err == nil || sends > 1 || kind != "repeated" && sends != 0 {
				t.Fatal("invalid lease published", err, sends)
			}
			if escaped != nil && escaped(context.Background()) == nil {
				t.Fatal("escaped callback entered")
			}
		})
	}
}

func TestSyntheticDNSRewriteCannotUseAliasOrFreshTTL(t *testing.T) {
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	answer := scopedResponse(t, q)
	alias := dnsmessage.MustNewName("cdn.example.com.")
	answer.Answers[0].Header.Name = alias
	answer.Answers = append([]dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: answer.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 7}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}}, answer.Answers...)
	answer.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"must strip"}}}}
	now := time.Now()
	record := SyntheticDNSMappingObservation{QName: "service.example.com", Synthetic: netip.MustParseAddr("198.18.0.1"), RealIPv4: netip.MustParseAddr("93.184.215.14"), ExpiresAt: now.Add(5 * time.Second), PossiblyIssued: true}
	wire, err := syntheticDNSRewrite(q, scopedPack(t, answer), record, now)
	var reply dnsmessage.Message
	if err != nil || reply.Unpack(wire) != nil || reply.AuthenticData || len(reply.Answers) != 1 || reply.Answers[0].Header.TTL != 5 || len(reply.Authorities) != 0 || len(reply.Additionals) != 1 {
		t.Fatal(reply, err)
	}
	record.QName = "cdn.example.com"
	if _, err := syntheticDNSRewrite(q, scopedPack(t, answer), record, now); err == nil {
		t.Fatal("alias became QName identity")
	}
	record.QName = "service.example.com"
	record.Synthetic = netip.MustParseAddr("1.1.1.1")
	if _, err := syntheticDNSRewrite(q, scopedPack(t, answer), record, now); err == nil {
		t.Fatal("arbitrary address rewritten")
	}
}

func TestSyntheticDNSCloseJoinsActualRequestWithoutHoldingGateDuringUpstream(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	entered, joined := make(chan struct{}), make(chan struct{})
	scopedExchange(f.r.service, scopedDNSKey{f.client, "service.example.com"}, func(ctx context.Context, _ []byte) (dohResponse, error) {
		close(entered)
		<-ctx.Done()
		close(joined)
		return dohResponse{}, ctx.Err()
	})
	result := make(chan error, 1)
	go func() {
		_, err := s.Reserve(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA))
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not enter modeled provider")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if release, err := f.gate.Enter(ctx); err != nil {
		t.Fatal("upstream held Gate", err)
	} else {
		release()
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join original request")
	}
	select {
	case <-joined:
	default:
		t.Fatal("Close preceded provider join")
	}
	if err := <-result; err == nil {
		t.Fatal("cancelled request reserved")
	}
	if len(s.ledger.Reservations) != 0 {
		t.Fatal("closed request retained an unprepared reservation")
	}
}

func TestSyntheticDNSPublicationModelLostSendAckRemainsReserved(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	owner := &syntheticDNSPublicationModel{use: func(ctx context.Context, _ *SyntheticDNSMapping, use func(context.Context) error) error {
		return use(ctx)
	}}
	s := f.source(t, owner)
	lost := errors.New("modeled uncertain send acknowledgement")
	err := s.Publish(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA), func([]byte) error { return lost })
	if !errors.Is(err, lost) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.root, syntheticDNSLedgerName))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := decodeSyntheticDNSLedger(data)
	if err != nil || len(ledger.Reservations) != 1 || !ledger.Reservations[0].PossiblyIssued || ledger.Reservations[0].LastPossiblyIssuedTTLBound == 0 {
		t.Fatal("lost ACK forgot possible publication", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := NewNetworkPolicyDNSSyntheticResolver(ctx, context.Background(), f.r, f.control, f.root, f.definition, owner); !errors.Is(err, ErrSyntheticDNSTransitionPending) {
		t.Fatal("lost ACK restart recreated permission", err)
	}
}

func TestSyntheticDNSRepeatAndConcurrentQueriesReuseOriginalWithoutRenewingTTL(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	now := time.Now()
	f.r.now = func() time.Time { return now }
	f.r.service.cache.now = f.r.now
	s := f.source(t, nil)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	original, err := s.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	first, err := original.Observation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	type result struct {
		mapping *SyntheticDNSMapping
		err     error
	}
	results := make(chan result, 16)
	for i := 0; i < 16; i++ {
		go func() { m, err := s.Reserve(context.Background(), f.client, q); results <- result{m, err} }()
	}
	for i := 0; i < 16; i++ {
		got := <-results
		if got.err != nil || got.mapping != original {
			t.Fatal("repeat replaced original", got.err)
		}
	}
	current, err := original.Observation(context.Background())
	if err != nil || !current.ExpiresAt.Equal(first.ExpiresAt) || len(s.ledger.Reservations) != 1 {
		t.Fatal("repeat renewed TTL or consumed pool", err, len(s.ledger.Reservations))
	}
	// A changed real answer gets a new address, while the old retained
	// original remains current through its own expiry and negative fences.
	scopedExchange(f.r.service, scopedDNSKey{f.client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
		answer := scopedResponse(t, q)
		answer.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{93, 184, 215, 15}}
		return dohResponse{wire: scopedPack(t, answer)}, nil
	})
	changed, err := s.Reserve(context.Background(), f.client, q)
	if err != nil || changed == original {
		t.Fatal("changed real target reused original", err)
	}
	if err := original.Current(context.Background()); err != nil {
		t.Fatal("new answer discarded prior retained mapping", err)
	}
}

func TestSyntheticDNSExpiredOriginalNeverReused(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	now := time.Now()
	f.r.now = func() time.Time { return now }
	f.r.service.cache.now = f.r.now
	s := f.source(t, nil)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	original, err := s.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	first, err := original.Observation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now = first.ExpiresAt.Add(time.Second)
	newMapping, err := s.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newMapping.Observation(context.Background())
	if err != nil || newMapping == original || second.Synthetic == first.Synthetic || len(s.ledger.Reservations) != 2 {
		t.Fatal("expired object/address reused", err)
	}
}

func TestSyntheticDNSFullRetainedMetadataRefusesAllocationWithoutReuse(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	original, err := s.Reserve(context.Background(), f.client, q)
	if err != nil {
		t.Fatal(err)
	}
	record, err := original.Observation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Protected unissued metadata models exhausted reservations only.
	// Loading it creates no original mapping handles or ready effects.
	ledger := syntheticDNSLedger{Schema: 1, Owner: syntheticDNSLedgerOwner}
	for i := 0; i < syntheticDNSMaxReservations; i++ {
		row := record
		row.Synthetic = syntheticDNSAddress(i)
		row.PublicationID = fmt.Sprintf("%032x", i+1)
		ledger.Reservations = append(ledger.Reservations, row)
	}
	data, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, syntheticDNSLedgerName)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	restarted := f.source(t, nil)
	if _, err := restarted.Reserve(context.Background(), f.client, q); !errors.Is(err, ErrSyntheticDNSMapping) {
		t.Fatal("full retained pool allocated", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !slices.Equal(after, data) {
		t.Fatal("allocation rewrote retained reservations", err)
	}
}

func TestSyntheticDNSPublicationModelAsynchronousReturnRevokesAndJoins(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	entered, joined := make(chan struct{}), make(chan struct{})
	owner := &syntheticDNSPublicationModel{use: func(ctx context.Context, _ *SyntheticDNSMapping, use func(context.Context) error) error {
		go func() { _ = use(ctx); close(joined) }()
		<-entered
		return nil
	}, current: func(ctx context.Context, _ *SyntheticDNSMapping) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}}
	s := f.source(t, owner)
	result := make(chan error, 1)
	q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	go func() {
		result <- s.Publish(context.Background(), f.client, q, func([]byte) error { t.Error("asynchronous receiver sent"); return nil })
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrSyntheticDNSMapping) {
			t.Fatal("asynchronous success", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("asynchronous receiver waited for whole request timeout")
	}
	// Source joined the callback before returning; the surrounding modeled
	// owner's goroutine may need one scheduling step to report that join.
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("original callback did not join")
	}
	if len(s.ledger.Reservations) != 1 || s.ledger.Reservations[0].PossiblyIssued {
		t.Fatal("unready asynchronous lease marked publication")
	}
}

func TestSyntheticDNSManagedFamilyRefusesButActualBaselineRemains(t *testing.T) {
	for _, mode := range []string{"managed", "unmatched", "qname-negative", "actual-ip-negative"} {
		t.Run(mode, func(t *testing.T) {
			var negatives []config.ResourceMatch
			if mode == "qname-negative" {
				negatives = []config.ResourceMatch{{Kind: "exact", Value: "service.example.com"}}
			}
			if mode == "actual-ip-negative" {
				negatives = []config.ResourceMatch{{Kind: "ip", Value: "2606:4700::1111"}}
			}
			f := syntheticDNSModelFixture(t, negatives)
			s := f.source(t, nil)
			name := "service.example.com"
			if mode == "unmatched" {
				name = "unmatched.example.com"
			}
			var wire []byte
			err := s.Publish(context.Background(), f.client, scopedQuery(t, name, dnsmessage.TypeAAAA), func(w []byte) error { wire = slices.Clone(w); return nil })
			if mode == "managed" {
				if !errors.Is(err, ErrSyntheticDNSUnsupportedFamily) || len(wire) != 0 {
					t.Fatal("managed AAAA silently published real IPv6", err)
				}
				return
			}
			var reply dnsmessage.Message
			if err != nil || reply.Unpack(wire) != nil || len(reply.Answers) != 1 || reply.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA != netip.MustParseAddr("2606:4700::1001").As16() || len(s.ledger.Reservations) != 0 {
				t.Fatal("baseline IPv6 changed globally", err, reply)
			}
		})
	}
	for _, typ := range []dnsmessage.Type{64, 65} {
		f := syntheticDNSModelFixture(t, nil)
		s := f.source(t, nil)
		f.r.baseline = func(context.Context, []byte) ([]byte, error) {
			t.Fatal("managed SVCB/HTTPS became fallback")
			return nil, nil
		}
		if err := s.Publish(context.Background(), f.client, scopedQuery(t, "service.example.com", typ), func([]byte) error { t.Fatal("managed SVCB/HTTPS published"); return nil }); !errors.Is(err, ErrScopedDNS) {
			t.Fatal("unsupported selected type accepted", typ, err)
		}
	}
}

func TestSyntheticDNSClosingResidenceCannotRenewReceivedTTL(t *testing.T) {
	for _, path := range []string{"service", "default", "baseline", "answer-negative"} {
		for _, timing := range []struct {
			ttl   uint32
			delay time.Duration
		}{{2, 5 * time.Second}, {5, 2 * time.Second}} {
			t.Run(fmt.Sprintf("%s-%d", path, timing.ttl), func(t *testing.T) {
				var negatives []config.ResourceMatch
				if path == "answer-negative" {
					negatives = []config.ResourceMatch{{Kind: "ip", Value: "93.184.215.14"}}
				}
				f := syntheticDNSModelFixture(t, negatives)
				now := time.Now()
				f.r.now = func() time.Time { return now }
				f.r.service.cache.now = f.r.now
				wireReceived := false
				selected := func(_ context.Context, q []byte) (dohResponse, error) {
					answer := scopedResponse(t, q)
					answer.Answers[0].Header.TTL = timing.ttl
					wireReceived = true
					return dohResponse{wire: scopedPack(t, answer)}, nil
				}
				scopedExchange(f.r.service, scopedDNSKey{f.client, "service.example.com"}, selected)
				if path == "default" {
					f.r.service = nil
					networkDefaultExchange(f.r, selected)
				}
				f.r.baseline = func(_ context.Context, q []byte) ([]byte, error) {
					answer := scopedResponse(t, q)
					answer.Answers[0].Header.TTL = timing.ttl
					answer.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}
					wireReceived = true
					return scopedPack(t, answer), nil
				}
				admit := f.r.admit
				f.r.admit = func(ctx context.Context, c netip.Addr, name string) (NetworkPolicyDNSAdmission, error) {
					if name != "" && wireReceived {
						now = now.Add(timing.delay)
						wireReceived = false
					}
					return admit(ctx, c, name)
				}
				owner := &syntheticDNSPublicationModel{use: func(ctx context.Context, _ *SyntheticDNSMapping, use func(context.Context) error) error {
					return use(ctx)
				}}
				s := f.source(t, owner)
				name := "service.example.com"
				if path == "baseline" {
					name = "unmatched.example.com"
				}
				var wire []byte
				err := s.Publish(context.Background(), f.client, scopedQuery(t, name, dnsmessage.TypeA), func(w []byte) error { wire = slices.Clone(w); return nil })
				if timing.delay >= time.Duration(timing.ttl)*time.Second {
					if path == "baseline" || path == "answer-negative" {
						var reply dnsmessage.Message
						if err != nil || reply.Unpack(wire) != nil || len(reply.Answers) != 1 || reply.Answers[0].Header.TTL != 0 || len(s.ledger.Reservations) != 0 {
							t.Fatal("expired real baseline renewed TTL or reserved", err, reply)
						}
						return
					}
					if err == nil || len(wire) != 0 || len(s.ledger.Reservations) != 0 {
						t.Fatal("closing read renewed expired wire", err, len(s.ledger.Reservations))
					}
					return
				}
				var reply dnsmessage.Message
				if err != nil || reply.Unpack(wire) != nil || len(reply.Answers) != 1 || reply.Answers[0].Header.TTL > timing.ttl-uint32(timing.delay/time.Second) {
					t.Fatal("closing residence omitted", err, reply)
				}
			})
		}
	}
}

func TestSyntheticDNSDeletedReservationCannotRestoreOriginal(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	m, err := s.Reserve(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, syntheticDNSLedgerName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := m.Current(context.Background()); err == nil {
		t.Fatal("deleted protected ledger remained current")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Current(context.Background()); err == nil {
		t.Fatal("restored ledger revived deleted reservation")
	}
}
