package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

type usqueOwnedBridgeFixture struct {
	a        *ProxyTunnelAdapter
	plan     RoutePlan
	spec     ProcessSpec
	address  string
	services []catalog.Service
	ctx      context.Context
}

// Only local configuration reads and an in-memory producer are used. These
// fixtures neither launch USQUE nor observe procfs, dial, resolve DNS or probe.
func usqueOwnedBridgeNewFixture(t *testing.T, transport usqueTransport) usqueOwnedBridgeFixture {
	t.Helper()
	root := t.TempDir()
	config := filepath.Join(root, "engine.json")
	if err := os.WriteFile(config, []byte(`{"endpoint_v4":"1.1.1.1","endpoint_h2_v4":"162.159.193.10"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &ProxyTunnelAdapter{EngineID: "usque", EngineBin: filepath.Join(root, "usque"),
		FreshProfile: func(context.Context) (string, error) { return "wan-123456789abc", nil }}
	service := proxyPredicateFixtureService()
	service.Strategy = []string{"usque"}
	frozen := copyProxyPredicateService(service)
	return usqueOwnedBridgeFixture{a: a, spec: a.engineProcessAt(config, 18080, root, "usque-canary", transport),
		address: "127.0.0.1:18080", services: []catalog.Service{service},
		plan: RoutePlan{Adapter: "usque", Routes: []Route{{ServiceID: service.ID, ServiceName: "Display name is not an ID", ProbeURL: service.ProbeURL, ProbeService: &frozen}}},
		ctx:  WithReviewGuard(context.Background(), func(context.Context) error { return nil }),
	}
}

func usqueOwnedBridgeDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func usqueOwnedBridgeProof(options usquediag.OwnedProbeOptions) usquediag.OwnedRuntimeEvidence {
	identity := usquediag.OwnedRuntimeIdentity{
		RuntimeID:     "managed:usque:" + usqueOwnedBridgeDigest([]byte("fixture managed process and listener")),
		BinarySHA256:  "a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10",
		SessionSHA256: usqueOwnedBridgeDigest([]byte("fixture session")), ArgsSHA256: usqueOwnedBridgeDigest([]byte("fixture exact argv")),
		EnvironmentID: usqueOwnedBridgeDigest([]byte("fixture current epoch")), SocketBinding: usqueOwnedBridgeDigest([]byte("fixture owned socket")),
		SourceCommit: "6aa03fc97d12848dce34eedbd187fb1077b5d1ea", Transport: options.Runtime.Transport, Endpoint: options.Runtime.Endpoint.String(),
		PeerObservation: "tcp-established-peer",
	}
	if identity.Transport == "QUIC" {
		identity.PeerObservation = "udp-unconnected-exclusive-config-inference"
	}
	data, _ := json.Marshal([]string{"owned-usque-path-v1", identity.RuntimeID, identity.BinarySHA256, identity.SessionSHA256,
		identity.ArgsSHA256, identity.EnvironmentID, identity.Transport, identity.Endpoint, identity.PeerObservation, identity.SocketBinding, identity.SourceCommit})
	identity.BindingID = usqueOwnedBridgeDigest(data)
	checked := time.Now().Add(-time.Second).UTC()
	proof := usquediag.OwnedRuntimeEvidence{Origin: "managed-usque-canary", CheckedAt: checked.Format(time.RFC3339Nano),
		ValidUntil: checked.Add(usquediag.MaxCanaryAge).Format(time.RFC3339Nano), Identity: identity,
		ProofBasis: "official-release-owned-path-inference", ProtocolPath: identity.Transport,
		Warp: "plus", Colo: "AMS", Loc: "NL", EgressIP: "1.1.1.1", ServiceProofVersion: 1, ChallengeRoutes: []string{}}
	for _, service := range options.Network.Services {
		proof.ReachableRoutes = append(proof.ReachableRoutes, service.ID)
		proof.ConfirmedRoutes = append(proof.ConfirmedRoutes, service.ID)
	}
	return proof
}

func usqueOwnedBridgeAcceptedResponse(url string) usquediag.OwnedServiceResponse {
	return usquediag.OwnedServiceResponse{URL: url, HTTPStatus: 200, ContentType: "application/json", Body: `{"result":{"accepted":true}}`}
}

func TestUSQUEOwnedBridgeUsesExactRuntimeAndRetainsTypedProof(t *testing.T) {
	for _, transport := range []usqueTransport{{}, {HTTP2: true, SNI: "cloudflare.com"}} {
		t.Run(usqueTransportName(transport), func(t *testing.T) {
			fixture := usqueOwnedBridgeNewFixture(t, transport)
			freshCalls, calls := 0, 0
			fixture.a.FreshProfile = func(context.Context) (string, error) { freshCalls++; return "wan-123456789abc", nil }
			var produced usquediag.OwnedRuntimeEvidence
			fixture.a.ownedUSQUEProbe = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				calls++
				if !options.Enabled || options.Authority == nil || options.Runtime.Root != fixture.spec.Dir || options.Runtime.Binary != fixture.spec.Binary ||
					options.Runtime.SOCKSAddress != fixture.address || options.Network.SOCKSAddress != fixture.address || options.Runtime.Transport != usqueTransportName(transport) ||
					options.Network.Timeout != 20*time.Second || options.Network.UDP != nil || len(options.Network.Services) != 1 {
					t.Fatal("runtime or bounded network request was reconstructed from other authority", options)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 25*time.Second {
					t.Fatal("producer context has no bounded deadline")
				}
				for range 2 {
					if err := options.Authority(ctx); err != nil {
						t.Fatal(err)
					}
					epoch, err := options.Runtime.Environment(ctx)
					if err != nil || len(epoch) != 64 {
						t.Fatal("actual FreshProfile was unavailable", err)
					}
				}
				service := options.Network.Services[0]
				if service.ID != fixture.services[0].ID || service.URL != fixture.services[0].ProbeURL || service.Challenge || service.Validator == nil {
					t.Fatal("service ID/URL/full semantic validator were lost")
				}
				if err := service.Validator(usqueOwnedBridgeAcceptedResponse(service.URL)); err != nil {
					t.Fatal(err)
				}
				produced = usqueOwnedBridgeProof(options)
				return produced, nil
			}
			got, err := fixture.a.probeOwnedUSQUECandidate(fixture.ctx, fixture.plan, fixture.spec, fixture.address, fixture.services)
			if err != nil || calls != 1 || freshCalls != 2 || got.Owned == nil || !reflect.DeepEqual(*got.Owned, produced) ||
				got.CheckedAt != produced.CheckedAt || got.ValidUntil != produced.ValidUntil || got.Endpoint != produced.Identity.Endpoint || got.BindingID != "" ||
				got.Transport != produced.ProtocolPath || !reflect.DeepEqual(got.ConfirmedRoutes, produced.ConfirmedRoutes) {
				t.Fatal("typed evidence was changed or downgraded", got, err)
			}
			produced.ReachableRoutes[0], produced.ConfirmedRoutes[0] = "tampered", "tampered"
			if got.Owned.ReachableRoutes[0] != fixture.services[0].ID || got.Owned.ConfirmedRoutes[0] != fixture.services[0].ID || got.ConfirmedRoutes[0] != fixture.services[0].ID {
				t.Fatal("returned receipt retains producer-owned mutable slices")
			}
		})
	}
}

func TestUSQUEOwnedBridgeUsesFrozenLogicalServiceForSyntheticCell(t *testing.T) {
	fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{})
	fixture.plan.Routes[0].ServiceID = "policy-cell-123"
	fixture.plan.Routes[0].LogicalServiceID = fixture.services[0].ID
	fixture.plan.Routes[0].NetworkPolicyGeneration = "admitted-generation"
	fixture.a.ownedUSQUEProbe = func(_ context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		if options.Network.Services[0].ID != fixture.services[0].ID {
			t.Fatal("synthetic policy cell or display name replaced the catalog identity")
		}
		return usqueOwnedBridgeProof(options), nil
	}
	got, err := fixture.a.probeOwnedUSQUECandidate(fixture.ctx, fixture.plan, fixture.spec, fixture.address, fixture.services)
	if err != nil || got.Owned == nil || len(got.ConfirmedRoutes) != 1 || got.ConfirmedRoutes[0] != fixture.services[0].ID {
		t.Fatal("frozen logical service proof was lost", got, err)
	}
}

func TestUSQUEOwnedBridgeNeverFallsBackAfterOwnedProducerFailure(t *testing.T) {
	fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{})
	legacy, calls := 0, 0
	fixture.a.Probe = func(context.Context, string) error { legacy++; return nil }
	fixture.a.CanaryProbe = func(context.Context, string, string) error { legacy++; return nil }
	fixture.a.CanaryTraceProbe = func(context.Context, string) (usqueCanaryEvidence, error) {
		legacy++
		return usqueCanaryEvidence{Warp: "on"}, nil
	}
	fixture.a.ownedUSQUEProbe = func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		calls++
		return usquediag.OwnedRuntimeEvidence{}, errors.New("owned path unconfirmed")
	}
	got, err := fixture.a.probeOwnedUSQUECandidate(fixture.ctx, fixture.plan, fixture.spec, fixture.address, fixture.services)
	if err == nil || calls != 1 || legacy != 0 || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
		t.Fatal("owned failure was replaced with generic or legacy success", calls, legacy, got, err)
	}
}

func TestUSQUEOwnedBridgeRejectsMissingRevokedAndCanceledGuardBeforeProducer(t *testing.T) {
	for _, mode := range []string{"missing", "nil", "nil-context", "wrong-type", "revoked", "canceled", "guard-cancels", "revoked-at-producer-boundary"} {
		t.Run(mode, func(t *testing.T) {
			fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			guards, calls := 0, 0
			switch mode {
			case "missing":
				fixture.ctx = ctx
			case "nil":
				fixture.ctx = WithReviewGuard(ctx, nil)
			case "nil-context":
				fixture.ctx = nil
			case "wrong-type":
				fixture.ctx = context.WithValue(ctx, reviewGuardKey{}, func() error { return nil })
			case "revoked":
				fixture.ctx = WithReviewGuard(ctx, func(context.Context) error { return errors.New("review revoked") })
			case "canceled":
				fixture.ctx = WithReviewGuard(ctx, func(context.Context) error { guards++; return nil })
				cancel()
			case "guard-cancels":
				fixture.ctx = WithReviewGuard(ctx, func(context.Context) error { cancel(); return nil })
			case "revoked-at-producer-boundary":
				fixture.ctx = WithReviewGuard(ctx, func(context.Context) error {
					guards++
					if guards == 2 {
						return errors.New("review revoked")
					}
					return nil
				})
			}
			fixture.a.ownedUSQUEProbe = func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				calls++
				return usquediag.OwnedRuntimeEvidence{}, errors.New("producer should not run")
			}
			got, err := fixture.a.probeOwnedUSQUECandidate(fixture.ctx, fixture.plan, fixture.spec, fixture.address, fixture.services)
			if err == nil || calls != 0 || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) || mode == "canceled" && guards != 0 {
				t.Fatal("absent/revoked/canceled authority reached an active producer", calls, guards, got, err)
			}
		})
	}
}

func TestUSQUEOwnedBridgeFencesCancellationAndRevocationAfterProducer(t *testing.T) {
	for _, mode := range []string{"cancel", "revoke", "authority-recheck"} {
		t.Run(mode, func(t *testing.T) {
			fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			revoked := false
			fixture.ctx = WithReviewGuard(ctx, func(context.Context) error {
				if revoked {
					return errors.New("review revoked")
				}
				return nil
			})
			fixture.a.ownedUSQUEProbe = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				proof := usqueOwnedBridgeProof(options)
				if mode == "cancel" {
					cancel()
				} else {
					revoked = true
				}
				if mode == "authority-recheck" && options.Authority(ctx) == nil {
					t.Fatal("producer's Authority stopped using the real review guard")
				}
				return proof, nil
			}
			got, err := fixture.a.probeOwnedUSQUECandidate(fixture.ctx, fixture.plan, fixture.spec, fixture.address, fixture.services)
			if err == nil || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
				t.Fatal("proof escaped an expired authority", got, err)
			}
		})
	}
}

func TestUSQUEOwnedBridgeRejectsRuntimeAndCatalogMismatchBeforeProducer(t *testing.T) {
	for _, mode := range []string{"adapter", "plan-adapter", "fresh-missing", "relative-root", "relative-binary", "config-path", "pid-path", "not-route-proof", "process-ID", "listener", "port-mismatch", "config-arg", "unknown-flag", "duplicate-flag", "bad-SNI", "missing-config", "oversized-config", "private-pin", "H2-pin-missing", "duplicate-pin", "noncanonical-pin", "services-missing", "services-extra", "service-ID", "service-URL", "display-name-as-ID", "duplicate-service", "over-eight", "empty-probe", "query", "private-service-host", "ambiguous-predicate", "unfrozen-route", "different-full-predicate", "logical-ID-mismatch", "DEFAULT-is-not-service"} {
		t.Run(mode, func(t *testing.T) {
			fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{HTTP2: true})
			switch mode {
			case "adapter":
				fixture.a.EngineID = "xray"
			case "plan-adapter":
				fixture.plan.Adapter = "xray"
			case "fresh-missing":
				fixture.a.FreshProfile = nil
			case "relative-root":
				fixture.spec.Dir = "relative"
			case "relative-binary":
				fixture.spec.Binary = "usque"
			case "config-path":
				fixture.spec.MatchArg = filepath.Join(fixture.spec.Dir, "other.json")
			case "pid-path":
				fixture.spec.PIDPath = filepath.Join(fixture.spec.Dir, "other.pid")
			case "not-route-proof":
				fixture.spec.RouteProof = false
			case "process-ID":
				fixture.spec.ID = "usque-engine"
			case "listener":
				fixture.address = "192.0.2.1:18080"
			case "port-mismatch":
				fixture.address = "127.0.0.1:18081"
			case "config-arg":
				fixture.spec.Args[1] = filepath.Join(fixture.spec.Dir, "other.json")
			case "unknown-flag":
				fixture.spec.Args = append(fixture.spec.Args, "--ipv6")
			case "duplicate-flag":
				fixture.spec.Args = append(fixture.spec.Args, "--http2")
			case "bad-SNI":
				fixture.spec.Args = append(fixture.spec.Args[:9], "-s", "bad\x00host", "--http2")
			case "missing-config":
				if err := os.Remove(fixture.spec.MatchArg); err != nil {
					t.Fatal(err)
				}
			case "oversized-config":
				if err := os.WriteFile(fixture.spec.MatchArg, []byte(strings.Repeat("x", (8<<20)+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			case "private-pin":
				if err := os.WriteFile(fixture.spec.MatchArg, []byte(`{"endpoint_h2_v4":"10.0.0.1"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "H2-pin-missing":
				if err := os.WriteFile(fixture.spec.MatchArg, []byte(`{"endpoint_v4":"1.1.1.1"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "duplicate-pin":
				if err := os.WriteFile(fixture.spec.MatchArg, []byte(`{"endpoint_h2_v4":"1.1.1.1","endpoint_h2_v4":"1.0.0.1"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "noncanonical-pin":
				if err := os.WriteFile(fixture.spec.MatchArg, []byte(`{"Endpoint_H2_V4":"1.1.1.1"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "services-missing":
				fixture.services = nil
			case "services-extra":
				fixture.plan.Routes = nil
			case "service-ID":
				fixture.services[0].ID = "other"
			case "service-URL":
				fixture.services[0].ProbeURL = "https://example.com/other"
			case "display-name-as-ID":
				fixture.services[0].ID = fixture.plan.Routes[0].ServiceName
			case "duplicate-service":
				fixture.services = append(fixture.services, fixture.services[0])
				fixture.plan.Routes = append(fixture.plan.Routes, fixture.plan.Routes[0])
			case "over-eight":
				fixture.services = make([]catalog.Service, 9)
				fixture.plan.Routes = make([]Route, 9)
			case "empty-probe":
				fixture.services[0].ProbeURL = ""
				fixture.plan.Routes[0].ProbeURL = ""
			case "query", "private-service-host":
				url := "https://example.com/health?supplied=value"
				if mode == "private-service-host" {
					url = "https://service.internal/health"
				}
				fixture.services[0].ProbeURL, fixture.services[0].Probes[0].URL, fixture.plan.Routes[0].ProbeURL = url, url, url
			case "ambiguous-predicate":
				other := fixture.services[0].Probes[0]
				other.ID = "other"
				fixture.services[0].Probes = append(fixture.services[0].Probes, other)
			case "unfrozen-route":
				fixture.plan.Routes[0].ProbeService = nil
			case "different-full-predicate":
				fixture.services[0].Probes[0].Expect.BodyContains[0] = "weaker"
			case "logical-ID-mismatch":
				fixture.plan.Routes[0].LogicalServiceID = "other"
			case "DEFAULT-is-not-service":
				fixture.plan.Routes[0].NetworkPolicyRole = "default"
			}
			calls := 0
			fixture.a.ownedUSQUEProbe = func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				calls++
				return usquediag.OwnedRuntimeEvidence{}, nil
			}
			got, err := fixture.a.probeOwnedUSQUECandidate(fixture.ctx, fixture.plan, fixture.spec, fixture.address, fixture.services)
			if err == nil || calls != 0 || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
				t.Fatal("unreviewed/mismatched runtime or service reached producer", calls, got, err)
			}
		})
	}
}

func TestUSQUEOwnedBridgeFullCatalogSemanticsWithoutSecondRequest(t *testing.T) {
	for _, mode := range []string{"accepted", "false-200", "content-type", "invalid-JSON", "JSON-schema", "JSON-truncated", "sample-too-large", "known-block-page", "URL-tamper", "caller-mutation", "predicate-tamper", "youtube-200", "youtube-204"} {
		t.Run(mode, func(t *testing.T) {
			fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{})
			if strings.HasPrefix(mode, "youtube-") {
				fixture.services[0].ProbeURL, fixture.services[0].Probes = "https://www.youtube.com/generate_204", nil
				fixture.plan.Routes[0].ProbeURL = fixture.services[0].ProbeURL
			}
			if mode == "false-200" || mode == "known-block-page" {
				fixture.services[0].Probes[0].Expect = catalog.ProbeExpectation{BodyContains: []string{"service-ready"}}
			}
			frozen := copyProxyPredicateService(fixture.services[0])
			fixture.plan.Routes[0].ProbeService = &frozen
			calls, validations := 0, 0
			fixture.a.ownedUSQUEProbe = func(_ context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				calls++
				service := options.Network.Services[0]
				response := usqueOwnedBridgeAcceptedResponse(service.URL)
				switch mode {
				case "false-200":
					response.ContentType, response.Body = "text/html", "<html>Sign in</html>"
				case "content-type":
					response.ContentType = "text/plain"
				case "invalid-JSON":
					response.Body = "not JSON"
				case "JSON-schema":
					response.Body = `{"accepted":true}`
				case "JSON-truncated":
					response.BodyTruncated = true
				case "sample-too-large":
					response.Body = strings.Repeat("x", probecheck.MaxBodyBytes+1)
				case "known-block-page":
					response.ContentType, response.Body = "text/html", "<html>Доступ к информационному ресурсу ограничен service-ready</html>"
				case "URL-tamper":
					response.URL = "https://example.com/other"
				case "caller-mutation":
					fixture.services[0].Probes[0].Expect.ContentTypes[0] = "text/plain"
					fixture.services[0].Probes[0].Expect.JSONFields[0] = "missing"
					fixture.services[0].Probes[0].Expect.BodyContains[0] = "absent"
					fixture.services[0].Provenance.Provider = "changed"
				case "predicate-tamper":
					options.Network.Services[0].ID = "other"
					options.Network.Services[0].URL = "https://example.com/other"
					options.Network.Services[0].Validator = nil
				case "youtube-200", "youtube-204":
					response.ContentType, response.Body = "text/plain", ""
					if mode == "youtube-204" {
						response.HTTPStatus = 204
					}
				}
				validations++
				if err := service.Validator(response); err != nil {
					return usquediag.OwnedRuntimeEvidence{}, err
				}
				return usqueOwnedBridgeProof(options), nil
			}
			got, err := fixture.a.probeOwnedUSQUECandidate(fixture.ctx, fixture.plan, fixture.spec, fixture.address, fixture.services)
			positive := mode == "accepted" || mode == "caller-mutation" || mode == "youtube-204"
			if calls != 1 || validations != 1 || (err == nil) != positive || (got.Owned != nil) != positive {
				t.Fatal("semantic grades weakened or service was replayed", calls, validations, got, err)
			}
		})
	}
}

func TestUSQUEOwnedBridgeRejectsReceiptDowngradeOrInventedGrades(t *testing.T) {
	for _, mode := range []string{"missing-proof", "endpoint", "transport", "expired", "future", "reachability-only", "foreign-confirmed", "extra-grade", "challenge", "UDP", "negotiated"} {
		t.Run(mode, func(t *testing.T) {
			fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{})
			fixture.a.ownedUSQUEProbe = func(_ context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				proof := usqueOwnedBridgeProof(options)
				switch mode {
				case "missing-proof":
					return usquediag.OwnedRuntimeEvidence{Warp: "on"}, nil
				case "endpoint":
					proof.Identity.Endpoint = netip.MustParseAddrPort("1.0.0.1:443").String()
				case "transport":
					proof.Identity.Transport, proof.ProtocolPath = "HTTP/2", "HTTP/2"
				case "expired":
					proof.CheckedAt, proof.ValidUntil = time.Now().Add(-10*time.Minute).Format(time.RFC3339Nano), time.Now().Add(-5*time.Minute).Format(time.RFC3339Nano)
				case "future":
					proof.CheckedAt = time.Now().Add(time.Minute).Format(time.RFC3339Nano)
				case "reachability-only":
					proof.ConfirmedRoutes = nil
				case "foreign-confirmed":
					proof.ReachableRoutes, proof.ConfirmedRoutes = []string{"other"}, []string{"other"}
				case "extra-grade":
					proof.ReachableRoutes = append(proof.ReachableRoutes, "other")
					proof.ConfirmedRoutes = append(proof.ConfirmedRoutes, "other")
				case "challenge":
					proof.ChallengeRoutes = append([]string(nil), proof.ConfirmedRoutes...)
				case "UDP":
					proof.UDPForwarding = true
				case "negotiated":
					proof.Negotiated = true
				}
				return proof, nil
			}
			got, err := fixture.a.probeOwnedUSQUECandidate(fixture.ctx, fixture.plan, fixture.spec, fixture.address, fixture.services)
			if err == nil || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
				t.Fatal("typed producer evidence was downgraded/adopted or grades invented", got, err)
			}
		})
	}
}
