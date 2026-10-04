package usquediag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func ownedGradeFixtureEvidence() OwnedRuntimeEvidence {
	checked := time.Date(2026, 10, 4, 0, 0, 0, 123, time.UTC)
	identity := ownedFixtureIdentity()
	return OwnedRuntimeEvidence{Origin: "managed-usque-canary", CheckedAt: checked.Format(time.RFC3339Nano), ValidUntil: checked.Add(MaxCanaryAge).Format(time.RFC3339Nano), Identity: identity, ProofBasis: ownedPathBasis, ProtocolPath: identity.Transport, Warp: "on", ServiceProofVersion: ownedServiceProofVersion}
}

// Only inert receipt files and callbacks are used. All executable candidates
// are absent; the memory HTTP transport cannot open sockets or resolve names.
func ownedGradeReadback(t *testing.T, receipt CanaryEvidence, fresh bool) Report {
	t.Helper()
	root := t.TempDir()
	path := func(name string) string { return filepath.Join(root, name) }
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path("evidence.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	// Fixture clock is independent of every receipt field, including flat times.
	checked := time.Date(2026, 10, 4, 0, 0, 0, 123, time.UTC)
	m := &Manager{Runner: runner, Architecture: "arm64", ConfigPath: path("absent-config"), SessionPath: path("absent-session"), InitPath: path("absent-init"), NDMCPath: path("absent-ndmc"), BinaryCandidates: []string{path("absent-usque")}, IPCandidates: []string{path("absent-ip")}, EvidencePath: path("evidence.json"), Now: func() time.Time { return checked.Add(time.Minute) }}
	if fresh {
		m.EvidenceRuntime = func(context.Context) (OwnedRuntimeIdentity, error) { return ownedFixtureIdentity(), nil }
	}
	report := m.Check(context.Background())
	if len(runner.calls) != 0 {
		t.Fatal("portable readback invoked a command")
	}
	if report.Capabilities.Fresh {
		t.Fatal("typed receipt promoted a legacy capability")
	}
	return report
}

func ownedGradeValidator(service catalog.Service, observations *int) func(OwnedServiceResponse) error {
	return func(response OwnedServiceResponse) error {
		*observations++
		if response.URL != service.ProbeURL {
			return errors.New("private-validator-URL")
		}
		body := []byte(response.Body)
		defer clear(body)
		assessed := probecheck.Evaluate(service, probecheck.ServiceProbe(service), probecheck.Observation{RequestedURL: response.URL, FinalURL: response.URL, HTTPStatus: response.HTTPStatus, ContentType: response.ContentType, Body: body, BodyTruncated: response.BodyTruncated})
		if assessed.Verdict != evidence.VerdictPass {
			return errors.New("private-validator-" + assessed.ErrorCode)
		}
		return nil
	}
}

func TestOwnedServiceSemanticCriteriaInsideIdentityBracket(t *testing.T) {
	youtube := catalog.Service{ID: "youtube", ProbeURL: "https://www.youtube.com/generate_204", Domains: []string{"youtube.com"}, Probes: []catalog.Probe{{URL: "https://www.youtube.com/generate_204", Required: true, Expect: catalog.ProbeExpectation{StatusCodes: []int{204}}}}}
	for _, tc := range []struct {
		name              string
		status            int
		contentType, body string
		validator, pass   bool
	}{
		{"TLS-blockpage-reachable-only", 200, "text/html", "<html>Доступ к запрашиваемому ресурсу ограничен</html>", false, true},
		{"TLS-204-reachable-only", 204, "", "", false, true},
		{"youtube-blockpage-semantic-rejected", 200, "text/html", "<html>Доступ к запрашиваемому ресурсу ограничен</html>", true, false},
		{"youtube-204-semantic-confirmed", 204, "", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := ownedFixtureOptions(t)
			o.Network.Services = []OwnedServiceProbe{{ID: youtube.ID, URL: youtube.ProbeURL}}
			observations, captures := 0, 0
			if tc.validator {
				validate := ownedGradeValidator(youtube, &observations)
				o.Network.Services[0].Validator = func(response OwnedServiceResponse) error {
					if captures != 1 {
						t.Fatal("semantic validator escaped owned identity bracket")
					}
					return validate(response)
				}
			}
			tracked := &ownedTrackedBody{Reader: strings.NewReader(tc.body)}
			client := &http.Client{Transport: ownedMemoryRoundTripper(func(request *http.Request) (*http.Response, error) {
				if request.URL.String() != youtube.ProbeURL {
					t.Fatal("approved URL changed")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{tc.contentType}}, Body: tracked, ContentLength: int64(len(tc.body)), Request: request, TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}}, nil
			})}
			checked := time.Date(2026, 10, 4, 0, 0, 0, 123, time.UTC)
			got, err := probeOwnedUSQUE(context.Background(), o, func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
				captures++
				return ownedFixtureIdentity(), nil
			}, func(ctx context.Context, request OwnedNetworkRequest) (OwnedApplicationProof, error) {
				response, err := ownedHTTPSResponse(ctx, client, request.Services[0].URL, "", ownedServiceBodyLimit, false, true)
				if err != nil {
					return OwnedApplicationProof{}, err
				}
				if err := validateOwnedServiceResponse(ctx, request.Services[0], "", response); err != nil {
					return OwnedApplicationProof{}, err
				}
				proof := OwnedApplicationProof{Warp: "on"}
				recordOwnedServiceProof(&proof, request.Services[0])
				return proof, nil
			}, func() time.Time { return checked })
			if !tracked.closed {
				t.Fatal("response body not closed")
			}
			if !tc.pass {
				requireOwnedProbeError(t, got, err, "owned-network-service-invalid")
				if captures != 1 || observations != 1 || strings.Contains(err.Error(), "private") {
					t.Fatal("semantic rejection leaked or completed capture")
				}
				return
			}
			if err != nil || captures != 2 || got.CheckedAt != checked.Format(time.RFC3339Nano) || got.ValidUntil != checked.Add(MaxCanaryAge).Format(time.RFC3339Nano) || !reflect.DeepEqual(got.ReachableRoutes, []string{"youtube"}) || len(got.ChallengeRoutes) != 0 {
				t.Fatalf("incorrect response grade or timestamps: %+v %v", got, err)
			}
			confirmed := tc.validator
			if (len(got.ConfirmedRoutes) == 1) != confirmed || observations != boolInt(tc.validator) {
				t.Fatal("semantic validator bypassed")
			}
			report := ownedGradeReadback(t, got.CanaryEvidence(), true)
			if !report.OwnedFresh {
				t.Fatal("fresh graded receipt refused")
			}
			assertCheckStatus(t, report, "warp-evidence", "pass")
			want := "warning"
			if confirmed {
				want = "pass"
			}
			assertCheckStatus(t, report, "service-evidence", want)
			if (len(report.Evidence.ConfirmedRoutes) == 1) != confirmed {
				t.Fatal("flat display published reachability as semantic evidence")
			}
		})
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestOwnedServiceSamplingUsesExistingCriteria(t *testing.T) {
	raw := "https://example.com/probe"
	for _, tc := range []struct {
		name, contentType, body string
		expect                  catalog.ProbeExpectation
		pass                    bool
	}{
		{"large-normal-nonJSON", "text/html", strings.Repeat("safe service content ", 3000), catalog.ProbeExpectation{}, true},
		{"truncated-JSON", "application/json", "{\"ok\":true,\"padding\":\"" + strings.Repeat("x", ownedServiceBodyLimit) + "\"}", catalog.ProbeExpectation{JSON: true, JSONFields: []string{"ok"}}, false},
		{"wrong-content-type", "text/plain", "{\"ok\":true}", catalog.ProbeExpectation{JSON: true, ContentTypes: []string{"application/json"}}, false},
		{"frozen-body-marker-missing", "text/plain", "ordinary HTTP 200 content", catalog.ProbeExpectation{BodyContains: []string{"frozen health marker v42"}}, false},
		{"frozen-body-marker-exact", "text/plain", "service: frozen health marker v42", catalog.ProbeExpectation{BodyContains: []string{"frozen health marker v42"}}, true},
		{"frozen-JSON-schema-missing", "application/json", "{\"ok\":true}", catalog.ProbeExpectation{JSON: true, JSONFields: []string{"result.ok"}}, false},
		{"frozen-JSON-schema-exact", "application/json", "{\"result\":{\"ok\":true}}", catalog.ProbeExpectation{JSON: true, JSONFields: []string{"result.ok"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &ownedTrackedBody{Reader: strings.NewReader(tc.body)}
			client := &http.Client{Transport: ownedMemoryRoundTripper(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{tc.contentType}}, Body: body, ContentLength: int64(len(tc.body)), Request: request, TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}}, nil
			})}
			response, err := ownedHTTPSResponse(context.Background(), client, raw, "", ownedServiceBodyLimit, false, true)
			if err != nil || !body.closed || body.read > ownedServiceBodyLimit+1 || response.BodyTruncated != (len(tc.body) > ownedServiceBodyLimit) || len(response.Body) > ownedServiceBodyLimit {
				t.Fatalf("untruthful sample: %+v %v", response, err)
			}
			calls := 0
			service := catalog.Service{ID: "fixture-service", ProbeURL: raw, Domains: []string{"example.com"}, Probes: []catalog.Probe{{URL: raw, Expect: tc.expect}}}
			probe := OwnedServiceProbe{ID: service.ID, URL: raw, Validator: ownedGradeValidator(service, &calls)}
			err = validateOwnedServiceResponse(context.Background(), probe, "", response)
			if (err == nil) != tc.pass || calls != 1 || err != nil && !errors.Is(err, errOwnedNetworkService) {
				t.Fatal("bounded semantic grade incorrect", err)
			}
			if !tc.pass {
				o := ownedFixtureOptions(t)
				o.Network.Services = []OwnedServiceProbe{probe}
				got, probeErr := probeOwnedUSQUE(context.Background(), o, func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
					return ownedFixtureIdentity(), nil
				}, func(context.Context, OwnedNetworkRequest) (OwnedApplicationProof, error) {
					return OwnedApplicationProof{}, err
				}, time.Now)
				requireOwnedProbeError(t, got, probeErr, "owned-network-service-invalid")
			}
		})
	}
}

func TestOwnedChallengeIsSeparateFromSemanticGrade(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	service := OwnedServiceProbe{ID: "fixture-service", URL: "https://example.com/probe", Challenge: true}
	for _, tc := range []struct {
		name            string
		status          int
		body, challenge string
		truncated, pass bool
	}{
		{"exact", 200, TransportChallengeResponse(nonce), nonce, false, true},
		{"wrong", 200, TransportChallengeResponse(strings.Repeat("b", 64)), nonce, false, false},
		{"trailing", 200, TransportChallengeResponse(nonce) + "\n", nonce, false, false},
		{"empty", 200, "", "", false, false},
		{"204", 204, TransportChallengeResponse(nonce), nonce, false, false},
		{"truncated", 200, TransportChallengeResponse(nonce), nonce, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := OwnedServiceResponse{URL: service.URL, HTTPStatus: tc.status, Body: tc.body, BodyTruncated: tc.truncated}
			err := validateOwnedServiceResponse(context.Background(), service, tc.challenge, response)
			if (err == nil) != tc.pass {
				t.Fatal("incorrect challenge validation", err)
			}
			if !tc.pass {
				return
			}
			proof := OwnedApplicationProof{Warp: "on"}
			recordOwnedServiceProof(&proof, service)
			if len(proof.ConfirmedRoutes) != 0 || !reflect.DeepEqual(proof.ChallengeRoutes, []string{service.ID}) {
				t.Fatal("challenge acquired semantic authority")
			}
			e := ownedGradeFixtureEvidence()
			e.ReachableRoutes = proof.ReachableRoutes
			e.ChallengeRoutes = proof.ChallengeRoutes
			report := ownedGradeReadback(t, e.CanaryEvidence(), true)
			assertCheckStatus(t, report, "service-evidence", "warning")
			assertCheckStatus(t, report, "owned-service-challenge", "pass")
			if len(report.Evidence.ConfirmedRoutes) != 0 {
				t.Fatal("challenge published semantic display grade")
			}
			for _, check := range report.Checks {
				if check.ID == "owned-service-challenge" && !strings.Contains(check.Message, "challenge") {
					t.Fatal("challenge wording lost")
				}
			}
		})
	}
}

func TestOwnedProducerRejectsInjectedOrMutatedServiceGrades(t *testing.T) {
	for _, name := range []string{"missing-reachable", "alien-reachable", "duplicate-reachable", "confirmed-without-validator", "missing-semantic", "challenge-without-request", "missing-challenge", "duplicate-confirmed", "confirmed-outside-reachable", "mutated-callback-flags"} {
		t.Run(name, func(t *testing.T) {
			o := ownedFixtureOptions(t)
			if name == "missing-semantic" {
				o.Network.Services[0].Validator = func(OwnedServiceResponse) error { return nil }
			}
			if name == "missing-challenge" {
				o.Network.Services[0].Challenge = true
			}
			captures := 0
			got, err := probeOwnedUSQUE(context.Background(), o, func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
				captures++
				return ownedFixtureIdentity(), nil
			}, func(_ context.Context, request OwnedNetworkRequest) (OwnedApplicationProof, error) {
				proof := OwnedApplicationProof{Warp: "on", ReachableRoutes: []string{"fixture-service"}}
				switch name {
				case "missing-reachable":
					proof.ReachableRoutes = nil
				case "alien-reachable":
					proof.ReachableRoutes = []string{"foreign-service"}
				case "duplicate-reachable":
					proof.ReachableRoutes = append(proof.ReachableRoutes, "fixture-service")
				case "confirmed-without-validator", "mutated-callback-flags":
					proof.ConfirmedRoutes = []string{"fixture-service"}
				case "challenge-without-request":
					proof.ChallengeRoutes = []string{"fixture-service"}
				case "duplicate-confirmed":
					proof.ConfirmedRoutes = []string{"fixture-service", "fixture-service"}
				case "confirmed-outside-reachable":
					proof.ConfirmedRoutes = []string{"foreign-service"}
				}
				if name == "mutated-callback-flags" {
					request.Services[0].Validator = func(OwnedServiceResponse) error { return nil }
				}
				return proof, nil
			}, time.Now)
			requireOwnedProbeError(t, got, err, "owned-probe-service-proof-invalid")
			if captures != 1 || o.Network.Services[0].Validator != nil && name == "mutated-callback-flags" {
				t.Fatal("callback rewrote expected or caller criteria")
			}
		})
	}
}

func TestOwnedReceiptGradeVersionSubsetsAndDisplayFailClosed(t *testing.T) {
	base := ownedGradeFixtureEvidence()
	base.ReachableRoutes = []string{"fixture-service"}
	base.ConfirmedRoutes = []string{"fixture-service"}
	base.ChallengeRoutes = []string{"fixture-service"}
	mutations := map[string]func(*OwnedRuntimeEvidence){
		"old-version":         func(e *OwnedRuntimeEvidence) { e.ServiceProofVersion = 0 },
		"future-version":      func(e *OwnedRuntimeEvidence) { e.ServiceProofVersion = 2 },
		"duplicate-reachable": func(e *OwnedRuntimeEvidence) { e.ReachableRoutes = append(e.ReachableRoutes, e.ReachableRoutes[0]) },
		"unsafe-id":           func(e *OwnedRuntimeEvidence) { e.ReachableRoutes = []string{"private\nsecret"} },
		"too-many": func(e *OwnedRuntimeEvidence) {
			e.ReachableRoutes = nil
			for i := 0; i < 9; i++ {
				e.ReachableRoutes = append(e.ReachableRoutes, fmt.Sprintf("service-%d", i))
			}
		},
		"semantic-outside-reachable":  func(e *OwnedRuntimeEvidence) { e.ConfirmedRoutes = []string{"alien-service"} },
		"challenge-outside-reachable": func(e *OwnedRuntimeEvidence) { e.ChallengeRoutes = []string{"alien-service"} },
		"duplicate-semantic":          func(e *OwnedRuntimeEvidence) { e.ConfirmedRoutes = append(e.ConfirmedRoutes, e.ConfirmedRoutes[0]) },
		"duplicate-challenge":         func(e *OwnedRuntimeEvidence) { e.ChallengeRoutes = append(e.ChallengeRoutes, e.ChallengeRoutes[0]) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := base
			e.ReachableRoutes = append([]string(nil), base.ReachableRoutes...)
			e.ConfirmedRoutes = append([]string(nil), base.ConfirmedRoutes...)
			e.ChallengeRoutes = append([]string(nil), base.ChallengeRoutes...)
			mutate(&e)
			checked, _ := time.Parse(time.RFC3339Nano, e.CheckedAt)
			if safeOwnedEvidence(e) || OwnedEvidenceFresh(e, e.Identity, checked) {
				t.Fatal("unsafe service grade accepted")
			}
			receipt := e.CanaryEvidence()
			receipt.BindingID = CanaryBinding(e.Identity.SessionSHA256, e.Identity.SessionSHA256, e.Identity.BinarySHA256, e.Identity.EnvironmentID)
			receipt.ConfirmedRoutes = []string{"flat-unsafe-semantic"}
			report := ownedGradeReadback(t, receipt, true)
			if report.OwnedFresh || report.OwnedEvidence != nil || len(report.Evidence.ConfirmedRoutes) != 0 || report.Evidence.BindingID != "" {
				t.Fatal("invalid typed receipt fell back to flat grade")
			}
			assertCheckStatus(t, report, "service-evidence", "warning")
		})
	}
	for _, fresh := range []bool{true, false} {
		t.Run(fmt.Sprintf("valid-conflicting-flats-fresh-%t", fresh), func(t *testing.T) {
			receipt := base.CanaryEvidence()
			receipt.BindingID = CanaryBinding(base.Identity.SessionSHA256, base.Identity.SessionSHA256, base.Identity.BinarySHA256, base.Identity.EnvironmentID)
			receipt.ConfirmedRoutes = []string{"flat-unsafe-semantic"}
			receipt.Transport, receipt.Endpoint, receipt.EgressIP = "QUIC", "1.1.1.1:443", "8.8.8.8"
			receipt.CheckedAt = "2026-10-04T00:00:00Z"
			receipt.ValidUntil = "2026-10-04T00:02:00Z"
			report := ownedGradeReadback(t, receipt, fresh)
			if report.OwnedEvidence == nil || report.Evidence.BindingID != "" {
				t.Fatal("valid typed proof acquired legacy binding")
			}
			want := "warning"
			if fresh {
				want = "pass"
			}
			assertCheckStatus(t, report, "service-evidence", want)
			if fresh && !reflect.DeepEqual(report.Evidence.ConfirmedRoutes, base.ConfirmedRoutes) || !fresh && len(report.Evidence.ConfirmedRoutes) != 0 {
				t.Fatal("historical/conflicting flats published as semantic proof")
			}
			if fresh && (report.Evidence.CheckedAt != base.CheckedAt || report.Evidence.ValidUntil != base.ValidUntil || report.Evidence.Transport != base.ProtocolPath || report.Evidence.Endpoint != base.Identity.Endpoint || report.Evidence.EgressIP != base.EgressIP) {
				t.Fatal("typed proof retained conflicting flat metadata or renewed timestamps")
			}
		})
	}
}

func TestOwnedGradedReceiptCopiesAllRouteSlices(t *testing.T) {
	e := ownedGradeFixtureEvidence()
	e.ReachableRoutes = []string{"fixture-service"}
	e.ConfirmedRoutes = []string{"fixture-service"}
	e.ChallengeRoutes = []string{"fixture-service"}
	receipt := e.CanaryEvidence()
	e.ReachableRoutes[0] = "source-mutated"
	e.ConfirmedRoutes[0] = "source-mutated"
	e.ChallengeRoutes[0] = "source-mutated"
	if receipt.Owned.ReachableRoutes[0] != "fixture-service" || receipt.Owned.ConfirmedRoutes[0] != "fixture-service" || receipt.Owned.ChallengeRoutes[0] != "fixture-service" {
		t.Fatal("typed grade aliases source buffers")
	}
	receipt.Owned.ConfirmedRoutes[0] = "owned-mutated"
	if receipt.ConfirmedRoutes[0] != "fixture-service" {
		t.Fatal("typed and flat semantic slices alias")
	}
	receipt.Owned.ConfirmedRoutes[0] = "fixture-service"
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var restored CanaryEvidence
	if err := json.Unmarshal(encoded, &restored); err != nil || restored.Owned == nil || !safeOwnedEvidence(*restored.Owned) {
		t.Fatal("graded receipt roundtrip failed", err)
	}
}

func TestOwnedEnvelopeNullAliasesAndDuplicatesCannotFallbackToLegacy(t *testing.T) {
	e := ownedGradeFixtureEvidence()
	legacy := e.CanaryEvidence()
	legacy.Owned = nil
	legacy.BindingID = CanaryBinding(e.Identity.SessionSHA256, e.Identity.SessionSHA256, e.Identity.BinarySHA256, e.Identity.EnvironmentID)
	legacy.ConfirmedRoutes = []string{"flat-service"}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	checked, _ := time.Parse(time.RFC3339Nano, e.CheckedAt)
	endpoints := Endpoints{H2IPv4: "162.159.193.10"}
	for _, extra := range []string{
		`"owned_runtime":null`,
		`"OWNED_RUNTIME":null`,
		`"Owned_Runtime":` + string(typed),
		`"owned_runtime":` + string(typed) + `,"owned_runtime":null`,
		`"owned_runtime":null,"owned_runtime":` + string(typed),
		`"owned_runtime":` + string(typed) + `,"OWNED_RUNTIME":null`,
	} {
		path := filepath.Join(t.TempDir(), "receipt.json")
		raw := strings.TrimSuffix(string(encoded), "}") + "," + extra + "}"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readCanaryEvidence(path)
		if err != nil || got.Owned != nil || got.BindingID != "" || len(got.ConfirmedRoutes) != 0 {
			t.Fatal("ambiguous typed envelope enabled legacy fallback", err)
		}
		if EvaluateCanaryCapabilities(got, endpoints, legacy.BindingID, checked).Fresh {
			t.Fatal("ambiguous envelope became legacy confirmed capability")
		}
	}
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readCanaryEvidence(path)
	if err != nil || got.BindingID != legacy.BindingID || len(got.ConfirmedRoutes) != 0 || !EvaluateCanaryCapabilities(got, endpoints, legacy.BindingID, checked).Fresh {
		t.Fatal("legacy WARP facts changed or ungraded service fields survived", err)
	}
}

func TestOwnedServiceValidatorErrorsCancellationAndMetadataAreFenced(t *testing.T) {
	for _, name := range []string{"wrong-url", "oversized-body", "callback-error", "callback-cancels"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			callbacks := 0
			service := OwnedServiceProbe{ID: "fixture-service", URL: "https://example.com/probe", Validator: func(OwnedServiceResponse) error {
				callbacks++
				if name == "callback-error" {
					return errors.New("private-validator-secret")
				}
				if name == "callback-cancels" {
					cancel()
				}
				return nil
			}}
			response := OwnedServiceResponse{URL: service.URL, HTTPStatus: 200, Body: "approved"}
			if name == "wrong-url" {
				response.URL = "https://example.com/changed"
			}
			if name == "oversized-body" {
				response.Body = strings.Repeat("x", ownedServiceBodyLimit+1)
			}
			o := ownedFixtureOptions(t)
			o.Network.Services = []OwnedServiceProbe{service}
			got, err := probeOwnedUSQUE(ctx, o, func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
				return ownedFixtureIdentity(), nil
			}, func(ctx context.Context, request OwnedNetworkRequest) (OwnedApplicationProof, error) {
				if err := validateOwnedServiceResponse(ctx, request.Services[0], "", response); err != nil {
					return OwnedApplicationProof{}, err
				}
				proof := OwnedApplicationProof{Warp: "on"}
				recordOwnedServiceProof(&proof, request.Services[0])
				return proof, nil
			}, time.Now)
			want := "owned-network-service-invalid"
			if name == "callback-cancels" {
				want = errOwnedNetworkStopped.Error()
			}
			requireOwnedProbeError(t, got, err, want)
			wantCalls := 1
			if name == "wrong-url" || name == "oversized-body" {
				wantCalls = 0
			}
			if callbacks != wantCalls || strings.Contains(err.Error(), "private") {
				t.Fatal("callback admission or private error fencing failed")
			}
		})
	}
}

func TestOwnedSemanticSuccessCannotSurviveRuntimeOrAdmissionDrift(t *testing.T) {
	for _, name := range []string{"runtime-drift", "admission-revoked"} {
		t.Run(name, func(t *testing.T) {
			o := ownedFixtureOptions(t)
			validated := false
			o.Network.Services[0].Validator = func(OwnedServiceResponse) error { validated = true; return nil }
			o.Authority = func(context.Context) error {
				if validated && name == "admission-revoked" {
					return errors.New("revoked")
				}
				return nil
			}
			captures := 0
			got, err := probeOwnedUSQUE(context.Background(), o, func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
				captures++
				identity := ownedFixtureIdentity()
				if validated && name == "runtime-drift" {
					identity.EnvironmentID = strings.Repeat("b", 64)
					identity.BindingID = ownedIdentityBinding(identity)
				}
				return identity, nil
			}, func(ctx context.Context, request OwnedNetworkRequest) (OwnedApplicationProof, error) {
				if captures != 1 {
					t.Fatal("semantic callback outside identity bracket")
				}
				response := OwnedServiceResponse{URL: request.Services[0].URL, HTTPStatus: 200, Body: "approved"}
				if err := validateOwnedServiceResponse(ctx, request.Services[0], "", response); err != nil {
					return OwnedApplicationProof{}, err
				}
				proof := OwnedApplicationProof{Warp: "on"}
				recordOwnedServiceProof(&proof, request.Services[0])
				return proof, nil
			}, time.Now)
			want := "owned-probe-runtime-changed"
			if name == "admission-revoked" {
				want = "owned-probe-admission-refused"
			}
			requireOwnedProbeError(t, got, err, want)
			if !validated || captures != 2 {
				t.Fatal("semantic grade skipped current runtime/admission re-read")
			}
		})
	}
}
