package dnscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDraftPersistsWithoutChangingApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetDraft("ad-block"); err != nil {
		t.Fatal(err)
	}
	snapshot := m.Snapshot()
	if !snapshot.Dirty || snapshot.Draft.ProfileID != "ad-block" || snapshot.Applied.ProfileID != "automatic" || snapshot.Mode != "preview" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Snapshot().Draft.ProfileID != "ad-block" {
		t.Fatal("draft did not persist")
	}
}

func TestRejectsUnknownProfile(t *testing.T) {
	m, _ := New("")
	if err := m.SetDraft("unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if _, err := m.Probe(context.Background(), "unknown"); err == nil {
		t.Fatal("unknown profile probe accepted")
	}
}

func TestCatalogHasUsefulProfiles(t *testing.T) {
	wanted := map[string]bool{"ad-block": false, "family": false, "security": false, "private": false, "nextdns": false, "quad9-unfiltered": false, "quad9-secure-ecs": false, "quad9-unfiltered-ecs": false, "controld-unfiltered": false, "controld-uncensored": false, "xbox-dns": false, "uncensoreddns": false, "flashstart": false}
	for _, profile := range Profiles() {
		if _, ok := wanted[profile.ID]; ok {
			wanted[profile.ID] = true
		}
	}
	for id, found := range wanted {
		if !found {
			t.Fatalf("missing profile %s", id)
		}
	}
}

func TestRequestedDNSProvidersCarrySafetyMetadata(t *testing.T) {
	wanted := map[string]bool{"quad9": false, "quad9-unfiltered": false, "quad9-secure-ecs": false, "quad9-unfiltered-ecs": false, "controld-unfiltered": false, "controld-uncensored": false, "xbox-dns": false, "cloudflare": false, "google": false, "uncensoreddns": false, "flashstart": false}
	for _, provider := range Providers() {
		if _, ok := wanted[provider.ID]; ok {
			wanted[provider.ID] = true
		}
		if provider.ID == "uncensoreddns" && (len(provider.Servers) != 0 || !provider.EncryptedOnly || len(provider.Warnings) == 0 || !strings.Contains(provider.Warnings[0], "UDP/TCP")) {
			t.Fatal("UncensoredDNS is not encrypted-only")
		}
		if provider.ID == "flashstart" && (provider.USQUERegistration != "blocked" || provider.Scope != "negative-control" || provider.AllowedForUSQUE || provider.AllowedForAutoPilot || len(provider.Warnings) == 0) {
			t.Fatal("FlashStart is not blocked for USQUE registration")
		}
		if provider.ID != "system" && provider.Configured && len(provider.Endpoints) == 0 {
			t.Fatalf("provider %s has no typed endpoints", provider.ID)
		}
	}
	for id, found := range wanted {
		if !found {
			t.Fatalf("missing provider %s", id)
		}
	}
}

func TestQuad9AlternatePortsAreSeparateDiagnosticEndpoints(t *testing.T) {
	provider, _ := providerByIDFor("quad9", document{})
	foundPlaintext := false
	foundTLS := false
	for _, endpoint := range provider.Endpoints {
		if endpoint.Scope != "diagnostic" {
			continue
		}
		if (endpoint.Transport == "udp" || endpoint.Transport == "tcp") && endpoint.Port == 9953 {
			foundPlaintext = true
		}
		if endpoint.Transport == "dot" && endpoint.Port == 8853 {
			foundTLS = true
		}
	}
	if !foundPlaintext || !foundTLS {
		t.Fatalf("Quad9 diagnostic endpoints are incomplete: %+v", provider.Endpoints)
	}
}

func TestServiceDNSDraftPersistsAndNeverAppliesWithoutAdapter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetServiceDraft("telegram", "controld-uncensored"); err != nil {
		t.Fatal(err)
	}
	snapshot := m.Snapshot()
	if !snapshot.Dirty || snapshot.ServiceDrafts["telegram"] != "controld-uncensored" || len(snapshot.ServiceApplied) != 0 {
		t.Fatalf("unexpected service DNS draft: %+v", snapshot)
	}
	if m.Plan("").Ready {
		t.Fatal("per-service DNS plan became ready without an adapter")
	}
	if err := m.Apply(); err == nil {
		t.Fatal("per-service DNS draft was applied without an adapter")
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Snapshot().ServiceDrafts["telegram"] != "controld-uncensored" {
		t.Fatal("service DNS draft did not persist")
	}
	if err := reloaded.SetServiceDraft("telegram", "inherit"); err != nil {
		t.Fatal(err)
	}
	if _, exists := reloaded.Snapshot().ServiceDrafts["telegram"]; exists {
		t.Fatal("inherit did not remove service DNS draft")
	}
}

func TestServiceDNSDraftRejectsUnknownValues(t *testing.T) {
	m, _ := New("")
	if err := m.SetServiceDraft("bad/service", "private"); err == nil {
		t.Fatal("invalid service ID accepted")
	}
	if err := m.SetServiceDraft("telegram", "missing-profile"); err == nil {
		t.Fatal("unknown DNS profile accepted")
	}
}

func TestNextDNSRequiresValidatedProfileID(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetDraft("nextdns"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Probe(context.Background(), "nextdns"); err == nil {
		t.Fatal("unconfigured NextDNS was probed")
	}
	configurationBlocked := false
	for _, check := range m.Plan("").Checks {
		if check.ID == "configuration" && check.Status == "fail" {
			configurationBlocked = true
		}
	}
	if !configurationBlocked {
		t.Fatal("unconfigured NextDNS plan has no configuration blocker")
	}
	if err := m.SetNextDNSProfileID("wrong-id"); err == nil {
		t.Fatal("invalid NextDNS ID accepted")
	}
	if err := m.SetNextDNSProfileID("a1b2c3"); err != nil {
		t.Fatal(err)
	}
	snapshot := m.Snapshot()
	if snapshot.NextDNSProfileID != "a1b2c3" {
		t.Fatalf("profile ID = %q", snapshot.NextDNSProfileID)
	}
	provider, ok := providerByIDFor("nextdns", m.doc)
	if !ok || !provider.Configured || provider.DoH != "https://dns.nextdns.io/a1b2c3" || provider.DoT != "a1b2c3.dns.nextdns.io:853" {
		t.Fatalf("configured NextDNS = %+v", provider)
	}
	if err := m.SetNextDNSProfileID(""); err != nil || m.Snapshot().NextDNSProfileID != "" {
		t.Fatalf("NextDNS ID was not cleared: %v", err)
	}
}

func TestCustomDNSProviderIsNormalizedAndDraftOnly(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetDraft("custom"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Probe(context.Background(), "custom"); err == nil {
		t.Fatal("unconfigured custom DNS was probed")
	}
	input := CustomProviderInput{
		Name:    "Домашний DNS",
		Servers: []string{"9.9.9.9", "9.9.9.9:53", "2001:4860:4860::8888"},
		DoH:     "https://dns.example/dns-query",
		DoT:     "dns.example",
	}
	if err := m.SetCustomProvider(input); err != nil {
		t.Fatal(err)
	}
	provider, ok := providerByIDFor("custom", m.doc)
	if !ok || !provider.Configured || len(provider.Servers) != 2 || provider.Servers[0] != "9.9.9.9:53" || provider.Servers[1] != "[2001:4860:4860::8888]:53" || provider.DoT != "dns.example:853" {
		t.Fatalf("custom provider = %+v", provider)
	}
	if m.Snapshot().Applied.ProfileID != "automatic" {
		t.Fatal("custom DNS changed applied selection")
	}
	if err := m.ClearCustomProvider(); err != nil {
		t.Fatal(err)
	}
	provider, _ = providerByIDFor("custom", m.doc)
	if provider.Configured {
		t.Fatal("custom DNS was not cleared")
	}
}

func TestCustomDNSRejectsUnsafeEndpoints(t *testing.T) {
	m, _ := New("")
	invalid := []CustomProviderInput{
		{DoH: "http://dns.example/dns-query"},
		{DoH: "https://user:pass@dns.example/dns-query"},
		{DoH: "https://dns.example/dns-query?token=secret"},
		{Servers: []string{"9.9.9.9:http"}},
		{DoT: "dns.example:70000"},
		{Servers: []string{"127.0.0.1"}},
		{Servers: []string{"192.168.1.1"}},
		{Servers: []string{"169.254.1.1"}},
		{Servers: []string{"0.0.0.0"}},
		{Servers: []string{"224.0.0.1"}},
		{DoH: "https://[::1]/dns-query"},
	}
	for _, input := range invalid {
		if err := m.SetCustomProvider(input); err == nil {
			t.Fatalf("unsafe custom DNS accepted: %+v", input)
		}
	}
}

func TestCustomDNSTrustedLocalRequiresExplicitOptIn(t *testing.T) {
	m, _ := New("")
	if err := m.SetCustomProvider(CustomProviderInput{Name: "LAN DNS", Servers: []string{"192.168.1.2"}, TrustedLocal: true}); err != nil {
		t.Fatal(err)
	}
	provider, _ := providerByIDFor("custom", m.doc)
	if !provider.TrustedLocal || provider.Scope != "trusted-local" || provider.AllowedForUSQUE || provider.AllowedForAutoPilot {
		t.Fatalf("unexpected trusted-local policy: %+v", provider)
	}
}

func TestPlanRefusesToReplaceExistingRouterDNS(t *testing.T) {
	m, _ := New("")
	if err := m.SetDraft("ad-block"); err != nil {
		t.Fatal(err)
	}
	plan := m.Plan("Keenetic ndnproxy: udp :53")
	if plan.Ready || plan.Listener == "" || len(plan.Steps) < 6 {
		t.Fatalf("unsafe DNS plan = %+v", plan)
	}
	foundOwnership := false
	for _, check := range plan.Checks {
		if check.ID == "ownership" && check.Status == "fail" {
			foundOwnership = true
		}
	}
	if !foundOwnership {
		t.Fatalf("ownership gate missing: %+v", plan.Checks)
	}
}

func TestAutomaticDNSPlanRequiresNoLiveChange(t *testing.T) {
	m, _ := New("")
	plan := m.Plan("Keenetic ndnproxy: udp :53")
	if !plan.Ready || plan.Profile.ID != "automatic" {
		t.Fatalf("automatic plan = %+v", plan)
	}
}

func TestApplyRefusesNonSystemProfileAndPreservesDraft(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetDraft("ad-block"); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(); err == nil {
		t.Fatal("filtering DNS was applied without a platform adapter")
	}
	snapshot := m.Snapshot()
	if !snapshot.Dirty || snapshot.Draft.ProfileID != "ad-block" || snapshot.Applied.ProfileID != "automatic" {
		t.Fatalf("blocked DNS draft was not preserved: %+v", snapshot)
	}
}

func TestApplyConfirmsAutomaticProfileWithoutNetworkClaim(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.doc.Applied = Selection{ProfileID: "ad-block"}
	m.doc.Draft = Selection{ProfileID: "automatic"}
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if snapshot := m.Snapshot(); snapshot.Dirty || snapshot.Applied.ProfileID != "automatic" {
		t.Fatalf("automatic DNS was not confirmed: %+v", snapshot)
	}
}

func TestDNSQueryAndResponseValidation(t *testing.T) {
	query, err := buildDNSQuery(4242)
	if err != nil {
		t.Fatal(err)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil || header.ID != 4242 || !header.RecursionDesired {
		t.Fatalf("query header = %+v, err = %v", header, err)
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0].Name.String() != "cloudflare.com." {
		t.Fatalf("questions = %+v, err = %v", questions, err)
	}
	if err := parser.SkipAllAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := parser.SkipAllAuthorities(); err != nil {
		t.Fatal(err)
	}
	ednsHeader, err := parser.AdditionalHeader()
	if err != nil || ednsHeader.Type != dnsmessage.TypeOPT || !ednsHeader.DNSSECAllowed() {
		t.Fatalf("EDNS header = %+v, err = %v", ednsHeader, err)
	}

	name := dnsmessage.MustNewName("cloudflare.com.")
	responseBuilder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4242, Response: true, RecursionAvailable: true, AuthenticData: true})
	if err := responseBuilder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := responseBuilder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := responseBuilder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := responseBuilder.AResource(dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}); err != nil {
		t.Fatal(err)
	}
	response, err := responseBuilder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	addresses, authenticated, err := validateDNSResponse(query, response)
	if err != nil || addresses != 1 || !authenticated {
		t.Fatalf("addresses = %d, authenticated = %t, err = %v", addresses, authenticated, err)
	}
}

func TestDNSResponseMustMatchQuery(t *testing.T) {
	query, err := buildDNSQuery(11)
	if err != nil {
		t.Fatal(err)
	}
	response, err := buildDNSQuery(12)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateDNSResponse(query, response); err == nil {
		t.Fatal("mismatched non-response packet accepted")
	}
}

func TestDNSSECResultIsExplainedInPlan(t *testing.T) {
	m, _ := New("")
	if err := m.SetDraft("private"); err != nil {
		t.Fatal(err)
	}
	m.doc.ProbeProfileID = "private"
	m.doc.LastProbe = []ProbeResult{{Server: "https://cloudflare-dns.com/dns-query", Transport: "DoH", Status: "pass", DNSSEC: "resolver-reported-ad", Addresses: 2}}
	found := false
	for _, check := range m.Plan("").Checks {
		if check.ID == "dnssec" && check.Status == "pass" && strings.Contains(check.Message, "AD-флаг") && !strings.Contains(check.Message, "DNSSEC подтверждён") {
			found = true
		}
	}
	if !found {
		t.Fatal("resolver-reported AD bit was not explained honestly in the plan")
	}
}

func TestSchemaThreeMigrationClearsUncensoredPlaintextEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	legacy := document{
		Schema: 3,
		Draft:  Selection{ProfileID: "uncensoreddns"}, Applied: Selection{ProfileID: "automatic"},
		ProbeProfileID: "uncensoreddns", ProbedAt: "2026-08-27T12:00:00Z",
		LastProbe:     []ProbeResult{{Server: "91.239.100.100:53", Transport: "UDP", Status: "pass", DNSSEC: "confirmed"}},
		ServiceDrafts: map[string]string{}, ServiceApplied: map[string]string{},
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := m.Snapshot()
	if snapshot.Schema != schema || snapshot.ProbeProfileID != "" || snapshot.ProbedAt != "" || len(snapshot.LastProbe) != 0 || len(snapshot.MigrationWarnings) != 1 {
		t.Fatalf("unexpected migrated snapshot: %+v", snapshot)
	}
	var persisted document
	contents, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(contents, &persisted) != nil || persisted.Schema != schema {
		t.Fatalf("migration was not persisted: %v, %s", err, contents)
	}
}

func TestSchemaThreeMigrationRenamesDNSSECEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	legacy := document{Schema: 3, Draft: Selection{ProfileID: "private"}, Applied: Selection{ProfileID: "automatic"}, ProbeProfileID: "private", LastProbe: []ProbeResult{{Transport: "DoH", Status: "pass", DNSSEC: "confirmed"}}, ServiceDrafts: map[string]string{}, ServiceApplied: map[string]string{}}
	encoded, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Snapshot().LastProbe[0].DNSSEC; got != "resolver-reported-ad" {
		t.Fatalf("DNSSEC evidence = %q", got)
	}
}

func TestDoHRedirectPolicy(t *testing.T) {
	initial, _ := url.Parse("https://dns.example/dns-query")
	policy := dohRedirectPolicy(initial, nil)
	request := func(raw string) *http.Request {
		parsed, _ := url.Parse(raw)
		return &http.Request{URL: parsed}
	}
	if err := policy(request("https://dns.example/next"), []*http.Request{request(initial.String())}); err != nil {
		t.Fatalf("same-origin redirect rejected: %v", err)
	}
	if err := policy(request("http://dns.example/next"), []*http.Request{request(initial.String())}); err == nil {
		t.Fatal("HTTPS downgrade accepted")
	}
	if err := policy(request("https://other.example/next"), []*http.Request{request(initial.String())}); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}
	via := []*http.Request{request(initial.String()), request("https://dns.example/one"), request("https://dns.example/two")}
	if err := policy(request("https://dns.example/three"), via); err == nil {
		t.Fatal("third redirect accepted")
	}
	allowed := dohRedirectPolicy(initial, map[string]struct{}{"allowed.example": {}})
	if err := allowed(request("https://allowed.example/next"), []*http.Request{request(initial.String())}); err != nil {
		t.Fatalf("allowlisted origin rejected: %v", err)
	}
}

func TestPublicDNSAddressPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "192.0.2.1", "224.0.0.1", "::", "::1", "fe80::1", "2001:db8::1"} {
		if publicDNSAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("non-public address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"} {
		if !publicDNSAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("public address rejected: %s", raw)
		}
	}
}

func TestProbeTimeoutMessageUsesActualTimeout(t *testing.T) {
	message := friendlyProbeError(context.DeadlineExceeded, endpointProbeTimeout)
	if !strings.Contains(message, "5 сек.") || strings.Contains(message, "4 сек") {
		t.Fatalf("unexpected timeout message: %q", message)
	}
	if message := friendlyProbeError(errors.New("timeout"), 7*time.Second); !strings.Contains(message, "7 сек.") {
		t.Fatalf("custom timeout ignored: %q", message)
	}
}

func TestDNSTLSNeverDisablesCertificateVerification(t *testing.T) {
	configuration := dnsTLSConfig("dns.example")
	if configuration.InsecureSkipVerify || configuration.ServerName != "dns.example" || configuration.MinVersion < 0x0303 {
		t.Fatalf("unsafe TLS configuration: %+v", configuration)
	}
}
