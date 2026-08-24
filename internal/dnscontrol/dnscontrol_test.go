package dnscontrol

import (
	"context"
	"path/filepath"
	"testing"

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
	wanted := map[string]bool{"ad-block": false, "family": false, "security": false, "private": false, "nextdns": false}
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
	if err != nil || len(questions) != 1 || questions[0].Name.String() != "example.com." {
		t.Fatalf("questions = %+v, err = %v", questions, err)
	}

	name := dnsmessage.MustNewName("example.com.")
	responseBuilder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4242, Response: true, RecursionAvailable: true})
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
	addresses, err := validateDNSResponse(query, response)
	if err != nil || addresses != 1 {
		t.Fatalf("addresses = %d, err = %v", addresses, err)
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
	if _, err := validateDNSResponse(query, response); err == nil {
		t.Fatal("mismatched non-response packet accepted")
	}
}
