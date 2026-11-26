package recipehints

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func fixture(t *testing.T) (Document, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	r := Recipe{Schema: 1, ServiceID: "youtube", Scenario: "web", ProviderID: "cloudflare", TrafficClass: "nfqws2", StrategyID: "tls-modern-1", CompatibilityID: "nfqws2-v1", Family: "ipv4", ResolutionActor: "router", DNSRequestPath: "system"}
	h, _ := r.Hash()
	d := Document{Schema: 1, Sequence: 5, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Recipes: []Aggregate{{Recipe: r, Hash: h, Successes: 90, Failures: 10, Installations: 10, ObservedAt: now.Add(-2 * time.Hour)}}, Revoked: []string{}}
	return d, pub, priv, now
}
func signed(t *testing.T, d Document, key ed25519.PrivateKey) []byte {
	t.Helper()
	b, e := json.Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	out, e := json.Marshal(Envelope{KeyID: "release-1", Payload: b, Signature: ed25519.Sign(key, b)})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestVerifyCatalog(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Document)
		pass   bool
	}{
		{"valid", func(*Document) {}, true},
		{"wrong-schema", func(d *Document) { d.Schema = 2 }, false},
		{"rollback", func(d *Document) { d.Sequence = 3 }, false},
		{"zero-sequence", func(d *Document) { d.Sequence = 0 }, false},
		{"expired", func(d *Document) { d.ExpiresAt = d.IssuedAt }, false},
		{"future", func(d *Document) { d.IssuedAt = d.ExpiresAt }, false},
		{"unbounded-validity", func(d *Document) { d.ExpiresAt = d.IssuedAt.Add(8 * 24 * time.Hour) }, false},
		{"hash-mismatch", func(d *Document) { d.Recipes[0].Hash = "bad" }, false},
		{"duplicate-record", func(d *Document) { d.Recipes = append(d.Recipes, d.Recipes[0]) }, false},
		{"fake-installations", func(d *Document) { d.Recipes[0].Installations = 500 }, false},
		{"large-count", func(d *Document) { d.Recipes[0].Successes = 1000001 }, false},
		{"old-observation", func(d *Document) { d.Recipes[0].ObservedAt = d.IssuedAt.Add(-31 * 24 * time.Hour) }, false},
		{"future-observation", func(d *Document) { d.Recipes[0].ObservedAt = d.ExpiresAt }, false},
		{"bad-revocation", func(d *Document) { d.Revoked = []string{"no"} }, false},
		{"too-many", func(d *Document) {
			for len(d.Recipes) < 257 {
				d.Recipes = append(d.Recipes, d.Recipes[0])
			}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, pub, key, now := fixture(t)
			c.mutate(&d)
			v, e := Verify(signed(t, d, key), map[string]ed25519.PublicKey{"release-1": pub}, 4, now)
			if (e == nil) != c.pass {
				t.Fatalf("pass=%v error=%v", c.pass, e)
			}
			if c.pass && v.Sequence() != 5 {
				t.Fatal(v.Sequence())
			}
		})
	}
}
func TestSignatureAndParserBoundaries(t *testing.T) {
	d, pub, key, now := fixture(t)
	base := signed(t, d, key)
	for _, test := range []struct {
		name string
		data []byte
		keys map[string]ed25519.PublicKey
	}{
		{"no-key", base, nil}, {"malformed", []byte("{"), nil}, {"empty", nil, nil},
		{"oversize", bytes.Repeat([]byte(" "), MaxCatalogBytes+1), nil},
		{"trailing", append(append([]byte{}, base...), []byte("{}")...), map[string]ed25519.PublicKey{"release-1": pub}},
		{"unknown-key", base, map[string]ed25519.PublicKey{"different": pub}},
		{"tampered", bytes.Replace(base, []byte(`"sequence":5`), []byte(`"sequence":6`), 1), map[string]ed25519.PublicKey{"release-1": pub}},
		{"unknown-field", append([]byte(`{"unexpected":true,`), base[1:]...), map[string]ed25519.PublicKey{"release-1": pub}},
		{"duplicate-field", append([]byte(`{"key_id":"release-1",`), base[1:]...), map[string]ed25519.PublicKey{"release-1": pub}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, e := Verify(test.data, test.keys, 4, now); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestRecipeIdentity(t *testing.T) {
	d, _, _, _ := fixture(t)
	r := d.Recipes[0].Recipe
	original, _ := r.Hash()
	changes := []struct {
		name   string
		change func(*Recipe)
		valid  bool
	}{
		{"family", func(r *Recipe) { r.Family = "ipv6" }, true}, {"provider", func(r *Recipe) { r.ProviderID = "xbox-dns" }, true},
		{"scenario", func(r *Recipe) { r.Scenario = "video" }, true}, {"actor", func(r *Recipe) { r.ResolutionActor = "engine" }, true},
		{"dns-query-path", func(r *Recipe) { r.DNSRequestPath = "traffic-path" }, true}, {"compatibility", func(r *Recipe) { r.CompatibilityID = "nfqws2-v2" }, true},
		{"strategy", func(r *Recipe) { r.StrategyID = "tls-modern-2" }, true}, {"service", func(r *Recipe) { r.ServiceID = "custom-site" }, true},
		{"shell", func(r *Recipe) { r.StrategyID = "abc;reboot" }, false}, {"url-secret", func(r *Recipe) { r.ProviderID = "https://key.example" }, false},
		{"invalid-family", func(r *Recipe) { r.Family = "auto" }, false}, {"remote-nfqws", func(r *Recipe) { r.ResolutionActor = "remote-proxy" }, false},
		{"unknown-actor", func(r *Recipe) { r.ResolutionActor = "cloud" }, false},
	}
	for _, c := range changes {
		t.Run(c.name, func(t *testing.T) {
			copy := r
			c.change(&copy)
			h, e := copy.Hash()
			if (e == nil) != c.valid {
				t.Fatalf("%v", e)
			}
			if c.valid && h == original {
				t.Fatal("identity lost an effective field")
			}
		})
	}
}
func TestShortlistNeverGrantsAuthority(t *testing.T) {
	d, pub, key, now := fixture(t)
	v, e := Verify(signed(t, d, key), map[string]ed25519.PublicKey{"release-1": pub}, 4, now)
	if e != nil {
		t.Fatal(e)
	}
	ctx := Context{ServiceID: "youtube", Scenario: "web", CompatibilityID: "nfqws2-v1", Family: "ipv4"}
	p := Policy{AllowedProviders: map[string]bool{"cloudflare": true}, AllowedTraffic: map[string]bool{"nfqws2": true}, AllowedStrategies: map[string]bool{"tls-modern-1": true}, Limit: 3}
	rows := v.Shortlist(ctx, p, now)
	if len(rows) != 1 || rows[0].EligibleForApply || !rows[0].LocalCheckRequired {
		t.Fatalf("%+v", rows)
	}
	for _, c := range []struct {
		name   string
		change func(*Context, *Policy)
		clock  time.Time
	}{
		{"no-provider-consent", func(_ *Context, p *Policy) { p.AllowedProviders = nil }, now},
		{"no-engine-consent", func(_ *Context, p *Policy) { p.AllowedTraffic = nil }, now},
		{"unknown-local-strategy", func(_ *Context, p *Policy) { p.AllowedStrategies = nil }, now},
		{"wrong-service", func(c *Context, _ *Policy) { c.ServiceID = "gemini" }, now},
		{"wrong-scenario", func(c *Context, _ *Policy) { c.Scenario = "video" }, now},
		{"wrong-family", func(c *Context, _ *Policy) { c.Family = "ipv6" }, now},
		{"wrong-engine-version", func(c *Context, _ *Policy) { c.CompatibilityID = "nfqws2-v2" }, now},
		{"expired-catalog", func(*Context, *Policy) {}, now.Add(2 * time.Hour)},
		{"clock-backwards", func(*Context, *Policy) {}, now.Add(-2 * time.Hour)},
		{"unbounded-limit", func(_ *Context, p *Policy) { p.Limit = 100 }, now},
	} {
		t.Run(c.name, func(t *testing.T) {
			cc, pp := ctx, p
			c.change(&cc, &pp)
			if len(v.Shortlist(cc, pp, c.clock)) != 0 {
				t.Fatal("policy bypass")
			}
		})
	}
	d.Revoked = []string{d.Recipes[0].Hash}
	v, _ = Verify(signed(t, d, key), map[string]ed25519.PublicKey{"release-1": pub}, 4, now)
	if len(v.Shortlist(ctx, p, now)) != 0 {
		t.Fatal("revoked candidate allowed")
	}
	if len((Verified{}).Shortlist(ctx, p, now)) != 0 {
		t.Fatal("unsigned catalog allowed")
	}
}
func TestSparseHintsAreNotRecommendations(t *testing.T) {
	d, pub, key, now := fixture(t)
	d.Recipes[0].Installations = 1
	d.Recipes[0].Successes = 1
	d.Recipes[0].Failures = 0
	v, e := Verify(signed(t, d, key), map[string]ed25519.PublicKey{"release-1": pub}, 4, now)
	if e != nil {
		t.Fatal(e)
	}
	p := Policy{AllowedProviders: map[string]bool{"cloudflare": true}, AllowedTraffic: map[string]bool{"nfqws2": true}, AllowedStrategies: map[string]bool{"tls-modern-1": true}, Limit: 3}
	if len(v.Shortlist(Context{ServiceID: "youtube", Scenario: "web", CompatibilityID: "nfqws2-v1", Family: "ipv4"}, p, now)) > 0 {
		t.Fatal("one report promoted")
	}
}

func TestShortlistRankingIsDeterministicAndBounded(t *testing.T) {
	d, pub, key, now := fixture(t)
	base := d.Recipes[0]
	strategies := map[string]bool{}
	for _, spec := range []struct {
		id               string
		pass, fail, inst uint32
		cohort           string
		age              time.Duration
	}{
		{"recent", 90, 10, 10, "", 2 * time.Hour},
		{"old", 95, 5, 10, "", 7 * 24 * time.Hour},
		{"relevant", 90, 10, 10, "isp-a", 2 * time.Hour},
		{"other-cohort", 99, 1, 10, "isp-b", 2 * time.Hour},
		{"all-failed", 0, 20, 10, "", 2 * time.Hour},
	} {
		a := base
		a.Recipe.StrategyID = spec.id
		a.Hash, _ = a.Recipe.Hash()
		a.Successes = spec.pass
		a.Failures = spec.fail
		a.Installations = spec.inst
		a.Cohort = spec.cohort
		a.ObservedAt = now.Add(-spec.age)
		d.Recipes = append(d.Recipes, a)
		strategies[spec.id] = true
	}
	p := Policy{AllowedProviders: map[string]bool{"cloudflare": true}, AllowedTraffic: map[string]bool{"nfqws2": true}, AllowedStrategies: strategies, Limit: 2}
	v, err := Verify(signed(t, d, key), map[string]ed25519.PublicKey{"release-1": pub}, 4, now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context{ServiceID: "youtube", Scenario: "web", CompatibilityID: "nfqws2-v1", Family: "ipv4", Cohort: "isp-a"}
	for i := 0; i < 20; i++ {
		out := v.Shortlist(ctx, p, now)
		if len(out) != 2 || out[0].Recipe.StrategyID != "relevant" || out[1].Recipe.StrategyID != "recent" {
			t.Fatalf("wrong ordering %+v", out)
		}
	}
}

func TestRemoteResolutionIsNeverAssumedControllable(t *testing.T) {
	d, pub, key, now := fixture(t)
	r := &d.Recipes[0].Recipe
	r.TrafficClass = "xray"
	r.StrategyID = ""
	r.ResolutionActor = "remote-proxy"
	d.Recipes[0].Hash, _ = r.Hash()
	v, err := Verify(signed(t, d, key), map[string]ed25519.PublicKey{"release-1": pub}, 4, now)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Shortlist(Context{ServiceID: "youtube", Scenario: "web", CompatibilityID: "nfqws2-v1", Family: "ipv4"}, Policy{AllowedProviders: map[string]bool{"cloudflare": true}, AllowedTraffic: map[string]bool{"xray": true}, Limit: 3}, now)
	if len(out) != 0 {
		t.Fatal("assumed ownership of remote DNS")
	}
}
