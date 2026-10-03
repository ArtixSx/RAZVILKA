package providerfeed

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func publisherRefillFixture(t *testing.T) (*Manager, []string, string) {
	t.Helper()
	m, _, path := persistentManager(t)
	var ids []string
	for _, preset := range []string{"igareck-reality-mobile", "igareck-black-vless", "kort0881-ru-sni"} {
		v, err := m.Save(context.Background(), "", SaveRequest{Request: Request{PresetID: preset, Limit: 32}, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, v.SourceID)
		c := m.states[v.SourceID]
		c.state.LastAttemptAt = testTime.Add(-20 * time.Minute)
		c.state.NextRefreshAt = testTime.Add(time.Hour)
		m.states[v.SourceID] = c
	}
	if err := m.persistLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.jobs = jobState{started: true, entries: map[string]*jobEntry{}, wake: make(chan struct{}, 1)}
	return m, ids, path
}

func TestRefillPublisherCollectionsShareAgeAndDoNotMultiplyUtility(t *testing.T) {
	for _, scenario := range []string{"max-not-sum", "sibling-untried", "sibling-aged", "ready-before-cooldown", "cooldown-credit-not-transferred", "not-allowed", "disabled"} {
		t.Run(scenario, func(t *testing.T) {
			m, ids, _ := publisherRefillFixture(t)
			useful := map[string]int{ids[0]: 2, ids[1]: 2, ids[2]: 3}
			allowed, want := ids, ids[2]
			a, b := m.states[ids[0]], m.states[ids[1]]
			switch scenario {
			case "sibling-untried":
				b.state.LastAttemptAt = time.Time{}
			case "sibling-aged":
				b.state.LastAttemptAt = testTime.Add(-2 * time.Hour)
			case "ready-before-cooldown":
				a.state.RetryAfterAt = testTime.Add(time.Hour)
				b.state.RetryAfterAt = testTime.Add(time.Hour)
				useful[ids[0]], useful[ids[1]] = 512, 512
			case "cooldown-credit-not-transferred":
				a.state.RetryAfterAt = testTime.Add(time.Hour)
				useful[ids[0]], useful[ids[1]] = 512, 0
			case "not-allowed":
				allowed = ids[:2]
				useful[ids[2]] = 512
				want = ids[0]
			case "disabled":
				m.storage.doc.Sources[m.sourceIndexLocked(ids[2])].Enabled = false
				useful[ids[2]] = 512
				want = ids[0]
			}
			m.states[ids[0]], m.states[ids[1]] = a, b
			if scenario == "not-allowed" || scenario == "disabled" {
				// Within one publisher, the deterministic source-ID order wins.
				if ids[1] < want {
					want = ids[1]
				}
			}
			d, err := m.RequestRefillRanked(context.Background(), allowed, useful)
			if err != nil || d.State != "queued" || d.SourceID != want || len(m.jobs.queue) != 1 {
				t.Fatal("publisher duplicated age/quota or ignored readiness/allowlist", d, err)
			}
		})
	}
}

func TestRefillPublisherAgeAndDeterministicOrderSurviveRestart(t *testing.T) {
	m, ids, path := publisherRefillFixture(t)
	// An untried sibling does not make a recently tried repository untried.
	c := m.states[ids[1]]
	c.state.LastAttemptAt = time.Time{}
	m.states[ids[1]] = c
	if err := m.persistLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	nodes := m.nodes
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(nodes, path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.now = func() time.Time { return testTime }
	next.jobs = jobState{started: true, entries: map[string]*jobEntry{}, wake: make(chan struct{}, 1)}
	d, err := next.RequestRefillRanked(context.Background(), ids, map[string]int{ids[0]: 2, ids[1]: 2, ids[2]: 3})
	if err != nil || d.SourceID != ids[2] {
		t.Fatal("restart reset publisher age", d, err)
	}
	// Repeated demand joins the durable worker job, without quota expansion.
	d2, err := next.RequestRefillRanked(context.Background(), []string{ids[1], ids[2], ids[0]}, nil)
	if err != nil || !reflect.DeepEqual(d, d2) || len(next.jobs.entries) != 1 {
		t.Fatal("polling duplicated refill", d2, err)
	}
}

func TestRefillPublisherKeysUseTrustedCatalogueOnly(t *testing.T) {
	a := subscription{ID: "a", Request: Request{PresetID: "igareck-reality-mobile"}}
	b := subscription{ID: "b", Request: Request{PresetID: "igareck-black-vless"}}
	if refillPublisherKey(a) != refillPublisherKey(b) {
		t.Fatal("known repository collections not grouped")
	}
	a.Request = Request{URL: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/private-token?secret=a"}
	b.Request = Request{URL: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/private-token?secret=b"}
	if refillPublisherKey(a) != "source:a" || refillPublisherKey(b) != "source:b" {
		t.Fatal("custom URL became a publisher/operator claim")
	}
}
