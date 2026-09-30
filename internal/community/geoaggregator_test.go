package community

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const geoCatalogFixture = `{"version":1,"generated":"2026-09-29T09:28:21Z","base":"https://raw.githubusercontent.com/Ground-Zerro/Geo-Aggregator/main/",
"categories":[{"id":"messengers","name":"Мессенджеры и почта"},{"id":"media","name":"Медиа и стриминг"},{"id":"adult","name":"18+","sensitive":true}],
"services":[{"id":"telegram","name":"Telegram","cat":"messengers","src":"source2/telegram.txt"},
{"id":"youtube","name":"YouTube","cat":"media","icon":"youtube","src":"source2/youtube.txt"},
{"id":"hidden","name":"Hidden","cat":"adult","src":"source1/hidden.txt"},
{"id":"escape","name":"Escape","cat":"media","src":"../../etc/passwd"},
{"id":"Bad_ID","name":"Bad","cat":"media","src":"source1/bad.txt"},
{"id":"generic","name":"Generic","cat":"media","icon":"lucide-globe","src":"source1/generic.txt"}]}`

func geoTestManager(t *testing.T, lists map[string]string, fetched *[]string) *Manager {
	t.Helper()
	m, err := New(Registry{Schema: 1, Entries: []Entry{{
		ID: "telegram-networks", Name: "Telegram · домены и сети", Category: "Мессенджеры", Provider: "Test", License: "MIT",
		Access: Access{Region: "RU", Status: "catalog", Note: "Тест."}, SourcePage: "https://github.com/v2fly/domain-list-community",
		DomainsURL: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/telegram", ProbeURL: "https://telegram.org/",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if fetched != nil {
			*fetched = append(*fetched, r.URL.String())
		}
		body, ok := lists[r.URL.String()]
		if !ok {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})})
	return m
}

func TestGeoAggregatorCatalogueIsSearchableWithoutSensitiveOrUnsafeEntries(t *testing.T) {
	var fetched []string
	m := geoTestManager(t, map[string]string{geoAggregatorCatalog: geoCatalogFixture}, &fetched)
	if err := m.RefreshGeoAggregator(context.Background()); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, s := range m.Search("", nil) {
		ids = append(ids, s.ID)
	}
	want := []string{"ga-generic", "telegram-networks", "ga-telegram", "ga-youtube"}
	slices.Sort(want)
	slices.Sort(ids)
	if !slices.Equal(ids, want) {
		t.Fatalf("entries %v, want %v", ids, want)
	}
	for _, s := range m.Search("youtube", nil) {
		if s.ID != "ga-youtube" || s.Icon != "youtube" || s.Catalog != "geo-aggregator" || s.Category != "Медиа и стриминг" {
			t.Fatalf("unexpected youtube entry %+v", s.Entry)
		}
	}
	for _, s := range m.Search("generic", nil) {
		if s.Icon != "" {
			t.Fatal("generic glyph passed as a brand icon")
		}
	}
	// Within the TTL the index is not fetched again.
	if err := m.RefreshGeoAggregator(context.Background()); err != nil || len(fetched) != 1 {
		t.Fatalf("index fetched again: %v %v", fetched, err)
	}
}

func TestGeoAggregatorPreviewSplitsMixedListAndDerivesProbe(t *testing.T) {
	list := "# Telegram\n149.154.160.0/20\n2001:67c:4e8::/48\n91.108.4.1\ncdn-telegram.org\nt.me\ntelegram.org\ntelegram.me\n"
	m := geoTestManager(t, map[string]string{geoAggregatorCatalog: geoCatalogFixture, geoAggregatorBase + "source2/telegram.txt": list}, nil)
	if err := m.RefreshGeoAggregator(context.Background()); err != nil {
		t.Fatal(err)
	}
	preview, err := m.Preview(context.Background(), "ga-telegram", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	s := preview.Service
	if len(s.Domains) != 4 || len(s.CIDRs) != 3 || s.ProbeURL != "https://telegram.org/" {
		t.Fatalf("service %+v", s)
	}
	if s.Provenance == nil || s.Provenance.EntryID != "ga-telegram" || !slices.Equal(s.SourceRefs, []string{"community:ga-telegram"}) {
		t.Fatalf("provenance %+v %v", s.Provenance, s.SourceRefs)
	}
}

func TestDerivedProbeURL(t *testing.T) {
	for _, c := range []struct {
		id      string
		domains []string
		want    string
	}{
		{"ga-youtube", []string{"ads.youtube.com", "ggpht.com", "googlevideo.com", "youtu.be", "youtube.com", "youtube-nocookie.com"}, "https://youtube.com/"},
		{"ga-google-gemini", []string{"gemini.google.com", "bard.google.com"}, "https://gemini.google.com/"},
		{"ga-anthropic", []string{"anthropic.com", "claude.ai", "console.anthropic.com"}, "https://anthropic.com/"},
		{"ga-empty", nil, ""},
	} {
		if got := derivedProbeURL(c.id, c.domains); got != c.want {
			t.Errorf("%s: %q, want %q", c.id, got, c.want)
		}
	}
}

// Picks observed on the real catalogue (29.09.2026) that a plain heuristic got wrong.
func TestDerivedProbeURLPrefersMainSites(t *testing.T) {
	for id, c := range map[string]struct {
		domains []string
		want    string
	}{
		"ga-github":    {[]string{"github.io", "github.com", "githubassets.com", "githubusercontent.com"}, "https://github.com/"},
		"ga-microsoft": {[]string{"microsoft.io", "microsoft.com", "live.com"}, "https://microsoft.com/"},
		"ga-steam":     {[]string{"steam.tv", "steampowered.com", "steamcommunity.com"}, "https://store.steampowered.com/"},
	} {
		if got := derivedProbeURL(id, c.domains); got != c.want {
			t.Errorf("%s: %q, want %q", id, got, c.want)
		}
	}
}
