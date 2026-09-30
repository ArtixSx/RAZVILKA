package community

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Geo-Aggregator (github.com/Ground-Zerro/Geo-Aggregator, GPL-3.0) publishes a
// hand-maintained catalogue of about 300 services in 19 categories, rebuilt
// daily from v2fly, Loyalsoldier, runetfreedom, itdoginfo and antifilter data.
// HydraRoute imports services from it. Each service is one list mixing
// domains and networks. Only the catalogue index is cached here; a service
// list is fetched on preview like any other community source, and the owner
// still reviews and imports it explicitly.
const (
	geoAggregatorBase    = "https://raw.githubusercontent.com/Ground-Zerro/Geo-Aggregator/main/"
	geoAggregatorCatalog = geoAggregatorBase + "db/catalog.json"
	geoAggregatorPage    = "https://github.com/Ground-Zerro/Geo-Aggregator"
	geoAggregatorTTL     = 12 * time.Hour
	geoAggregatorPrefix  = "ga-"
	maxGeoServices       = 1000
)

var (
	geoSourcePattern = regexp.MustCompile(`^source[0-9]{1,3}/[A-Za-z0-9][A-Za-z0-9@._-]{0,127}\.txt$`)
	geoIconPattern   = regexp.MustCompile(`^[a-z0-9]{1,40}$`)
)

type geoCatalog struct {
	Version    int    `json:"version"`
	Base       string `json:"base"`
	Categories []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Sensitive bool   `json:"sensitive"`
	} `json:"categories"`
	Services []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Cat  string `json:"cat"`
		Icon string `json:"icon"`
		Src  string `json:"src"`
	} `json:"services"`
}

// geoEntries converts the index into catalogue entries. Sensitive (18+)
// categories and anything outside the expected shapes are left out.
func geoEntries(body []byte) ([]Entry, error) {
	var index geoCatalog
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&index); err != nil || index.Version != 1 || index.Base != geoAggregatorBase || len(index.Services) == 0 || len(index.Services) > maxGeoServices {
		return nil, errors.New("Geo-Aggregator catalogue has an unexpected shape")
	}
	categories := map[string]string{}
	for _, c := range index.Categories {
		if c.Sensitive || !entryIDPattern.MatchString(c.ID) || strings.TrimSpace(c.Name) == "" || len(c.Name) > 80 {
			continue
		}
		categories[c.ID] = strings.TrimSpace(c.Name)
	}
	entries := []Entry{}
	seen := map[string]bool{}
	for _, s := range index.Services {
		category, ok := categories[s.Cat]
		id := geoAggregatorPrefix + s.ID
		name := strings.TrimSpace(s.Name)
		if !ok || !entryIDPattern.MatchString(id) || seen[id] || name == "" || len(name) > 80 || !geoSourcePattern.MatchString(s.Src) {
			continue
		}
		icon := ""
		if geoIconPattern.MatchString(s.Icon) {
			icon = s.Icon // a Simple Icons slug; "lucide-*" generic glyphs are not used
		}
		seen[id] = true
		entries = append(entries, Entry{
			ID: id, Name: name, Category: category, Icon: icon,
			Description: "Каталог Geo-Aggregator: домены и сети сервиса.",
			ListURL:     geoAggregatorBase + s.Src,
			Provider:    "Geo-Aggregator", SourcePage: geoAggregatorPage, License: "GPL-3.0",
			Catalog: "geo-aggregator",
			Access:  Access{Region: "RU", Status: "catalog", Note: "Сервис из каталога Geo-Aggregator; доступность проверяется на вашем роутере."},
		})
	}
	if len(entries) == 0 {
		return nil, errors.New("Geo-Aggregator catalogue has no usable services")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, nil
}

// RefreshGeoAggregator reloads the index when it is older than its TTL. A
// failure keeps the previous index; the curated catalogue always remains.
func (m *Manager) RefreshGeoAggregator(ctx context.Context) error {
	m.mu.RLock()
	fresh := !m.geoAt.IsZero() && time.Since(m.geoAt) >= 0 && time.Since(m.geoAt) < geoAggregatorTTL
	m.mu.RUnlock()
	if fresh {
		return nil
	}
	body, err := m.fetch(ctx, geoAggregatorCatalog)
	if err != nil {
		return err
	}
	entries, err := geoEntries(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.geo, m.geoAt = entries, time.Now()
	m.mu.Unlock()
	return nil
}

func (m *Manager) geoEntries() []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Entry(nil), m.geo...)
}

// splitMixedList separates a Geo-Aggregator list into domain and network lines.
func splitMixedList(body []byte) (domains, cidrs []byte) {
	var d, c bytes.Buffer
	for _, raw := range bytes.Split(body, []byte{'\n'}) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := netip.ParsePrefix(line); err == nil {
			c.WriteString(line + "\n")
			continue
		}
		if address, err := netip.ParseAddr(line); err == nil {
			c.WriteString(netip.PrefixFrom(address, address.BitLen()).String() + "\n")
			continue
		}
		d.WriteString(line + "\n")
	}
	return d.Bytes(), c.Bytes()
}

// derivedProbeURL picks the service's main site for the check: a domain named
// after the service, otherwise the shortest two-label domain.
func derivedProbeURL(entryID string, domains []string) string {
	id := strings.TrimPrefix(entryID, geoAggregatorPrefix)
	// The main site is not the best-named domain for these services.
	if probe, ok := map[string]string{"steam": "https://store.steampowered.com/", "google-gemini": "https://gemini.google.com/"}[id]; ok {
		return probe
	}
	best := ""
	score := func(domain string) int {
		labels := strings.Split(domain, ".")
		value := 0
		if labels[0] == id || strings.ReplaceAll(labels[0], "-", "") == strings.ReplaceAll(id, "-", "") {
			value += 100
		} else if slices.Contains(strings.Split(id, "-"), labels[0]) {
			value += 50
		}
		if len(labels) == 2 {
			value += 20
		}
		switch labels[len(labels)-1] {
		case "com":
			value += 10
		case "org", "net":
			value += 6
		case "io", "app", "tv":
			value += 2
		}
		return value*100 - len(domain)
	}
	for _, domain := range domains {
		if best == "" || score(domain) > score(best) {
			best = domain
		}
	}
	if best == "" {
		return ""
	}
	return "https://" + best + "/"
}
