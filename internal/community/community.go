package community

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

const maxSourceBytes = 2 << 20

var entryIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var includeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$`)

var allowedHosts = map[string]bool{
	"raw.githubusercontent.com": true,
	"core.telegram.org":         true,
}

type Registry struct {
	Schema  int     `json:"schema"`
	Entries []Entry `json:"entries"`
}

type Entry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases,omitempty"`
	Category    string   `json:"category"`
	Icon        string   `json:"icon"`
	Description string   `json:"description"`
	ProbeURL    string   `json:"probe_url,omitempty"`
	DomainsURL  string   `json:"domains_url,omitempty"`
	CIDRsURL    string   `json:"cidrs_url,omitempty"`
	Provider    string   `json:"provider"`
	SourcePage  string   `json:"source_page"`
	License     string   `json:"license,omitempty"`
	Access      Access   `json:"access"`
}

// Access describes why an entry is useful in a regional routing catalog. It
// is intentionally separate from the domain-list provider: V2Fly explicitly
// does not claim that a listed service is blocked or should be proxied.
type Access struct {
	Region      string `json:"region"`
	Status      string `json:"status"`
	Since       string `json:"since,omitempty"`
	Note        string `json:"note"`
	EvidenceURL string `json:"evidence_url,omitempty"`
	VerifiedAt  string `json:"verified_at,omitempty"`
}

type Summary struct {
	Entry
	Imported bool `json:"imported"`
}

type Conflict struct {
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	ServiceID   string `json:"service_id"`
	ServiceName string `json:"service_name"`
}

type Preview struct {
	Entry     Entry           `json:"entry"`
	Service   catalog.Service `json:"service"`
	Conflicts []Conflict      `json:"conflicts"`
	Skipped   int             `json:"skipped"`
	SourceSHA string          `json:"source_sha256"`
	FetchedAt string          `json:"fetched_at"`
	FromCache bool            `json:"from_cache"`
}

type cachedPreview struct {
	preview Preview
	at      time.Time
}

type Manager struct {
	registry Registry
	client   *http.Client
	mu       sync.RWMutex
	cache    map[string]cachedPreview
}

func Load(path string) (*Manager, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var registry Registry
	if err := json.Unmarshal(b, &registry); err != nil {
		return nil, fmt.Errorf("decode community catalog: %w", err)
	}
	return New(registry)
}

func New(registry Registry) (*Manager, error) {
	if registry.Schema != 1 {
		return nil, fmt.Errorf("unsupported community catalog schema %d", registry.Schema)
	}
	if len(registry.Entries) == 0 || len(registry.Entries) > 128 {
		return nil, errors.New("community catalog must contain 1..128 entries")
	}
	seen := map[string]bool{}
	validAccess := map[string]bool{"blocked": true, "throttled": true, "partial": true, "provider-limited": true, "variable": true, "catalog": true}
	for i := range registry.Entries {
		e := &registry.Entries[i]
		if !entryIDPattern.MatchString(e.ID) || e.Name == "" || e.Category == "" || e.Provider == "" || e.SourcePage == "" {
			return nil, fmt.Errorf("invalid community entry %q", e.ID)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("duplicate community entry %q", e.ID)
		}
		seen[e.ID] = true
		if e.DomainsURL == "" && e.CIDRsURL == "" {
			return nil, fmt.Errorf("community entry %q has no data URL", e.ID)
		}
		if e.Access.Region == "" {
			e.Access.Region = "RU"
		}
		if e.Access.Region != "RU" || !validAccess[e.Access.Status] || strings.TrimSpace(e.Access.Note) == "" {
			return nil, fmt.Errorf("community entry %q has invalid access status", e.ID)
		}
		if e.Access.EvidenceURL != "" {
			if err := validatePageURL(e.Access.EvidenceURL); err != nil {
				return nil, fmt.Errorf("community entry %q evidence: %w", e.ID, err)
			}
		}
		for _, rawURL := range []string{e.DomainsURL, e.CIDRsURL} {
			if rawURL != "" {
				if err := validateSourceURL(rawURL); err != nil {
					return nil, fmt.Errorf("community entry %q: %w", e.ID, err)
				}
			}
		}
		if err := validatePageURL(e.SourcePage); err != nil {
			return nil, fmt.Errorf("community entry %q source page: %w", e.ID, err)
		}
		if e.ProbeURL != "" {
			if err := validatePageURL(e.ProbeURL); err != nil {
				return nil, fmt.Errorf("community entry %q probe: %w", e.ID, err)
			}
		}
	}
	return &Manager{
		registry: registry,
		client: &http.Client{
			Timeout:       20 * time.Second,
			CheckRedirect: safeRedirect,
		},
		cache: map[string]cachedPreview{},
	}, nil
}

func (m *Manager) SetHTTPClient(client *http.Client) {
	if client == nil {
		return
	}
	clone := *client
	clone.CheckRedirect = safeRedirect
	m.mu.Lock()
	m.client = &clone
	m.mu.Unlock()
}

func (m *Manager) Search(query string, imported func(string) bool) []Summary {
	query = strings.ToLower(strings.TrimSpace(query))
	result := make([]Summary, 0, len(m.registry.Entries))
	for _, entry := range m.registry.Entries {
		haystack := strings.ToLower(strings.Join(append([]string{entry.ID, entry.Name, entry.Category, entry.Description, entry.Access.Status, entry.Access.Note}, entry.Aliases...), " "))
		if query != "" && !strings.Contains(haystack, query) {
			continue
		}
		result = append(result, Summary{Entry: entry, Imported: imported != nil && imported("custom-"+entry.ID)})
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name) })
	return result
}

func (m *Manager) Preview(ctx context.Context, id string, existing []catalog.Service, refresh bool) (Preview, error) {
	entry, ok := m.entry(id)
	if !ok {
		return Preview{}, os.ErrNotExist
	}
	if !refresh {
		m.mu.RLock()
		cached, found := m.cache[id]
		m.mu.RUnlock()
		if found && time.Since(cached.at) < 10*time.Minute {
			preview := clonePreview(cached.preview)
			preview.FromCache = true
			preview.Conflicts = findConflicts(preview.Service, existing)
			return preview, nil
		}
	}

	domains, cidrs := []string{}, []string{}
	skipped := 0
	hash := sha256.New()
	if entry.DomainsURL != "" {
		var count int
		var err error
		domains, count, err = m.fetchDomainTree(ctx, entry.DomainsURL, hash)
		if err != nil {
			return Preview{}, fmt.Errorf("domains source: %w", err)
		}
		skipped += count
	}
	if entry.CIDRsURL != "" {
		body, err := m.fetch(ctx, entry.CIDRsURL)
		if err != nil {
			return Preview{}, fmt.Errorf("CIDR source: %w", err)
		}
		hash.Write([]byte(entry.CIDRsURL))
		hash.Write(body)
		var count int
		cidrs, count = parseCIDRs(body)
		skipped += count
	}
	if len(domains) == 0 && len(cidrs) == 0 {
		return Preview{}, errors.New("community source contains no supported domains or CIDRs")
	}
	if len(domains) > 2000 || len(cidrs) > 2000 {
		return Preview{}, errors.New("community source exceeds per-service entry limit")
	}
	fetchedAt := time.Now().UTC().Format(time.RFC3339)
	digest := hex.EncodeToString(hash.Sum(nil))
	service := catalog.Service{
		ID: entry.ID, Name: entry.Name, Category: entry.Category, Icon: entry.Icon,
		Description: entry.Description, Domains: domains, CIDRs: cidrs,
		Strategy: []string{"auto"}, ProbeURL: entry.ProbeURL,
		SourceRefs: []string{"community:" + entry.ID},
		Note:       "Импортировано из проверенного community-каталога. Статус доступа: " + entry.Access.Note + " Перед применением проверьте список и возможные конфликты.",
		Provenance: &catalog.Provenance{Provider: entry.Provider, EntryID: entry.ID, URL: entry.SourcePage, License: entry.License, SHA256: digest, FetchedAt: fetchedAt},
	}
	if err := catalog.Validate(catalog.Catalog{Services: []catalog.Service{service}}); err != nil {
		return Preview{}, fmt.Errorf("community service validation: %w", err)
	}
	preview := Preview{Entry: entry, Service: service, Conflicts: findConflicts(service, existing), Skipped: skipped, SourceSHA: digest, FetchedAt: fetchedAt}
	m.mu.Lock()
	m.cache[id] = cachedPreview{preview: clonePreview(preview), at: time.Now()}
	m.mu.Unlock()
	return preview, nil
}

func (m *Manager) fetchDomainTree(ctx context.Context, rootURL string, hash io.Writer) ([]string, int, error) {
	visited := map[string]bool{}
	domains := map[string]bool{}
	skipped := 0
	var walk func(string, int) error
	walk = func(rawURL string, depth int) error {
		if depth > 8 {
			return errors.New("community include depth exceeds 8")
		}
		if visited[rawURL] {
			return nil
		}
		if len(visited) >= 64 {
			return errors.New("community source includes more than 64 files")
		}
		visited[rawURL] = true
		body, err := m.fetch(ctx, rawURL)
		if err != nil {
			return err
		}
		_, _ = hash.Write([]byte(rawURL))
		_, _ = hash.Write(body)
		parsed, includes, count := parseDomainDocument(body)
		skipped += count
		for _, domain := range parsed {
			domains[domain] = true
		}
		for _, include := range includes {
			includeURL, err := resolveDomainInclude(rawURL, include)
			if err != nil {
				skipped++
				continue
			}
			if err := walk(includeURL, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(rootURL, 0); err != nil {
		return nil, skipped, err
	}
	out := make([]string, 0, len(domains))
	for domain := range domains {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out, skipped, nil
}

func resolveDomainInclude(currentURL, include string) (string, error) {
	if !includeNamePattern.MatchString(include) {
		return "", errors.New("invalid community include name")
	}
	u, err := url.Parse(currentURL)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(path.Dir(u.Path), include)
	u.RawQuery = ""
	u.Fragment = ""
	if err := validateSourceURL(u.String()); err != nil {
		return "", err
	}
	return u.String(), nil
}

func (m *Manager) entry(id string) (Entry, bool) {
	for _, entry := range m.registry.Entries {
		if entry.ID == id {
			return entry, true
		}
	}
	return Entry{}, false
}

func (m *Manager) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RAZVILKA/0.10.0 community-catalog")
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxSourceBytes + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > maxSourceBytes {
		return nil, errors.New("source is empty or too large")
	}
	return body, nil
}

func parseDomains(body []byte) ([]string, int) {
	domains, includes, skipped := parseDomainDocument(body)
	return domains, skipped + len(includes)
}

func parseDomainDocument(body []byte) ([]string, []string, int) {
	seen := map[string]bool{}
	out := []string{}
	includeSeen := map[string]bool{}
	includes := []string{}
	skipped := 0
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		line = fields[0]
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "include:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "include:"))
			if name == "" || includeSeen[name] {
				skipped++
			} else {
				includeSeen[name] = true
				includes = append(includes, name)
			}
			continue
		}
		if strings.HasPrefix(lower, "regexp:") || strings.HasPrefix(lower, "keyword:") {
			skipped++
			continue
		}
		line = strings.TrimPrefix(lower, "full:")
		line = strings.TrimPrefix(line, "domain:")
		domain, err := normalizeDomain(line)
		if err != nil {
			skipped++
			continue
		}
		if !seen[domain] {
			seen[domain] = true
			out = append(out, domain)
		}
	}
	sort.Strings(out)
	sort.Strings(includes)
	return out, includes, skipped
}

func parseCIDRs(body []byte) ([]string, int) {
	seen := map[string]bool{}
	out := []string{}
	skipped := 0
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if line == "" || strings.HasPrefix(line, "payload:") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
		line = strings.Trim(line, "'\"")
		candidates := strings.Split(line, ",")
		var prefix netip.Prefix
		found := false
		for _, candidate := range candidates {
			candidate = strings.Trim(strings.TrimSpace(candidate), "'\"")
			parsed, err := netip.ParsePrefix(candidate)
			if err == nil {
				prefix, found = parsed.Masked(), true
				break
			}
		}
		if !found || !safePublicPrefix(prefix) {
			skipped++
			continue
		}
		value := prefix.String()
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out, skipped
}

func normalizeDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if len(value) > 253 || !strings.Contains(value, ".") || strings.ContainsAny(value, " /\\:@*") || net.ParseIP(value) != nil {
		return "", errors.New("invalid domain")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid domain label")
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return "", errors.New("domain must be ASCII")
			}
		}
	}
	return value, nil
}

func safePublicPrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return false
	}
	if address.Is4() && prefix.Bits() < 8 {
		return false
	}
	return !address.Is6() || prefix.Bits() >= 16
}

func findConflicts(candidate catalog.Service, existing []catalog.Service) []Conflict {
	domains := make(map[string]catalog.Service)
	cidrs := make(map[string]catalog.Service)
	for _, service := range existing {
		// A preview is also used after an entry has already been imported. Do not
		// report the imported copy as conflicting with its own upstream data.
		if service.ID == "custom-"+candidate.ID {
			continue
		}
		for _, domain := range service.Domains {
			domains[strings.ToLower(domain)] = service
		}
		for _, cidr := range service.CIDRs {
			cidrs[cidr] = service
		}
	}
	conflicts := []Conflict{}
	for _, domain := range candidate.Domains {
		if service, ok := domains[strings.ToLower(domain)]; ok {
			conflicts = append(conflicts, Conflict{Kind: "domain", Value: domain, ServiceID: service.ID, ServiceName: service.Name})
		}
	}
	for _, cidr := range candidate.CIDRs {
		if service, ok := cidrs[cidr]; ok {
			conflicts = append(conflicts, Conflict{Kind: "cidr", Value: cidr, ServiceID: service.ID, ServiceName: service.Name})
		}
	}
	if len(conflicts) > 200 {
		conflicts = conflicts[:200]
	}
	return conflicts
}

func validateSourceURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || !allowedHosts[strings.ToLower(u.Hostname())] {
		return errors.New("source URL is not allowlisted HTTPS")
	}
	return nil
}

func validatePageURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("URL must be absolute HTTPS")
	}
	return nil
}

func safeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if err := validateSourceURL(req.URL.String()); err != nil {
		return err
	}
	return nil
}

func clonePreview(in Preview) Preview {
	out := in
	out.Service.Domains = append([]string(nil), in.Service.Domains...)
	out.Service.CIDRs = append([]string(nil), in.Service.CIDRs...)
	out.Service.Strategy = append([]string(nil), in.Service.Strategy...)
	out.Service.SourceRefs = append([]string(nil), in.Service.SourceRefs...)
	out.Conflicts = append([]Conflict(nil), in.Conflicts...)
	if in.Service.Provenance != nil {
		provenance := *in.Service.Provenance
		out.Service.Provenance = &provenance
	}
	return out
}
