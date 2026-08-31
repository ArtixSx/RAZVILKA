package sources

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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

type Source struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Kind           string   `json:"kind"` // domains, cidrs, reference
	URL            string   `json:"url"`
	Format         string   `json:"format"` // lines, reference
	License        string   `json:"license,omitempty"`
	Enabled        bool     `json:"enabled"`
	MinEntries     int      `json:"min_entries,omitempty"`
	MaxBytes       int64    `json:"max_bytes,omitempty"`
	Description    string   `json:"description,omitempty"`
	Services       []string `json:"services,omitempty"`
	RedirectHosts  []string `json:"redirect_hosts,omitempty"`
	TrustTier      string   `json:"trust_tier,omitempty"`
	TTLHours       int      `json:"ttl_hours,omitempty"`
	ExpectedSHA256 string   `json:"expected_sha256,omitempty"`
	MaxEntries     int      `json:"max_entries,omitempty"`
}

type Registry struct {
	Schema  int      `json:"schema,omitempty"`
	Sources []Source `json:"sources"`
}

type State struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Kind           string       `json:"kind"`
	URL            string       `json:"url"`
	Enabled        bool         `json:"enabled"`
	AppliedEnabled bool         `json:"applied_enabled"`
	Dirty          bool         `json:"dirty"`
	Ready          bool         `json:"ready"`
	Entries        int          `json:"entries"`
	SHA256         string       `json:"sha256,omitempty"`
	UpdatedAt      time.Time    `json:"updated_at,omitempty"`
	LastError      string       `json:"last_error,omitempty"`
	Description    string       `json:"description,omitempty"`
	CacheStatus    string       `json:"cache_status,omitempty"`
	TrustTier      string       `json:"trust_tier,omitempty"`
	ExpiresAt      time.Time    `json:"expires_at,omitempty"`
	LastKnownGood  bool         `json:"last_known_good"`
	LegacyCache    bool         `json:"legacy_cache"`
	Provenance     *Provenance  `json:"provenance,omitempty"`
	Diff           *DiffSummary `json:"diff,omitempty"`
}

type settingsDocument struct {
	Schema  int             `json:"schema"`
	Draft   map[string]bool `json:"draft"`
	Applied map[string]bool `json:"applied"`
}

type Manager struct {
	mu           sync.RWMutex
	refreshGate  chan struct{}
	clientMu     sync.RWMutex
	reg          Registry
	cacheDir     string
	settingsPath string
	settings     settingsDocument
	client       *http.Client
	states       map[string]State
}

func LoadRegistry(path string) (Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Registry{}, err
	}
	var r Registry
	if err := json.Unmarshal(b, &r); err != nil {
		return Registry{}, err
	}
	if r.Schema < 0 || r.Schema > 2 {
		return Registry{}, errors.New("unsupported source registry schema")
	}
	// Upgrades preserve the user's registry. Migrate only these exact bundled
	// legacy release URLs; never grant redirects to arbitrary GitHub sources.
	if r.Schema < 2 {
		for i := range r.Sources {
			src := &r.Sources[i]
			if len(src.RedirectHosts) == 0 && (src.URL == "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/domains_all.lst" || src.URL == "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ipsum.lst") {
				src.RedirectHosts = []string{"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
			}
		}
	}
	seen := map[string]bool{}
	for _, s := range r.Sources {
		if !validSourceID(s.ID) || s.Name == "" || s.Kind == "" || s.URL == "" {
			return Registry{}, errors.New("invalid source entry")
		}
		if seen[s.ID] {
			return Registry{}, fmt.Errorf("duplicate source id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Kind != "domains" && s.Kind != "cidrs" && s.Kind != "reference" {
			return Registry{}, fmt.Errorf("unsupported source kind %q", s.Kind)
		}
		if err := validateSource(s); err != nil {
			return Registry{}, fmt.Errorf("source %q: %w", s.ID, err)
		}
	}
	return r, nil
}

func NewManager(reg Registry, cacheDir string, settingsPath ...string) *Manager {
	path := ""
	if len(settingsPath) > 0 {
		path = strings.TrimSpace(settingsPath[0])
	}
	m := &Manager{
		refreshGate:  make(chan struct{}, 1),
		reg:          reg,
		cacheDir:     cacheDir,
		settingsPath: path,
		settings:     settingsDocument{Schema: 1, Draft: map[string]bool{}, Applied: map[string]bool{}},
		client:       publicfetch.NewClient(25 * time.Second),
		states:       map[string]State{},
	}
	for _, s := range reg.Sources {
		m.settings.Draft[s.ID] = s.Enabled
		m.settings.Applied[s.ID] = s.Enabled
		m.states[s.ID] = State{ID: s.ID, Name: s.Name, Kind: s.Kind, URL: publicfetch.RedactedURL(s.URL), Enabled: s.Enabled, AppliedEnabled: s.Enabled, Description: s.Description, TrustTier: trustTier(s)}
	}
	m.loadSettings()
	m.inspectCache()
	return m
}

func (m *Manager) SetHTTPClient(c *http.Client) {
	if c == nil {
		return
	}
	clone := *c
	m.clientMu.Lock()
	m.client = &clone
	m.clientMu.Unlock()
}

func (m *Manager) List() []State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]State, 0, len(m.states))
	for _, s := range m.states {
		s = currentState(s, time.Now())
		s.Enabled = m.settings.Draft[s.ID]
		s.AppliedEnabled = m.settings.Applied[s.ID]
		s.Dirty = s.Enabled != s.AppliedEnabled
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Manager) Dirty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, draft := range m.settings.Draft {
		if draft != m.settings.Applied[id] {
			return true
		}
	}
	return false
}

func (m *Manager) SetDraft(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.states[id]; !ok {
		return fmt.Errorf("unknown source %q", id)
	}
	previous := cloneSettings(m.settings)
	m.settings.Draft[id] = enabled
	if err := m.saveSettingsLocked(); err != nil {
		m.settings = previous
		return err
	}
	return nil
}

func (m *Manager) Apply() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := cloneSettings(m.settings)
	m.settings.Applied = cloneBoolMap(m.settings.Draft)
	if err := m.saveSettingsLocked(); err != nil {
		m.settings = previous
		return err
	}
	return nil
}

func (m *Manager) Discard() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := cloneSettings(m.settings)
	m.settings.Draft = cloneBoolMap(m.settings.Applied)
	if err := m.saveSettingsLocked(); err != nil {
		m.settings = previous
		return err
	}
	return nil
}

// EntriesForService returns only cached entries from sources that explicitly
// opt in to enriching a service. SourceRefs remain provenance metadata and do
// not implicitly merge broad community lists into a single route.
func (m *Manager) EntriesForService(serviceID string) (domains, cidrs []string) {
	serviceID = strings.ToLower(strings.TrimSpace(serviceID))
	if serviceID == "" {
		return nil, nil
	}
	m.mu.RLock()
	sourcesForService := make([]Source, 0)
	for _, src := range m.reg.Sources {
		state := currentState(m.states[src.ID], time.Now())
		if !m.settings.Applied[src.ID] || !state.Ready || src.Kind == "reference" || !containsFold(src.Services, serviceID) {
			continue
		}
		sourcesForService = append(sourcesForService, src)
	}
	m.mu.RUnlock()
	for _, src := range sourcesForService {
		cached, err := m.readCache(src)
		if err != nil || !time.Now().Before(cached.ExpiresAt) {
			continue
		}
		entries, _ := validateLines(src.Kind, cached.Content)
		if src.Kind == "domains" {
			domains = append(domains, entries...)
		} else if src.Kind == "cidrs" {
			cidrs = append(cidrs, entries...)
		}
	}
	return uniqueSorted(domains), uniqueSorted(cidrs)
}

func containsFold(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), needle) {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) RefreshEnabled(ctx context.Context) []State {
	m.mu.RLock()
	enabled := cloneBoolMap(m.settings.Applied)
	m.mu.RUnlock()
	for _, src := range m.reg.Sources {
		if enabled[src.ID] && src.Kind != "reference" {
			_ = m.Refresh(ctx, src.ID)
		}
	}
	return m.List()
}

func (m *Manager) Refresh(ctx context.Context, id string) error {
	select {
	case m.refreshGate <- struct{}{}:
		defer func() { <-m.refreshGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var src *Source
	for i := range m.reg.Sources {
		if m.reg.Sources[i].ID == id {
			src = &m.reg.Sources[i]
			break
		}
	}
	if src == nil {
		return fmt.Errorf("unknown source %q", id)
	}
	if !validSourceID(src.ID) {
		return errors.New("unsafe source id")
	}
	if err := validateSource(*src); err != nil {
		return m.fail(*src, err)
	}
	if src.Kind == "reference" {
		return nil
	}

	max := src.MaxBytes
	if max <= 0 {
		max = 8 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return m.fail(*src, publicfetch.SafeError(err))
	}
	// Keep the fetch identity stable and free from a separately maintained
	// version literal. Build provenance is exposed by the local status API.
	req.Header.Set("User-Agent", "RAZVILKA/source-hub")
	m.clientMu.RLock()
	client := publicfetch.WithPolicy(m.client, src.URL, src.RedirectHosts)
	m.clientMu.RUnlock()
	resp, err := client.Do(req)
	if err != nil {
		return m.fail(*src, publicfetch.SafeError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return m.fail(*src, fmt.Errorf("http status %d", resp.StatusCode))
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return m.fail(*src, errors.New("source returned HTML instead of a list"))
	}
	lr := &io.LimitedReader{R: resp.Body, N: max + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return m.fail(*src, publicfetch.SafeError(err))
	}
	if int64(len(b)) > max {
		return m.fail(*src, fmt.Errorf("source exceeds max_bytes=%d", max))
	}
	prefix := strings.ToLower(strings.TrimSpace(string(b[:min(len(b), 512)])))
	for _, marker := range []string{"<!doctype html", "<html", "<head", "<body", "<script"} {
		if strings.HasPrefix(prefix, marker) {
			return m.fail(*src, errors.New("source body is HTML, not a list"))
		}
	}
	rawSHA := contentHash(b)
	if src.ExpectedSHA256 != "" && !strings.EqualFold(src.ExpectedSHA256, rawSHA) {
		return m.fail(*src, errors.New("source SHA256 does not match its pin"))
	}

	entries, err := validateLinesLimited(src.Kind, string(b), sourceEntryLimit(*src))
	if err != nil {
		return m.fail(*src, err)
	}
	if src.MinEntries > 0 && len(entries) < src.MinEntries {
		return m.fail(*src, fmt.Errorf("too few valid entries: %d < %d", len(entries), src.MinEntries))
	}
	normalized := strings.Join(entries, "\n") + "\n"
	sum := sha256.Sum256([]byte(normalized))
	digest := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
		return m.fail(*src, errors.New("cannot create source cache directory"))
	}
	now := time.Now().UTC()
	finalURL := src.URL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	cached := cacheDocument{Schema: 2, ID: src.ID, Kind: src.Kind, SourceHash: sourceHash(*src), Content: normalized, Entries: len(entries), SHA256: digest, FetchedAt: now, ExpiresAt: now.Add(sourceTTL(*src)), Provenance: Provenance{URL: publicfetch.RedactedURL(src.URL), FinalURL: publicfetch.RedactedURL(finalURL), RawSHA256: rawSHA, TrustTier: trustTier(*src)}}
	cached.Diff = DiffSummary{Added: len(entries)}
	if previous, err := m.readCache(*src); err == nil {
		cached.Diff = cacheDiff(previous, entries)
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return m.fail(*src, errors.New("cannot encode source cache"))
	}
	if err := writeAtomic(filepath.Join(m.cacheDir, src.ID+".cache.json"), data, 0o600); err != nil {
		return m.fail(*src, errors.New("cannot commit source cache"))
	}

	m.mu.Lock()
	draftEnabled := m.settings.Draft[src.ID]
	appliedEnabled := m.settings.Applied[src.ID]
	state := stateFromCache(m.states[src.ID], cached)
	state.Enabled, state.AppliedEnabled, state.Dirty = draftEnabled, appliedEnabled, draftEnabled != appliedEnabled
	m.states[src.ID] = state
	m.mu.Unlock()
	return nil
}

func (m *Manager) loadSettings() {
	if m.settingsPath == "" {
		return
	}
	b, err := os.ReadFile(m.settingsPath)
	if err != nil {
		return
	}
	var stored settingsDocument
	if json.Unmarshal(b, &stored) != nil || stored.Schema != 1 {
		return
	}
	for _, src := range m.reg.Sources {
		if enabled, ok := stored.Applied[src.ID]; ok {
			m.settings.Applied[src.ID] = enabled
		}
		if enabled, ok := stored.Draft[src.ID]; ok {
			m.settings.Draft[src.ID] = enabled
		} else {
			m.settings.Draft[src.ID] = m.settings.Applied[src.ID]
		}
	}
}

func (m *Manager) saveSettingsLocked() error {
	if m.settingsPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.settingsPath), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m.settings, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeAtomic(m.settingsPath, b, 0o600)
}

func cloneSettings(in settingsDocument) settingsDocument {
	return settingsDocument{Schema: in.Schema, Draft: cloneBoolMap(in.Draft), Applied: cloneBoolMap(in.Applied)}
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (m *Manager) fail(src Source, err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	m.mu.Lock()
	st := m.states[src.ID]
	st.LastError = err.Error()
	st.LastKnownGood = st.Ready
	if st.Ready {
		st.CacheStatus = "last-known-good"
	} else {
		st.CacheStatus = "quarantined"
	}
	m.states[src.ID] = st
	m.mu.Unlock()
	m.writeQuarantine(src, err)
	return err
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	parent, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	root, err := ownedfs.Open(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.WriteAtomic(filepath.Base(path), content, mode)
}

func (m *Manager) inspectCache() {
	for _, src := range m.reg.Sources {
		if src.Kind == "reference" || !validSourceID(src.ID) {
			continue
		}
		cached, err := m.readCache(src)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			m.rejectCache(src, err)
			continue
		}
		m.states[src.ID] = stateFromCache(m.states[src.ID], cached)
		m.inspectQuarantine(src, cached.FetchedAt)
	}
}

func (m *Manager) rejectCache(src Source, err error) {
	st := m.states[src.ID]
	st.Ready = false
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		err = errors.New("cache file unavailable or unsafe")
	}
	st.LastError = "cached source rejected: " + err.Error()
	st.CacheStatus = "quarantined"
	m.states[src.ID] = st
}

func validateLines(kind, body string) ([]string, error) {
	return validateLinesLimited(kind, body, 500000)
}

func validateLinesLimited(kind, body string, limit int) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}
	s := bufio.NewScanner(strings.NewReader(body))
	s.Buffer(make([]byte, 1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		var v string
		var err error
		switch kind {
		case "domains":
			v, err = normalizeDomain(line)
		case "cidrs":
			v, err = normalizeCIDR(line)
		default:
			return nil, errors.New("unsupported list kind")
		}
		if err != nil {
			continue
		} // quarantine malformed entries instead of poisoning entire list
		if _, ok := seen[v]; ok {
			continue
		}
		if len(out) >= limit {
			return nil, errors.New("source exceeds max_entries")
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no valid entries")
	}
	sort.Strings(out)
	return out, nil
}

func validSourceID(id string) bool {
	if len(id) == 0 || len(id) > 64 || !isSourceIDAlphaNumeric(id[0]) {
		return false
	}
	for i := 1; i < len(id); i++ {
		if !isSourceIDAlphaNumeric(id[i]) && id[i] != '-' && id[i] != '_' {
			return false
		}
	}
	return true
}

func isSourceIDAlphaNumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func normalizeDomain(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, p := range []string{"domain:", "full:"} {
		if strings.HasPrefix(v, p) {
			v = strings.TrimPrefix(v, p)
		}
	}
	v = strings.TrimPrefix(v, "||")
	v = strings.TrimPrefix(v, ".")
	v = strings.TrimSuffix(v, "^")
	if strings.ContainsAny(v, " /\\:@*") {
		return "", errors.New("invalid domain")
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.') {
			return "", errors.New("domain must be ascii hostname")
		}
	}
	if len(v) > 253 || !strings.Contains(v, ".") {
		return "", errors.New("domain must contain dot")
	}
	if net.ParseIP(v) != nil {
		return "", errors.New("ip is not domain")
	}
	labels := strings.Split(v, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", errors.New("bad label")
		}
	}
	return v, nil
}

func normalizeCIDR(v string) (string, error) {
	v = strings.TrimSpace(v)
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return "", err
	}
	p = p.Masked()
	if !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsLinkLocalMulticast() {
		return "", errors.New("not public unicast")
	}
	if p.Addr().Is4() && p.Bits() < 8 {
		return "", errors.New("ipv4 prefix too broad")
	}
	if p.Addr().Is6() && p.Bits() < 16 {
		return "", errors.New("ipv6 prefix too broad")
	}
	if p == netip.MustParsePrefix("0.0.0.0/0") || p == netip.MustParsePrefix("::/0") {
		return "", errors.New("default route rejected")
	}
	return p.String(), nil
}
