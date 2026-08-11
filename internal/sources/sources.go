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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Source struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"` // domains, cidrs, reference
	URL         string `json:"url"`
	Format      string `json:"format"` // lines, reference
	License     string `json:"license,omitempty"`
	Enabled     bool   `json:"enabled"`
	MinEntries  int    `json:"min_entries,omitempty"`
	MaxBytes    int64  `json:"max_bytes,omitempty"`
	Description string `json:"description,omitempty"`
}

type Registry struct {
	Sources []Source `json:"sources"`
}

type State struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	URL         string    `json:"url"`
	Enabled     bool      `json:"enabled"`
	Ready       bool      `json:"ready"`
	Entries     int       `json:"entries"`
	SHA256      string    `json:"sha256,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Description string    `json:"description,omitempty"`
}

type Manager struct {
	mu       sync.RWMutex
	reg      Registry
	cacheDir string
	client   *http.Client
	states   map[string]State
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
	seen := map[string]bool{}
	for _, s := range r.Sources {
		if s.ID == "" || s.Name == "" || s.Kind == "" || s.URL == "" {
			return Registry{}, fmt.Errorf("invalid source entry: %+v", s)
		}
		if seen[s.ID] {
			return Registry{}, fmt.Errorf("duplicate source id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Kind != "domains" && s.Kind != "cidrs" && s.Kind != "reference" {
			return Registry{}, fmt.Errorf("unsupported source kind %q", s.Kind)
		}
		u, err := url.Parse(s.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return Registry{}, fmt.Errorf("source %q must use an absolute https URL", s.ID)
		}
	}
	return r, nil
}

func NewManager(reg Registry, cacheDir string) *Manager {
	m := &Manager{reg: reg, cacheDir: cacheDir, client: &http.Client{Timeout: 25 * time.Second}, states: map[string]State{}}
	for _, s := range reg.Sources {
		st := State{ID: s.ID, Name: s.Name, Kind: s.Kind, URL: s.URL, Enabled: s.Enabled, Description: s.Description}
		if s.Kind == "reference" {
			st.Ready = true
		}
		m.states[s.ID] = st
	}
	m.inspectCache()
	return m
}

func (m *Manager) SetHTTPClient(c *http.Client) {
	if c != nil {
		m.client = c
	}
}

func (m *Manager) List() []State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]State, 0, len(m.states))
	for _, s := range m.states {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Manager) RefreshEnabled(ctx context.Context) []State {
	for _, src := range m.reg.Sources {
		if src.Enabled && src.Kind != "reference" {
			_ = m.Refresh(ctx, src.ID)
		}
	}
	return m.List()
}

func (m *Manager) Refresh(ctx context.Context, id string) error {
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
	if src.Kind == "reference" {
		return nil
	}

	max := src.MaxBytes
	if max <= 0 {
		max = 8 << 20
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return m.fail(*src, err)
	}
	req.Header.Set("User-Agent", "RAZVILKA/0.0.7-control-lab")
	resp, err := m.client.Do(req)
	if err != nil {
		return m.fail(*src, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return m.fail(*src, fmt.Errorf("http status %d", resp.StatusCode))
	}
	lr := &io.LimitedReader{R: resp.Body, N: max + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return m.fail(*src, err)
	}
	if int64(len(b)) > max {
		return m.fail(*src, fmt.Errorf("source exceeds max_bytes=%d", max))
	}

	entries, err := validateLines(src.Kind, string(b))
	if err != nil {
		return m.fail(*src, err)
	}
	if src.MinEntries > 0 && len(entries) < src.MinEntries {
		return m.fail(*src, fmt.Errorf("too few valid entries: %d < %d", len(entries), src.MinEntries))
	}
	normalized := strings.Join(entries, "\n") + "\n"
	sum := sha256.Sum256([]byte(normalized))
	digest := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(m.cacheDir, 0o755); err != nil {
		return m.fail(*src, err)
	}
	dst := filepath.Join(m.cacheDir, src.ID+".lst")
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, []byte(normalized), 0o600); err != nil {
		return m.fail(*src, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return m.fail(*src, err)
	}

	m.mu.Lock()
	m.states[src.ID] = State{ID: src.ID, Name: src.Name, Kind: src.Kind, URL: src.URL, Enabled: src.Enabled, Ready: true, Entries: len(entries), SHA256: digest, UpdatedAt: time.Now().UTC(), Description: src.Description}
	m.mu.Unlock()
	return nil
}

func (m *Manager) fail(src Source, err error) error {
	m.mu.Lock()
	st := m.states[src.ID]
	st.LastError = err.Error()
	m.states[src.ID] = st
	m.mu.Unlock()
	return err
}

func (m *Manager) inspectCache() {
	for _, src := range m.reg.Sources {
		if src.Kind == "reference" {
			continue
		}
		path := filepath.Join(m.cacheDir, src.ID+".lst")
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		h := sha256.New()
		scanner := bufio.NewScanner(io.TeeReader(f, h))
		count := 0
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) != "" {
				count++
			}
		}
		_ = f.Close()
		if scanner.Err() != nil {
			continue
		}
		info, _ := os.Stat(path)
		st := m.states[src.ID]
		st.Ready = true
		st.Entries = count
		st.SHA256 = hex.EncodeToString(h.Sum(nil))
		if info != nil {
			st.UpdatedAt = info.ModTime().UTC()
		}
		m.states[src.ID] = st
	}
}

func validateLines(kind, body string) ([]string, error) {
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
