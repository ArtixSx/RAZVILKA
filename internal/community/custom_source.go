package community

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const maxCustomSourceBytes = 256 << 10
const maxCustomPreviews = 8

var ErrCustomSource = errors.New("unsupported service definition source")
var ErrPreviewExpired = errors.New("reviewed source expired; preview again")

// CustomSource imports data only. Exactly one of URL and Content is required.
// No credentials, scripts, repository checkout or arbitrary executable config.
type CustomSource struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	ProbeURL string `json:"probe_url,omitempty"`
	URL      string `json:"url,omitempty"`
	Content  string `json:"content,omitempty"`
	Format   string `json:"format"`
}

// GitHubSourceURL accepts a file, never a repo root, query credential or host lookalike.
// Refs containing a slash must use an unambiguous raw URL (or a commit SHA).
func GitHubSourceURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", ErrCustomSource
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.ContainsAny(p, "\\\x00\r\n") {
			return "", ErrCustomSource
		}
	}
	switch strings.ToLower(u.Host) {
	case "github.com":
		if len(parts) < 5 || (parts[2] != "blob" && parts[2] != "raw") {
			return "", ErrCustomSource
		}
		parts = append(parts[:2], parts[3:]...)
		u.Host = "raw.githubusercontent.com"
		u.Path = "/" + strings.Join(parts, "/")
	case "raw.githubusercontent.com":
		if len(parts) < 4 {
			return "", ErrCustomSource
		}
	default:
		return "", ErrCustomSource
	}
	if publicfetch.ValidateURL(u.String()) != nil {
		return "", ErrCustomSource
	}
	return u.String(), nil
}
func customPublicDomain(s string) bool {
	s = strings.ToLower(s)
	if _, err := normalizeDomain(s); err != nil {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".internal", ".home.arpa", ".onion"} {
		if strings.HasSuffix(s, suffix) {
			return false
		}
	}
	return true
}

func (m *Manager) PreviewCustom(ctx context.Context, in CustomSource, existing []catalog.Service) (Preview, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Preview{}, err
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Category = strings.TrimSpace(in.Category)
	if in.Name == "" || len(in.Name) > 120 || len(in.Category) > 80 || len(in.URL) > 2048 || len(in.ProbeURL) > 2048 || len(in.Content) > maxCustomSourceBytes || (in.URL == "") == (strings.TrimSpace(in.Content) == "") {
		return Preview{}, ErrCustomSource
	}
	if in.Category == "" {
		in.Category = "Мои сервисы"
	}
	if in.Format != "domains" && in.Format != "cidrs" {
		return Preview{}, ErrCustomSource
	}
	if in.ProbeURL != "" {
		u, e := url.Parse(strings.TrimSpace(in.ProbeURL))
		if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" || net.ParseIP(u.Hostname()) != nil || !customPublicDomain(u.Hostname()) {
			return Preview{}, ErrCustomSource
		}
		u.Host = strings.ToLower(u.Host)
		in.ProbeURL = u.String()
	}
	var data []byte
	var err error
	if in.URL != "" {
		in.URL, err = GitHubSourceURL(in.URL)
		if err != nil {
			return Preview{}, err
		}
	}
	hash := sha256.New()
	identity, _ := json.Marshal(struct{ Name, Category, URL, Format, ProbeURL string }{in.Name, in.Category, in.URL, in.Format, in.ProbeURL})
	hash.Write(identity)
	domains, cidrs := []string{}, []string{}
	skipped := 0
	if in.URL != "" && in.Format == "domains" {
		domains, skipped, err = m.fetchDomainTree(ctx, in.URL, hash)
	} else {
		if in.URL != "" {
			data, err = m.fetch(ctx, in.URL)
		} else {
			data = []byte(in.Content)
		}
		if err == nil {
			if strings.Contains(strings.ToLower(string(data)), "<html") || strings.Contains(strings.ToLower(string(data)), "<!doctype") {
				return Preview{}, ErrCustomSource
			}
			hash.Write(data)
			if in.Format == "domains" {
				domains, skipped = parseDomains(data)
			} else {
				cidrs, skipped = parseCIDRs(data)
			}
		}
	}
	if err != nil {
		return Preview{}, err
	}
	clean := make([]string, 0, len(domains))
	for _, s := range domains {
		if customPublicDomain(s) {
			clean = append(clean, s)
		} else {
			skipped++
		}
	}
	domains = clean
	if len(domains)+len(cidrs) == 0 || len(domains) > 2000 || len(cidrs) > 2000 {
		return Preview{}, ErrCustomSource
	}
	// Do not invent a broad probe domain; without it import remains passive.
	if in.ProbeURL != "" && len(domains) > 0 {
		u, _ := url.Parse(in.ProbeURL)
		matched := false
		for _, d := range domains {
			matched = matched || u.Hostname() == d || strings.HasSuffix(u.Hostname(), "."+d)
		}
		if !matched {
			return Preview{}, ErrCustomSource
		}
	}
	if err := ctx.Err(); err != nil {
		return Preview{}, err
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	id := "adhoc-" + digest[:24]
	now := time.Now()
	at := now.UTC().Format(time.RFC3339)
	entry := Entry{ID: id, Name: in.Name, Category: in.Category, Icon: "GH", Provider: "GitHub — свой список", SourcePage: in.URL, ProbeURL: in.ProbeURL, Access: Access{Status: "catalog", Note: "Доступность не проверена. Импорт не назначает маршрут."}}
	if in.URL == "" {
		entry.Provider = "Локальный файл / текст"
		entry.Icon = "TXT"
	}
	service := catalog.Service{ID: id, Name: in.Name, Category: in.Category, Icon: entry.Icon, Domains: domains, CIDRs: cidrs, Strategy: []string{"auto"}, ProbeURL: in.ProbeURL, SourceRefs: []string{"community:" + id}, Provenance: &catalog.Provenance{Provider: entry.Provider, EntryID: id, URL: in.URL, SHA256: digest, FetchedAt: at}}
	if err := catalog.Validate(catalog.Catalog{Services: []catalog.Service{service}}); err != nil {
		return Preview{}, ErrCustomSource
	}
	preview := Preview{Entry: entry, Service: service, Conflicts: findConflicts(service, existing), Skipped: skipped, SourceSHA: digest, FetchedAt: at, ImportGuard: "source-sha256"}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Expiring bounded review cache; it is not an external subscription store.
	count := 0
	oldest := ""
	var oldestAt time.Time
	for key, c := range m.cache {
		if !strings.HasPrefix(key, "adhoc-") {
			continue
		}
		if c.at.After(now) || now.Sub(c.at) >= 10*time.Minute {
			delete(m.cache, key)
			continue
		}
		count++
		if oldest == "" || c.at.Before(oldestAt) {
			oldest, oldestAt = key, c.at
		}
	}
	if _, exists := m.cache[id]; !exists && count >= maxCustomPreviews {
		delete(m.cache, oldest)
	}
	m.cache[id] = cachedPreview{preview: clonePreview(preview), at: now}
	return preview, nil
}
