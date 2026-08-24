package customservices

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

const maxServices = 256

var nonID = regexp.MustCompile(`[^a-z0-9]+`)

type document struct {
	Schema   int               `json:"schema"`
	Services []catalog.Service `json:"services"`
}

type Manager struct {
	mu       sync.RWMutex
	path     string
	services []catalog.Service
}

func Load(path string) (*Manager, error) {
	m := &Manager{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := m.saveLocked(); err != nil {
			return nil, err
		}
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var doc document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("decode custom services: %w", err)
	}
	if doc.Schema != 1 {
		return nil, fmt.Errorf("unsupported custom services schema %d", doc.Schema)
	}
	if len(doc.Services) > maxServices {
		return nil, fmt.Errorf("custom services limit exceeded")
	}
	if err := catalog.Validate(catalog.Catalog{Services: doc.Services}); err != nil {
		return nil, err
	}
	m.services = clone(doc.Services)
	return m, nil
}

func (m *Manager) List() []catalog.Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.services)
}

func (m *Manager) Create(service catalog.Service, reserved map[string]bool) (catalog.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.services) >= maxServices {
		return catalog.Service{}, fmt.Errorf("custom services limit reached")
	}
	service.ID = customID(service.ID, service.Name)
	if reserved[service.ID] || m.indexLocked(service.ID) >= 0 {
		return catalog.Service{}, fmt.Errorf("service id %q already exists", service.ID)
	}
	service = normalize(service)
	if err := validateOne(service); err != nil {
		return catalog.Service{}, err
	}
	previous := clone(m.services)
	m.services = append(m.services, service)
	m.sortLocked()
	if err := m.saveLocked(); err != nil {
		m.services = previous
		return catalog.Service{}, err
	}
	return service, nil
}

func (m *Manager) Update(id string, service catalog.Service) (catalog.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	index := m.indexLocked(id)
	if index < 0 {
		return catalog.Service{}, os.ErrNotExist
	}
	service.ID = id
	if service.Provenance == nil && m.services[index].Provenance != nil {
		provenance := *m.services[index].Provenance
		service.Provenance = &provenance
	}
	if len(service.SourceRefs) == 0 && service.Provenance != nil {
		service.SourceRefs = append([]string(nil), m.services[index].SourceRefs...)
	}
	if service.Note == "" && service.Provenance != nil {
		service.Note = m.services[index].Note
	}
	service = normalize(service)
	if err := validateOne(service); err != nil {
		return catalog.Service{}, err
	}
	previous := clone(m.services)
	m.services[index] = service
	m.sortLocked()
	if err := m.saveLocked(); err != nil {
		m.services = previous
		return catalog.Service{}, err
	}
	return service, nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	index := m.indexLocked(id)
	if index < 0 {
		return os.ErrNotExist
	}
	previous := clone(m.services)
	m.services = append(m.services[:index:index], m.services[index+1:]...)
	if err := m.saveLocked(); err != nil {
		m.services = previous
		return err
	}
	return nil
}

func (m *Manager) Has(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.indexLocked(id) >= 0
}

// Merge validates the complete resulting catalog and commits it with one
// atomic rename. Existing custom services are updated only when allowUpdates
// is true; unrelated entries are preserved.
func (m *Manager) Merge(in []catalog.Service, reserved map[string]bool, allowUpdates bool) ([]catalog.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := clone(m.services)
	index := make(map[string]int, len(result))
	for i := range result {
		index[result[i].ID] = i
	}
	for _, service := range in {
		if !strings.HasPrefix(service.ID, "custom-") {
			return nil, fmt.Errorf("service id %q must use custom- prefix", service.ID)
		}
		if reserved[service.ID] {
			return nil, fmt.Errorf("service id %q is reserved", service.ID)
		}
		service = normalize(service)
		if err := validateOne(service); err != nil {
			return nil, err
		}
		if i, ok := index[service.ID]; ok {
			if !allowUpdates {
				return nil, fmt.Errorf("custom service %q already exists", service.ID)
			}
			result[i] = service
			continue
		}
		if len(result) >= maxServices {
			return nil, fmt.Errorf("custom services limit reached")
		}
		index[service.ID] = len(result)
		result = append(result, service)
	}
	return m.replaceLocked(result)
}

// ReplaceAll restores a previously captured custom catalog after a failed
// profile import transaction.
func (m *Manager) ReplaceAll(services []catalog.Service, reserved map[string]bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, service := range services {
		if !strings.HasPrefix(service.ID, "custom-") || reserved[service.ID] {
			return fmt.Errorf("invalid custom service id %q", service.ID)
		}
	}
	_, err := m.replaceLocked(clone(services))
	return err
}

func (m *Manager) replaceLocked(services []catalog.Service) ([]catalog.Service, error) {
	if len(services) > maxServices {
		return nil, fmt.Errorf("custom services limit exceeded")
	}
	if err := catalog.Validate(catalog.Catalog{Services: services}); err != nil {
		return nil, err
	}
	previous := clone(m.services)
	m.services = clone(services)
	m.sortLocked()
	if err := m.saveLocked(); err != nil {
		m.services = previous
		return nil, err
	}
	return clone(m.services), nil
}

func (m *Manager) indexLocked(id string) int {
	for i := range m.services {
		if m.services[i].ID == id {
			return i
		}
	}
	return -1
}

func (m *Manager) sortLocked() {
	sort.Slice(m.services, func(i, j int) bool {
		return strings.ToLower(m.services[i].Name) < strings.ToLower(m.services[j].Name)
	})
}

func (m *Manager) saveLocked() error {
	b, err := json.MarshalIndent(document{Schema: 1, Services: m.services}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".custom-services.tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, m.path)
}

func normalize(s catalog.Service) catalog.Service {
	s.Name = strings.TrimSpace(s.Name)
	s.Category = strings.TrimSpace(s.Category)
	if s.Category == "" {
		s.Category = "Пользовательские"
	}
	s.Icon = strings.TrimSpace(s.Icon)
	if s.Icon == "" {
		s.Icon = "+"
	}
	s.Description = strings.TrimSpace(s.Description)
	s.Note = strings.TrimSpace(s.Note)
	if s.Provenance != nil {
		p := *s.Provenance
		p.Provider = strings.TrimSpace(p.Provider)
		p.EntryID = strings.TrimSpace(p.EntryID)
		p.URL = strings.TrimSpace(p.URL)
		p.License = strings.TrimSpace(p.License)
		p.SHA256 = strings.TrimSpace(p.SHA256)
		p.FetchedAt = strings.TrimSpace(p.FetchedAt)
		s.Provenance = &p
	}
	s.Domains = normalizedList(s.Domains, true)
	s.CIDRs = normalizedList(s.CIDRs, false)
	if len(s.Strategy) == 0 {
		s.Strategy = []string{"auto"}
	} else {
		s.Strategy = normalizedList(s.Strategy, false)
	}
	s.SourceRefs = normalizedList(s.SourceRefs, false)
	s.ProbeURL = strings.TrimSpace(s.ProbeURL)
	for index := range s.Probes {
		s.Probes[index].ID = strings.ToLower(strings.TrimSpace(s.Probes[index].ID))
		s.Probes[index].Label = strings.TrimSpace(s.Probes[index].Label)
		s.Probes[index].URL = strings.TrimSpace(s.Probes[index].URL)
	}
	return s
}

func validateOne(s catalog.Service) error {
	if len(s.Domains) == 0 && len(s.CIDRs) == 0 {
		return fmt.Errorf("add at least one domain or CIDR")
	}
	if len(s.Domains) > 2000 || len(s.CIDRs) > 2000 {
		return fmt.Errorf("domain or CIDR limit exceeded")
	}
	return catalog.Validate(catalog.Catalog{Services: []catalog.Service{s}})
}

func normalizedList(in []string, lower bool) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if lower {
			item = strings.ToLower(strings.TrimSuffix(item, "."))
		}
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func customID(raw, name string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		raw = strings.ToLower(strings.TrimSpace(name))
	}
	raw = strings.Trim(nonID.ReplaceAllString(raw, "-"), "-")
	raw = strings.TrimPrefix(raw, "custom-")
	if len(raw) > 56 {
		raw = strings.Trim(raw[:56], "-")
	}
	if raw == "" {
		raw = "service"
	}
	return "custom-" + raw
}

func clone(in []catalog.Service) []catalog.Service {
	out := make([]catalog.Service, len(in))
	for i, s := range in {
		out[i] = s
		out[i].Domains = append([]string(nil), s.Domains...)
		out[i].CIDRs = append([]string(nil), s.CIDRs...)
		out[i].Strategy = append([]string(nil), s.Strategy...)
		out[i].SourceRefs = append([]string(nil), s.SourceRefs...)
		out[i].Probes = append([]catalog.Probe(nil), s.Probes...)
		if s.Provenance != nil {
			p := *s.Provenance
			out[i].Provenance = &p
		}
	}
	return out
}
