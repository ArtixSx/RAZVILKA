package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

type ServiceState struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"` // legacy compatibility
	Route   string `json:"route,omitempty"`
}

type Config struct {
	Listen          string                  `json:"listen"`
	Services        map[string]ServiceState `json:"services"` // desired/draft state
	AppliedServices map[string]ServiceState `json:"applied_services,omitempty"`
	EngineOrder     []string                `json:"engine_order"`
	SafeMode        bool                    `json:"safe_mode"`
	CatalogPath     string                  `json:"catalog_path,omitempty"`
	Revision        uint64                  `json:"revision,omitempty"`
	AppliedRevision uint64                  `json:"applied_revision,omitempty"`
	LastAppliedAt   string                  `json:"last_applied_at,omitempty"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func Default() Config {
	return Config{Listen: ":8787", Services: map[string]ServiceState{}, AppliedServices: map[string]ServiceState{}, EngineOrder: []string{"nfqws2", "usque", "warp-wg", "sing-box"}, SafeMode: true}
}

func Load(path string) (*Store, error) {
	s := &Store{path: path, cfg: Default()}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := s.Save(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.cfg); err != nil {
		return nil, err
	}
	if s.cfg.Services == nil {
		s.cfg.Services = map[string]ServiceState{}
	}
	if s.cfg.AppliedServices == nil {
		s.cfg.AppliedServices = cloneServices(s.cfg.Services)
	}
	if s.cfg.Listen == "" {
		s.cfg.Listen = ":8787"
	}
	if len(s.cfg.EngineOrder) == 0 {
		s.cfg.EngineOrder = []string{"nfqws2", "usque", "warp-wg", "sing-box"}
	}
	if s.cfg.AppliedRevision == 0 && len(s.cfg.AppliedServices) > 0 {
		s.cfg.AppliedRevision = s.cfg.Revision
	}
	return s, nil
}

func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.Services = cloneServices(s.cfg.Services)
	c.AppliedServices = cloneServices(s.cfg.AppliedServices)
	c.EngineOrder = append([]string(nil), s.cfg.EngineOrder...)
	return c
}

func normalizeState(state ServiceState) ServiceState {
	if state.Route == "" {
		state.Route = state.Mode
	}
	if state.Route == "" {
		state.Route = "auto"
	}
	state.Mode = state.Route
	return state
}

func (s *Store) UpdateService(id string, state ServiceState) error {
	state = normalizeState(state)
	s.mu.Lock()
	s.cfg.Services[id] = state
	s.cfg.Revision++
	s.mu.Unlock()
	return s.Save()
}

func (s *Store) Dirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !reflect.DeepEqual(s.cfg.Services, s.cfg.AppliedServices)
}

func (s *Store) ApplyDraft() error {
	s.mu.Lock()
	s.cfg.AppliedServices = cloneServices(s.cfg.Services)
	s.cfg.AppliedRevision = s.cfg.Revision
	s.cfg.LastAppliedAt = time.Now().UTC().Format(time.RFC3339)
	s.mu.Unlock()
	return s.Save()
}

func (s *Store) DiscardDraft() error {
	s.mu.Lock()
	s.cfg.Services = cloneServices(s.cfg.AppliedServices)
	s.cfg.Revision++
	s.mu.Unlock()
	return s.Save()
}

func (s *Store) Save() error {
	s.mu.RLock()
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
func cloneServices(in map[string]ServiceState) map[string]ServiceState {
	out := make(map[string]ServiceState, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
