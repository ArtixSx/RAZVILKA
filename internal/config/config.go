package config

import (
	"encoding/json"
	"errors"
	"fmt"
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
	SchemaVersion   int                     `json:"schema_version"`
	Listen          string                  `json:"listen"`
	Services        map[string]ServiceState `json:"services"` // desired/draft state
	AppliedServices map[string]ServiceState `json:"applied_services"`
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
	return Config{SchemaVersion: CurrentSchemaVersion, Listen: ":8787", Services: map[string]ServiceState{}, AppliedServices: map[string]ServiceState{}, EngineOrder: []string{"nfqws2", "usque", "warp-wg", "sing-box"}, SafeMode: true}
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
	cfg, _, err := InspectBytes(b)
	if err != nil {
		return nil, err
	}
	s.cfg = cfg
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
	defer s.mu.Unlock()
	previous := cloneConfig(s.cfg)
	s.cfg.Services[id] = state
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

func (s *Store) Dirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !reflect.DeepEqual(s.cfg.Services, s.cfg.AppliedServices)
}

func (s *Store) ApplyDraft() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneConfig(s.cfg)
	s.cfg.AppliedServices = cloneServices(s.cfg.Services)
	s.cfg.AppliedRevision = s.cfg.Revision
	s.cfg.LastAppliedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

func (s *Store) DiscardDraft() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneConfig(s.cfg)
	s.cfg.Services = cloneServices(s.cfg.AppliedServices)
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create config transaction: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("protect config transaction: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("write config transaction: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync config transaction: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config transaction: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("commit config transaction: %w", err)
	}
	return nil
}

func cloneConfig(in Config) Config {
	out := in
	out.Services = cloneServices(in.Services)
	out.AppliedServices = cloneServices(in.AppliedServices)
	out.EngineOrder = append([]string(nil), in.EngineOrder...)
	return out
}

func cloneServices(in map[string]ServiceState) map[string]ServiceState {
	out := make(map[string]ServiceState, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
