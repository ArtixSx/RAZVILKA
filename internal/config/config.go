package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type ServiceState struct {
	Enabled bool     `json:"enabled"`
	Mode    string   `json:"mode,omitempty"` // legacy compatibility
	Route   string   `json:"route,omitempty"`
	Sources []string `json:"sources,omitempty"` // empty means every LAN client
}

type Config struct {
	SchemaVersion        int                      `json:"schema_version"`
	Listen               string                   `json:"listen"`
	Services             map[string]ServiceState  `json:"services"` // desired/draft state
	AppliedServices      map[string]ServiceState  `json:"applied_services"`
	EngineOrder          []string                 `json:"engine_order"`
	SafeMode             bool                     `json:"safe_mode"`
	CatalogPath          string                   `json:"catalog_path,omitempty"`
	Revision             uint64                   `json:"revision,omitempty"`
	AppliedRevision      uint64                   `json:"applied_revision,omitempty"`
	LastAppliedAt        string                   `json:"last_applied_at,omitempty"`
	ServicePolicies      map[string]ServicePolicy `json:"service_policies,omitempty"`
	ServiceControl       ServiceControl           `json:"service_control,omitempty"`
	NetworkPolicy        *NetworkPolicy           `json:"network_policy,omitempty"`
	AppliedNetworkPolicy *NetworkPolicy           `json:"applied_network_policy,omitempty"`
}

type Store struct {
	mu             sync.RWMutex
	path           string
	cfg            Config
	diskImage      restorejournal.Image
	writeUncertain bool
}

type DraftScope string

const (
	DraftScopeAll      DraftScope = "all"
	DraftScopeServices DraftScope = "services"
	DraftScopeDevices  DraftScope = "devices"
)

func Default() Config {
	return Config{SchemaVersion: CurrentSchemaVersion, Listen: ":8787", Services: map[string]ServiceState{}, AppliedServices: map[string]ServiceState{}, EngineOrder: []string{"nfqws2", "usque", "warp-wg", "sing-box"}, SafeMode: true}
}

func Load(path string) (*Store, error) {
	s := &Store{path: path, cfg: Default()}
	image, err := restorejournal.ReadFileImage(context.Background(), path)
	if err == nil && !image.Exists {
		if err := s.Save(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	cfg, _, err := InspectBytes(image.Data)
	if err != nil {
		return nil, err
	}
	s.cfg = cfg
	s.diskImage = image
	return s, nil
}

func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneConfig(s.cfg)
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
	sources, err := NormalizeSources(state.Sources)
	if err != nil {
		return err
	}
	state.Sources = sources
	state = normalizeState(state)
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneConfig(s.cfg)
	s.cfg.Services[id] = state
	if !reflect.DeepEqual(previous.Services[id], state) {
		fenceServicePolicy(&s.cfg, id, state.Route, s.cfg.AppliedServices[id].Sources)
	}
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

// SetSafeMode changes only the live-write gate. Existing committed routes are
// not claimed as stopped or modified by this setting change.
func (s *Store) SetSafeMode(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.SafeMode == enabled {
		return nil
	}
	previous := cloneConfig(s.cfg)
	s.cfg.SafeMode = enabled
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

// MergeDraft stages a portable profile in one config transaction. It never
// changes AppliedServices, so importing a shared profile cannot affect live
// routing before the normal preview/validate/apply flow is completed.
func (s *Store) MergeDraft(states map[string]ServiceState) error {
	normalizedStates := make(map[string]ServiceState, len(states))
	for id, state := range states {
		sources, err := NormalizeSources(state.Sources)
		if err != nil {
			return fmt.Errorf("service %s: %w", id, err)
		}
		state.Sources = sources
		normalizedStates[id] = normalizeState(state)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneConfig(s.cfg)
	for id, state := range normalizedStates {
		s.cfg.Services[id] = state
	}
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

// ReplaceDraft is used to restore the exact desired state if a multi-store
// profile import cannot finish. AppliedServices are deliberately untouched.
func (s *Store) ReplaceDraft(states map[string]ServiceState) error {
	_, err := s.ReplaceDraftWithRollback(states)
	return err
}

// ReplaceDraftWithRollback is a guarded undo for a live multi-store import.
// A later config change (including Apply or Safe Mode) blocks automatic undo.
// It deliberately does not claim durable recovery across process termination.
func (s *Store) ReplaceDraftWithRollback(states map[string]ServiceState) (func() error, error) {
	normalizedStates := make(map[string]ServiceState, len(states))
	for id, state := range states {
		sources, err := NormalizeSources(state.Sources)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", id, err)
		}
		state.Sources = sources
		normalizedStates[id] = normalizeState(state)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneConfig(s.cfg)
	s.cfg.Services = cloneServices(normalizedStates)
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return nil, err
	}
	committed := cloneConfig(s.cfg)
	used := false
	return func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if used {
			return nil
		}
		if !reflect.DeepEqual(s.cfg, committed) {
			return errors.New("configuration changed after import; rollback refused")
		}
		s.cfg = cloneConfig(previous)
		if err := s.saveLocked(); err != nil {
			s.cfg = cloneConfig(committed)
			return err
		}
		used = true
		return nil
	}, nil
}

func (s *Store) DeleteService(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneConfig(s.cfg)
	delete(s.cfg.Services, id)
	delete(s.cfg.AppliedServices, id)
	delete(s.cfg.ServicePolicies, id)
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

func (s *Store) Dirty() bool {
	return s.DirtyScope(DraftScopeAll)
}

func (s *Store) DirtyScope(scope DraftScope) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return draftScopeDirty(s.cfg, scope)
}

func (s *Store) ApplyDraft() error {
	_, err := s.ApplyDraftWithRollback()
	return err
}

// ApplyDraftWithRollback commits the desired state and returns a guarded undo
// function for the surrounding dataplane transaction. Undo refuses to clobber
// a configuration that changed after the commit.
func (s *Store) ApplyDraftWithRollback() (func() error, error) {
	return s.ApplyDraftScopeWithRollback(DraftScopeAll)
}

// ApplyDraftScopeWithRollback commits only fields owned by one UI section.
// Service routing and device/source policies share ServiceState on disk, but
// they must never be applied implicitly by a button on the other page.
func (s *Store) ApplyDraftScopeWithRollback(scope DraftScope) (func() error, error) {
	return s.applyDraftScopeWithRollback(scope, nil)
}

// ApplyDraftScopeAtRevisionWithRollback binds an explicit plan review to the
// same locked configuration image that is committed by the transaction.
func (s *Store) ApplyDraftScopeAtRevisionWithRollback(scope DraftScope, expectedRevision uint64) (func() error, error) {
	return s.applyDraftScopeWithRollback(scope, &expectedRevision)
}

func (s *Store) applyDraftScopeWithRollback(scope DraftScope, expectedRevision *uint64) (func() error, error) {
	if !validDraftScope(scope) {
		return nil, fmt.Errorf("unknown draft scope %q", scope)
	}
	s.mu.Lock()
	if expectedRevision != nil && s.cfg.Revision != *expectedRevision {
		s.mu.Unlock()
		return nil, ErrRevisionChanged
	}
	previous := cloneConfig(s.cfg)
	applyDraftScope(&s.cfg, scope)
	clearServiceStopAfterManualApply(&s.cfg)
	for id, state := range s.cfg.AppliedServices {
		if !reflect.DeepEqual(previous.AppliedServices[id], state) {
			fenceServicePolicy(&s.cfg, id, state.Route, state.Sources)
		}
	}
	s.cfg.AppliedRevision = s.cfg.Revision
	s.cfg.LastAppliedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		s.mu.Unlock()
		return nil, err
	}
	committed := cloneConfig(s.cfg)
	s.mu.Unlock()
	used := false
	return func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if used {
			return nil
		}
		if !reflect.DeepEqual(s.cfg, committed) {
			return errors.New("configuration changed after dataplane commit; automatic config rollback refused")
		}
		s.cfg = cloneConfig(previous)
		if err := s.saveLocked(); err != nil {
			s.cfg = committed
			return err
		}
		used = true
		return nil
	}, nil
}

func (s *Store) DiscardDraft() error {
	return s.DiscardDraftScope(DraftScopeAll)
}

func (s *Store) DiscardDraftScope(scope DraftScope) error {
	if !validDraftScope(scope) {
		return fmt.Errorf("unknown draft scope %q", scope)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneConfig(s.cfg)
	discardDraftScope(&s.cfg, scope)
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

func validDraftScope(scope DraftScope) bool {
	return scope == DraftScopeAll || scope == DraftScopeServices || scope == DraftScopeDevices
}

func draftScopeDirty(cfg Config, scope DraftScope) bool {
	if scope == DraftScopeAll {
		return !reflect.DeepEqual(cfg.Services, cfg.AppliedServices)
	}
	for id := range serviceKeys(cfg.Services, cfg.AppliedServices) {
		desired := normalizeState(cfg.Services[id])
		applied := normalizeState(cfg.AppliedServices[id])
		switch scope {
		case DraftScopeServices:
			if desired.Enabled != applied.Enabled || desired.Route != applied.Route {
				return true
			}
		case DraftScopeDevices:
			if !reflect.DeepEqual(desired.Sources, applied.Sources) {
				return true
			}
		}
	}
	return false
}

func applyDraftScope(cfg *Config, scope DraftScope) {
	if scope == DraftScopeAll {
		cfg.AppliedServices = cloneServices(cfg.Services)
		return
	}
	next := cloneServices(cfg.AppliedServices)
	for id, desired := range cfg.Services {
		desired = normalizeState(desired)
		applied := normalizeState(next[id])
		switch scope {
		case DraftScopeServices:
			applied.Enabled = desired.Enabled
			applied.Route = desired.Route
			applied.Mode = desired.Route
			applied.Sources = AppliedSources(*cfg, id)
		case DraftScopeDevices:
			applied.Sources = append([]string(nil), desired.Sources...)
		}
		next[id] = applied
	}
	cfg.AppliedServices = next
}

func discardDraftScope(cfg *Config, scope DraftScope) {
	if scope == DraftScopeAll {
		cfg.Services = cloneServices(cfg.AppliedServices)
		return
	}
	next := cloneServices(cfg.Services)
	for id := range serviceKeys(cfg.Services, cfg.AppliedServices) {
		desired := normalizeState(next[id])
		applied := normalizeState(cfg.AppliedServices[id])
		switch scope {
		case DraftScopeServices:
			desired.Enabled = applied.Enabled
			desired.Route = applied.Route
			desired.Mode = applied.Route
		case DraftScopeDevices:
			desired.Sources = append([]string(nil), applied.Sources...)
		}
		next[id] = desired
	}
	cfg.Services = next
}

func serviceKeys(left, right map[string]ServiceState) map[string]struct{} {
	keys := make(map[string]struct{}, len(left)+len(right))
	for id := range left {
		keys[id] = struct{}{}
	}
	for id := range right {
		keys[id] = struct{}{}
	}
	return keys
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if s.writeUncertain {
		return restorejournal.ErrRecovery
	}
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	target, err := restorejournal.OpenFileTarget(s.path)
	if err != nil {
		return err
	}
	defer target.Close()
	return s.persistLocked(target, b)
}

func (s *Store) persistLocked(target restorejournal.Target, data []byte) error {
	after := restorejournal.Image{Exists: true, Data: data}
	if err := target.CompareAndSwap(context.Background(), s.diskImage, after); err != nil {
		if errors.Is(err, restorejournal.ErrRecovery) {
			actual, readErr := target.Read(context.Background())
			if readErr == nil && actual.Exists == s.diskImage.Exists && bytes.Equal(actual.Data, s.diskImage.Data) {
				// The failed write provably left the old bytes unchanged.
				return restorejournal.ErrAborted
			}
			// Callers restore their old in-memory view on failure. Prevent that
			// view from overwriting a possibly committed file on the next write.
			s.writeUncertain = true
		}
		return err
	}
	s.diskImage = restorejournal.Image{Exists: true, Data: append([]byte(nil), data...)}
	return nil
}

func cloneConfig(in Config) Config {
	out := in
	out.NetworkPolicy = CloneNetworkPolicy(in.NetworkPolicy)
	out.AppliedNetworkPolicy = CloneNetworkPolicy(in.AppliedNetworkPolicy)
	out.ServiceControl = cloneServiceControl(in.ServiceControl)
	out.Services = cloneServices(in.Services)
	out.AppliedServices = cloneServices(in.AppliedServices)
	out.EngineOrder = append([]string(nil), in.EngineOrder...)
	out.ServicePolicies = cloneServicePolicies(in.ServicePolicies)
	return out
}

func cloneServices(in map[string]ServiceState) map[string]ServiceState {
	out := make(map[string]ServiceState, len(in))
	for k, v := range in {
		v.Sources = append([]string(nil), v.Sources...)
		out[k] = v
	}
	return out
}

func NormalizeSources(values []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, fmt.Errorf("invalid device source %q", value)
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		prefix = prefix.Masked()
		address := prefix.Addr()
		if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
			return nil, fmt.Errorf("unsafe device source %q", value)
		}
		canonical := prefix.String()
		if !seen[canonical] {
			seen[canonical] = true
			out = append(out, canonical)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
