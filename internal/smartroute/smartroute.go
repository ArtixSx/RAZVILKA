package smartroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

const (
	schema         = 2
	defaultProfile = "network-unknown"
	legacyProfile  = "legacy-unscoped"
)

type Evidence struct {
	Route       string           `json:"route"`
	Status      string           `json:"status"`
	LatencyMS   int64            `json:"latency_ms,omitempty"`
	Score       int              `json:"score"`
	EgressIP    string           `json:"egress_ip,omitempty"`
	Evidence    string           `json:"evidence_source,omitempty"`
	Level       evidence.Level   `json:"evidence_level"`
	Outcome     evidence.Outcome `json:"outcome,omitempty"`
	ProbeID     string           `json:"probe_id,omitempty"`
	FreshUntil  string           `json:"fresh_until,omitempty"`
	ConfirmedAt string           `json:"confirmed_at"`
}

type ServiceState struct {
	SelectedRoute string              `json:"selected_route,omitempty"`
	LastSwitch    string              `json:"last_switch,omitempty"`
	Reason        string              `json:"reason,omitempty"`
	Evidence      map[string]Evidence `json:"evidence"`
}

type Snapshot struct {
	Schema         int                     `json:"schema"`
	NetworkProfile string                  `json:"network_profile"`
	KnownProfiles  int                     `json:"known_profiles"`
	Hysteresis     int                     `json:"hysteresis"`
	CooldownMinute int                     `json:"cooldown_minutes"`
	EvidenceHours  int                     `json:"evidence_ttl_hours"`
	Services       map[string]ServiceState `json:"services"`
}

type Decision struct {
	ServiceID string `json:"service_id"`
	Previous  string `json:"previous,omitempty"`
	Selected  string `json:"selected,omitempty"`
	Changed   bool   `json:"changed"`
	Reason    string `json:"reason"`
}

type document struct {
	Schema   int                                `json:"schema"`
	Profiles map[string]map[string]ServiceState `json:"profiles"`
}

type Manager struct {
	Path       string
	Hysteresis int
	Cooldown   time.Duration
	TTL        time.Duration
	// Profile supplies a privacy-safe identifier for the current WAN network.
	// Evidence and selections are never reused across different identifiers.
	Profile func() string
	now     func() time.Time
	mu      sync.RWMutex
	doc     document
}

func New(path string) (*Manager, error) {
	m := &Manager{Path: path, Hysteresis: 12, Cooldown: 10 * time.Minute, TTL: 24 * time.Hour, now: time.Now, doc: document{Schema: schema, Profiles: map[string]map[string]ServiceState{}}}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Observe(results []testlab.Result) ([]Decision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	services := m.servicesLocked(m.activeProfileLocked())
	touched := map[string]bool{}
	now := m.now().UTC()
	for _, result := range results {
		result.NormalizeEvidence()
		level := result.AssuranceLevel()
		if !level.AtLeast(evidence.Route) || result.ServiceID == "" || result.Route == "" || !knownStatus(result.Status) {
			continue
		}
		state := services[result.ServiceID]
		if state.Evidence == nil {
			state.Evidence = map[string]Evidence{}
		}
		checked := result.CheckedAt
		if parsed, err := time.Parse(time.RFC3339, checked); err != nil || parsed.After(now.Add(time.Minute)) {
			checked = now.Format(time.RFC3339)
		}
		probeID := ""
		if result.EvidenceV2 != nil {
			probeID = result.EvidenceV2.ProbeID
		}
		state.Evidence[result.Route] = Evidence{Route: result.Route, Status: result.Status, LatencyMS: result.LatencyMS, Score: score(result.Route, result.Status, result.LatencyMS), EgressIP: result.EgressIP, Evidence: result.EvidenceSource, Level: level, Outcome: result.Outcome, ProbeID: probeID, FreshUntil: result.EvidenceFreshUntil, ConfirmedAt: checked}
		services[result.ServiceID] = state
		touched[result.ServiceID] = true
	}
	ids := make([]string, 0, len(touched))
	for id := range touched {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	decisions := make([]Decision, 0, len(ids))
	for _, id := range ids {
		decisions = append(decisions, m.evaluateLocked(services, id, now))
	}
	if len(touched) > 0 {
		if err := m.saveLocked(); err != nil {
			return nil, err
		}
	}
	return decisions, nil
}

func (m *Manager) Suggest(serviceID, fallback string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.doc.Profiles[m.activeProfileLocked()][serviceID]
	if !ok || state.SelectedRoute == "" {
		return fallback
	}
	confirmed, ok := state.Evidence[state.SelectedRoute]
	if !ok || !viable(confirmed) || m.expired(confirmed, m.now().UTC()) {
		return fallback
	}
	return state.SelectedRoute
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	profile := m.activeProfileLocked()
	current := m.doc.Profiles[profile]
	services := make(map[string]ServiceState, len(current))
	for id, state := range current {
		copyState := state
		copyState.Evidence = make(map[string]Evidence, len(state.Evidence))
		for route, confirmed := range state.Evidence {
			copyState.Evidence[route] = confirmed
		}
		services[id] = copyState
	}
	return Snapshot{Schema: schema, NetworkProfile: profile, KnownProfiles: len(m.doc.Profiles), Hysteresis: m.Hysteresis, CooldownMinute: int(m.Cooldown.Minutes()), EvidenceHours: int(m.TTL.Hours()), Services: services}
}

func (m *Manager) evaluateLocked(services map[string]ServiceState, serviceID string, now time.Time) Decision {
	state := services[serviceID]
	decision := Decision{ServiceID: serviceID, Previous: state.SelectedRoute, Selected: state.SelectedRoute, Reason: "insufficient-confirmed-evidence"}
	valid := make([]Evidence, 0, len(state.Evidence))
	for _, confirmed := range state.Evidence {
		if !m.expired(confirmed, now) {
			valid = append(valid, confirmed)
		}
	}
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].Score == valid[j].Score {
			return valid[i].Route < valid[j].Route
		}
		return valid[i].Score > valid[j].Score
	})
	if len(valid) == 0 || !viable(valid[0]) {
		state.Reason = decision.Reason
		services[serviceID] = state
		return decision
	}
	best := valid[0]
	current, hasCurrent := state.Evidence[state.SelectedRoute]
	selectBest := state.SelectedRoute == "" || !hasCurrent || m.expired(current, now)
	reason := "selected-first-confirmed-route"
	if !selectBest && best.Route == state.SelectedRoute {
		decision.Reason = "current-route-remains-best"
		state.Reason = decision.Reason
		services[serviceID] = state
		return decision
	}
	if !selectBest && !viable(current) {
		selectBest = true
		reason = "confirmed-failover"
	}
	if !selectBest && withinCooldown(state.LastSwitch, now, m.Cooldown) {
		decision.Reason = "switch-cooldown-active"
		state.Reason = decision.Reason
		services[serviceID] = state
		return decision
	}
	if !selectBest && best.Score >= current.Score+m.Hysteresis {
		selectBest = true
		reason = fmt.Sprintf("score-improved-by-%d", best.Score-current.Score)
	}
	if !selectBest {
		decision.Reason = "hysteresis-kept-current-route"
		state.Reason = decision.Reason
		services[serviceID] = state
		return decision
	}
	state.SelectedRoute = best.Route
	state.LastSwitch = now.Format(time.RFC3339)
	state.Reason = reason
	services[serviceID] = state
	decision.Selected = best.Route
	decision.Changed = decision.Previous != best.Route
	decision.Reason = reason
	return decision
}

func (m *Manager) expired(confirmed Evidence, now time.Time) bool {
	checked, err := time.Parse(time.RFC3339, confirmed.ConfirmedAt)
	return err != nil || now.Sub(checked) > m.TTL
}

func score(route, status string, latency int64) int {
	base := map[string]int{"pass": 100, "partial": 62, "fail": 0}[status]
	cost := map[string]int{"direct": 0, "nfqws2": 3, "usque": 6, "warp-wg": 9, "sing-box": 11, "xray": 11, "amneziawg": 9}[route]
	penalty := int(latency / 100)
	if penalty > 30 {
		penalty = 30
	}
	value := base - cost - penalty
	if value < 0 {
		return 0
	}
	return value
}

func viable(confirmed Evidence) bool {
	return confirmed.Status == "pass" && confirmed.Level.AtLeast(evidence.Service) && (confirmed.Outcome == "" || confirmed.Outcome == evidence.OutcomeServiceAccepted)
}
func knownStatus(status string) bool {
	return status == "pass" || status == "partial" || status == "fail"
}

func withinCooldown(value string, now time.Time, cooldown time.Duration) bool {
	last, err := time.Parse(time.RFC3339, value)
	return err == nil && now.Sub(last) < cooldown
}

func (m *Manager) load() error {
	if m.Path == "" {
		return nil
	}
	b, err := os.ReadFile(m.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Smart Route state: %w", err)
	}
	var header struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(b, &header); err != nil {
		return fmt.Errorf("decode Smart Route state: %w", err)
	}
	if header.Schema == 1 {
		var old struct {
			Schema   int                     `json:"schema"`
			Services map[string]ServiceState `json:"services"`
		}
		if err := json.Unmarshal(b, &old); err != nil {
			return fmt.Errorf("decode Smart Route v1 state: %w", err)
		}
		if old.Services == nil {
			old.Services = map[string]ServiceState{}
		}
		m.doc = document{Schema: schema, Profiles: map[string]map[string]ServiceState{legacyProfile: old.Services}}
		return nil
	}
	if header.Schema != schema {
		return fmt.Errorf("unsupported Smart Route schema %d", header.Schema)
	}
	var loaded document
	if err := json.Unmarshal(b, &loaded); err != nil {
		return fmt.Errorf("decode Smart Route state: %w", err)
	}
	if loaded.Profiles == nil {
		loaded.Profiles = map[string]map[string]ServiceState{}
	}
	m.doc = loaded
	return nil
}

func (m *Manager) saveLocked() error {
	if m.Path == "" {
		return nil
	}
	m.doc.Schema = schema
	b, err := json.MarshalIndent(m.doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.Path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(m.Path), ".smart-route-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(b); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, m.Path); err != nil {
		return err
	}
	return os.Chmod(m.Path, 0600)
}

func (m *Manager) activeProfileLocked() string {
	if m.Profile == nil {
		return defaultProfile
	}
	profile := strings.TrimSpace(m.Profile())
	if profile == "" {
		return defaultProfile
	}
	return profile
}

func (m *Manager) servicesLocked(profile string) map[string]ServiceState {
	if m.doc.Profiles == nil {
		m.doc.Profiles = map[string]map[string]ServiceState{}
	}
	services := m.doc.Profiles[profile]
	if services == nil {
		services = map[string]ServiceState{}
		m.doc.Profiles[profile] = services
	}
	return services
}
