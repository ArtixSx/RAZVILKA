package warp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type HealthPolicy struct {
	Enabled               bool `json:"enabled"`
	AcceptTOS             bool `json:"accept_tos"`
	AutoGenerateCandidate bool `json:"auto_generate_candidate"`
	AutoApplyCandidate    bool `json:"auto_apply_candidate"`
	FailureThreshold      int  `json:"failure_threshold"`
	MinFailedServices     int  `json:"min_failed_services"`
	CooldownHours         int  `json:"cooldown_hours"`
	MaxRotationsPerDay    int  `json:"max_rotations_per_day"`
}

type HealthState struct {
	ConsecutiveFailedRounds int      `json:"consecutive_failed_rounds"`
	LastChecked             string   `json:"last_checked,omitempty"`
	LastDecision            string   `json:"last_decision,omitempty"`
	LastFailedServices      []string `json:"last_failed_services,omitempty"`
	LastSuccessfulServices  []string `json:"last_successful_services,omitempty"`
	RouteEvidenceConfirmed  bool     `json:"route_evidence_confirmed"`
	Rotations               []string `json:"rotations,omitempty"`
	LastActivation          string   `json:"last_activation,omitempty"`
	LastActivationError     string   `json:"last_activation_error,omitempty"`
}

type HealthStatus struct {
	Policy   HealthPolicy `json:"policy"`
	State    HealthState  `json:"state"`
	Eligible bool         `json:"eligible"`
	Reason   string       `json:"reason"`
}

type HealthEvidence struct {
	ServiceID      string
	Status         string
	RouteConfirmed bool
}

type HealthDecision struct {
	HealthStatus
	ShouldGenerate bool `json:"should_generate"`
}

type healthDocument struct {
	Schema int          `json:"schema"`
	Policy HealthPolicy `json:"policy"`
	State  HealthState  `json:"state"`
}

func defaultHealthPolicy() HealthPolicy {
	return HealthPolicy{FailureThreshold: 3, MinFailedServices: 2, CooldownHours: 24, MaxRotationsPerDay: 1}
}

func (m *Manager) Health() HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, _ := m.loadHealthLocked()
	return m.healthStatusLocked(doc)
}

func (m *Manager) UpdateHealthPolicy(policy HealthPolicy) (HealthStatus, error) {
	if err := validateHealthPolicy(policy); err != nil {
		return HealthStatus{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, err := m.loadHealthLocked()
	if err != nil {
		return HealthStatus{}, err
	}
	doc.Policy = policy
	if !policy.Enabled {
		doc.State.ConsecutiveFailedRounds = 0
		doc.State.LastDecision = "policy-disabled"
	}
	if err := m.saveHealthLocked(doc); err != nil {
		return HealthStatus{}, err
	}
	return m.healthStatusLocked(doc), nil
}

func (m *Manager) ObserveHealth(evidence []HealthEvidence) (HealthDecision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, err := m.loadHealthLocked()
	if err != nil {
		return HealthDecision{}, err
	}
	doc.State.LastChecked = time.Now().UTC().Format(time.RFC3339)
	failures, successes := []string{}, []string{}
	for _, item := range evidence {
		if !item.RouteConfirmed || strings.TrimSpace(item.ServiceID) == "" {
			continue
		}
		switch item.Status {
		case "pass", "partial":
			successes = append(successes, item.ServiceID)
		case "fail":
			failures = append(failures, item.ServiceID)
		}
	}
	sort.Strings(failures)
	sort.Strings(successes)
	doc.State.LastFailedServices = unique(failures)
	doc.State.LastSuccessfulServices = unique(successes)
	doc.State.RouteEvidenceConfirmed = len(failures)+len(successes) > 0

	if !doc.Policy.Enabled {
		doc.State.LastDecision = "policy-disabled"
		doc.State.ConsecutiveFailedRounds = 0
	} else if !doc.State.RouteEvidenceConfirmed {
		doc.State.LastDecision = "waiting-for-confirmed-warp-route-evidence"
	} else if len(doc.State.LastFailedServices) >= doc.Policy.MinFailedServices {
		doc.State.ConsecutiveFailedRounds++
		doc.State.LastDecision = fmt.Sprintf("failed-round-%d-of-%d", doc.State.ConsecutiveFailedRounds, doc.Policy.FailureThreshold)
	} else {
		doc.State.ConsecutiveFailedRounds = 0
		doc.State.LastDecision = "healthy-or-insufficient-failures"
	}

	status := m.healthStatusLocked(doc)
	decision := HealthDecision{HealthStatus: status, ShouldGenerate: status.Eligible && doc.Policy.AutoGenerateCandidate}
	if decision.ShouldGenerate {
		doc.State.LastDecision = "fresh-candidate-requested"
		decision.State.LastDecision = doc.State.LastDecision
	}
	if err := m.saveHealthLocked(doc); err != nil {
		return HealthDecision{}, err
	}
	return decision, nil
}

func (m *Manager) RecordRotation() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recordRotationLocked()
}

// RecordActivation stores the outcome of the transactional candidate Apply.
// It never changes a profile; activation and rollback belong to dataplane.
func (m *Manager) RecordActivation(ok bool, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, err := m.loadHealthLocked()
	if err != nil {
		return err
	}
	doc.State.LastActivation = time.Now().UTC().Format(time.RFC3339)
	doc.State.LastActivationError = strings.TrimSpace(detail)
	if ok {
		doc.State.ConsecutiveFailedRounds = 0
		doc.State.LastDecision = "fresh-profile-activated"
		doc.State.LastActivationError = ""
	} else {
		doc.State.LastDecision = "fresh-profile-activation-failed"
	}
	return m.saveHealthLocked(doc)
}

func (m *Manager) recordRotationLocked() error {
	doc, err := m.loadHealthLocked()
	if err != nil {
		return err
	}
	doc.State.Rotations = append(pruneRotations(doc.State.Rotations, time.Now().UTC().Add(-24*time.Hour)), time.Now().UTC().Format(time.RFC3339))
	doc.State.ConsecutiveFailedRounds = 0
	doc.State.LastDecision = "candidate-staged-awaiting-isolated-validation"
	return m.saveHealthLocked(doc)
}

func (m *Manager) healthStatusLocked(doc healthDocument) HealthStatus {
	status := HealthStatus{Policy: doc.Policy, State: doc.State, Reason: doc.State.LastDecision}
	if !doc.Policy.Enabled {
		status.Reason = "policy-disabled"
		return status
	}
	if !doc.Policy.AcceptTOS {
		status.Reason = "terms-not-accepted"
		return status
	}
	if !doc.State.RouteEvidenceConfirmed {
		status.Reason = "waiting-for-confirmed-warp-route-evidence"
		return status
	}
	if doc.State.ConsecutiveFailedRounds < doc.Policy.FailureThreshold {
		status.Reason = fmt.Sprintf("failure-threshold-not-reached-%d-of-%d", doc.State.ConsecutiveFailedRounds, doc.Policy.FailureThreshold)
		return status
	}
	if m.hasStagedCandidateLocked() {
		status.Reason = "candidate-already-staged"
		return status
	}
	now := time.Now().UTC()
	rotations := pruneRotations(doc.State.Rotations, now.Add(-24*time.Hour))
	if len(rotations) >= doc.Policy.MaxRotationsPerDay {
		status.Reason = "daily-rotation-limit-reached"
		return status
	}
	if len(rotations) > 0 {
		last, _ := time.Parse(time.RFC3339, rotations[len(rotations)-1])
		if now.Sub(last) < time.Duration(doc.Policy.CooldownHours)*time.Hour {
			status.Reason = "rotation-cooldown-active"
			return status
		}
	}
	status.Eligible = true
	status.Reason = "eligible-to-stage-fresh-candidate"
	return status
}

func (m *Manager) hasStagedCandidateLocked() bool {
	if m.EngineConfigs == nil {
		return false
	}
	for _, engine := range m.EngineConfigs.List() {
		if engine.ID != "warp-wg" {
			continue
		}
		for _, file := range engine.Files {
			if file.ID == "main" && file.Staged {
				return true
			}
		}
	}
	return false
}

func (m *Manager) loadHealthLocked() (healthDocument, error) {
	doc := healthDocument{Schema: 1, Policy: defaultHealthPolicy()}
	b, err := os.ReadFile(filepath.Join(m.Root, "health-policy.json"))
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return healthDocument{}, err
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return healthDocument{}, fmt.Errorf("decode WARP health policy: %w", err)
	}
	if doc.Schema != 1 {
		return healthDocument{}, fmt.Errorf("unsupported WARP health schema %d", doc.Schema)
	}
	if err := validateHealthPolicy(doc.Policy); err != nil {
		return healthDocument{}, err
	}
	return doc, nil
}

func (m *Manager) saveHealthLocked(doc healthDocument) error {
	doc.Schema = 1
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeSecret(filepath.Join(m.Root, "health-policy.json"), b)
}

func validateHealthPolicy(policy HealthPolicy) error {
	if policy.FailureThreshold < 2 || policy.FailureThreshold > 20 {
		return errors.New("failure_threshold must be 2..20")
	}
	if policy.MinFailedServices < 1 || policy.MinFailedServices > 20 {
		return errors.New("min_failed_services must be 1..20")
	}
	if policy.CooldownHours < 1 || policy.CooldownHours > 168 {
		return errors.New("cooldown_hours must be 1..168")
	}
	if policy.MaxRotationsPerDay < 1 || policy.MaxRotationsPerDay > 4 {
		return errors.New("max_rotations_per_day must be 1..4")
	}
	if policy.AutoGenerateCandidate && (!policy.Enabled || !policy.AcceptTOS) {
		return errors.New("automatic candidate generation requires enabled policy and accepted terms")
	}
	if policy.AutoApplyCandidate && !policy.AutoGenerateCandidate {
		return errors.New("automatic candidate apply requires automatic candidate generation")
	}
	return nil
}

func pruneRotations(values []string, after time.Time) []string {
	out := []string{}
	for _, value := range values {
		parsed, err := time.Parse(time.RFC3339, value)
		if err == nil && parsed.After(after) {
			out = append(out, parsed.UTC().Format(time.RFC3339))
		}
	}
	sort.Strings(out)
	return out
}

func unique(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
