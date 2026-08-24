package strategylab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SchemaVersion      = 1
	MaxEvidence        = 2000
	RequiredPasses     = 3
	RollbackFailures   = 3
	EvidenceFreshness  = 24 * time.Hour
	ConfidenceHalfLife = 12 * time.Hour
)

type Pool struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
}

var Pools = []Pool{
	{ID: "tcp-tls", Name: "Общий TLS", Protocol: "tcp", Description: "HTTPS и TLS ClientHello"},
	{ID: "http", Name: "HTTP", Protocol: "tcp", Description: "Открытый HTTP и редиректы"},
	{ID: "youtube-tcp", Name: "YouTube TCP", Protocol: "tcp", Description: "YouTube без googlevideo"},
	{ID: "googlevideo", Name: "Googlevideo", Protocol: "tcp", Description: "Видео CDN отдельным пулом"},
	{ID: "quic-udp", Name: "QUIC / HTTP3", Protocol: "quic", Description: "Настоящий QUIC handshake и HTTP/3 через UDP/443"},
	{ID: "discord-voice", Name: "Discord Voice", Protocol: "udp", Description: "Медиа и голосовой UDP"},
}

type Validation struct {
	OK        bool     `json:"ok"`
	Native    bool     `json:"native"`
	Code      string   `json:"code"`
	Output    string   `json:"output"`
	Arguments []string `json:"arguments,omitempty"`
	CheckedAt string   `json:"checked_at,omitempty"`
}

type Candidate struct {
	ID         string     `json:"id"`
	PoolID     string     `json:"pool_id"`
	Name       string     `json:"name"`
	Arguments  string     `json:"arguments"`
	Origin     string     `json:"origin"`
	Validation Validation `json:"validation"`
	CreatedAt  string     `json:"created_at"`
}

type CandidateInput struct {
	PoolID    string `json:"pool_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
	Origin    string `json:"origin,omitempty"`
}

type StageEvidence struct {
	Stage   string `json:"stage"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Elapsed int64  `json:"elapsed_ms,omitempty"`
}

type Evidence struct {
	CandidateID    string          `json:"candidate_id"`
	ServiceID      string          `json:"service_id"`
	Protocol       string          `json:"protocol"`
	IPFamily       string          `json:"ip_family"`
	Success        bool            `json:"success"`
	RouteConfirmed bool            `json:"route_confirmed"`
	LatencyMS      int64           `json:"latency_ms"`
	TTFBMS         int64           `json:"ttfb_ms,omitempty"`
	ReadMS         int64           `json:"read_ms,omitempty"`
	BytesRead      int64           `json:"bytes_read,omitempty"`
	StreamStatus   string          `json:"stream_status,omitempty"`
	HTTPStatus     int             `json:"http_status,omitempty"`
	Stages         []StageEvidence `json:"stages"`
	CheckedAt      string          `json:"checked_at"`
}

type Summary struct {
	CandidateID    string  `json:"candidate_id"`
	ServiceID      string  `json:"service_id"`
	Protocol       string  `json:"protocol"`
	IPFamily       string  `json:"ip_family"`
	Passes         int     `json:"passes"`
	Failures       int     `json:"failures"`
	Confirmed      int     `json:"confirmed"`
	FreshPasses    int     `json:"fresh_passes"`
	FreshFailures  int     `json:"fresh_failures"`
	SuccessRate    float64 `json:"success_rate"`
	Confidence     float64 `json:"confidence"`
	AverageLatency float64 `json:"average_latency_ms"`
	AverageTTFB    float64 `json:"average_ttfb_ms"`
	LastCheckedAt  string  `json:"last_checked_at,omitempty"`
	Eligible       bool    `json:"eligible"`
	Reason         string  `json:"reason"`
}

type Selection struct {
	ServiceID           string  `json:"service_id"`
	Protocol            string  `json:"protocol"`
	IPFamily            string  `json:"ip_family"`
	CandidateID         string  `json:"candidate_id"`
	PreviousCandidateID string  `json:"previous_candidate_id,omitempty"`
	Frozen              bool    `json:"frozen"`
	SelectedAt          string  `json:"selected_at"`
	LastHealthyAt       string  `json:"last_healthy_at,omitempty"`
	RolledBackAt        string  `json:"rolled_back_at,omitempty"`
	RollbackReason      string  `json:"rollback_reason,omitempty"`
	Healthy             bool    `json:"healthy"`
	Confidence          float64 `json:"confidence"`
	ConsecutiveFailures int     `json:"consecutive_failures"`
	Status              string  `json:"status"`
	Reason              string  `json:"reason"`
}

type State struct {
	SchemaVersion int                  `json:"schema_version"`
	Candidates    map[string]Candidate `json:"candidates"`
	Evidence      []Evidence           `json:"evidence"`
	Selections    map[string]Selection `json:"selections"`
}

type Snapshot struct {
	SchemaVersion int            `json:"schema_version"`
	Mode          string         `json:"mode"`
	Pools         []Pool         `json:"pools"`
	Candidates    []Candidate    `json:"candidates"`
	Evidence      []Evidence     `json:"evidence"`
	Summaries     []Summary      `json:"summaries"`
	Selections    []Selection    `json:"selections"`
	Safety        map[string]any `json:"safety"`
}

type Validator interface {
	Validate(context.Context, []string) Validation
}

type ExecValidator struct {
	Binary  string
	Timeout time.Duration
}

func (v ExecValidator) Validate(parent context.Context, arguments []string) Validation {
	binary := strings.TrimSpace(v.Binary)
	if binary == "" {
		binary = findNFQWS2()
	}
	if binary == "" {
		return Validation{Code: "NFQWS2_NOT_INSTALLED", Output: "NFQWS2 не установлен; нативная проверка недоступна"}
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	args := []string{"--dry-run", "--qnum=64600"}
	args = append(args, installedBaseArguments()...)
	args = append(args, arguments...)
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	text := strings.TrimSpace(string(output))
	if len(text) > 4096 {
		text = text[len(text)-4096:]
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Validation{Native: true, Code: "VALIDATION_TIMEOUT", Output: "Нативная проверка NFQWS2 превысила лимит времени", Arguments: arguments, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return Validation{Native: true, Code: "NATIVE_REJECTED", Output: text, Arguments: arguments, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	if text == "" {
		text = "NFQWS2 --dry-run: PASS"
	}
	return Validation{OK: true, Native: true, Code: "PASS", Output: text, Arguments: arguments, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
}

type Manager struct {
	Path      string
	Validator Validator
	Executor  ProbeExecutor
	Now       func() time.Time

	mu    sync.RWMutex
	state State
}

func New(path string) (*Manager, error) {
	m := &Manager{Path: path, Validator: ExecValidator{}, Executor: &SystemProbeExecutor{}, Now: time.Now, state: emptyState()}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return m, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &m.state); err != nil {
		return nil, fmt.Errorf("decode Strategy Lab state: %w", err)
	}
	if m.state.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported Strategy Lab schema %d", m.state.SchemaVersion)
	}
	if m.state.Candidates == nil {
		m.state.Candidates = map[string]Candidate{}
	}
	if m.state.Selections == nil {
		m.state.Selections = map[string]Selection{}
	}
	return m, nil
}

func (m *Manager) Probe(ctx context.Context, id string, target ProbeTarget) (Evidence, error) {
	m.mu.RLock()
	candidate, ok := m.state.Candidates[id]
	m.mu.RUnlock()
	if !ok {
		return Evidence{}, fmt.Errorf("unknown candidate %q", id)
	}
	if !candidate.Validation.OK || !candidate.Validation.Native {
		return Evidence{}, errors.New("candidate must pass native NFQWS2 validation first")
	}
	protocol := ""
	for _, pool := range Pools {
		if pool.ID == candidate.PoolID {
			protocol = pool.Protocol
			break
		}
	}
	target.Protocol = protocol
	if target.IPFamily == "" {
		target.IPFamily = "ipv4"
	}
	executor := m.Executor
	if executor == nil {
		return Evidence{}, errors.New("isolated Strategy Lab executor is disabled")
	}
	evidence, err := executor.Execute(ctx, candidate, target)
	if err != nil {
		return evidence, err
	}
	if len(evidence.Stages) == 0 {
		return Evidence{}, errors.New("executor returned no typed evidence")
	}
	if err := m.Record(evidence); err != nil {
		return evidence, err
	}
	return evidence, nil
}

func emptyState() State {
	return State{SchemaVersion: SchemaVersion, Candidates: map[string]Candidate{}, Evidence: []Evidence{}, Selections: map[string]Selection{}}
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	candidates := make([]Candidate, 0, len(m.state.Candidates))
	for _, candidate := range m.state.Candidates {
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].PoolID+candidates[i].Name < candidates[j].PoolID+candidates[j].Name
	})
	now := m.now()
	summaries := summarize(m.state, now)
	selections := selectionsWithHealth(m.state, summaries)
	sort.Slice(selections, func(i, j int) bool {
		return selectionKey(selections[i].ServiceID, selections[i].Protocol, selections[i].IPFamily) < selectionKey(selections[j].ServiceID, selections[j].Protocol, selections[j].IPFamily)
	})
	evidence := append(make([]Evidence, 0, len(m.state.Evidence)), m.state.Evidence...)
	return Snapshot{
		SchemaVersion: SchemaVersion, Mode: "expert-read-only-until-apply", Pools: append([]Pool(nil), Pools...),
		Candidates: candidates, Evidence: evidence, Summaries: summaries, Selections: selections,
		Safety: map[string]any{"live_config_changed": false, "default_route_changed": false, "temporary_scoped_firewall_probe": true, "native_validation_required": true, "required_confirmed_passes": RequiredPasses, "automatic_rollback_failures": RollbackFailures, "confidence_half_life_hours": int(ConfidenceHalfLife / time.Hour)},
	}
}

func (m *Manager) AddCandidate(poolID, name, arguments, origin string) (Candidate, error) {
	candidates, err := m.AddCandidates([]CandidateInput{{PoolID: poolID, Name: name, Arguments: arguments, Origin: origin}})
	if err != nil {
		return Candidate{}, err
	}
	return candidates[0], nil
}

// AddCandidates validates a migration batch completely before one atomic
// state write. A malformed candidate cannot leave a partial z2k/profile import.
func (m *Manager) AddCandidates(inputs []CandidateInput) ([]Candidate, error) {
	if len(inputs) == 0 || len(inputs) > 128 {
		return nil, errors.New("candidate batch must contain between 1 and 128 entries")
	}
	now := m.now().UTC()
	candidates := make([]Candidate, 0, len(inputs))
	for _, input := range inputs {
		candidate, err := buildCandidate(input, now)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	m.mu.Lock()
	previous := m.state.Candidates
	next := make(map[string]Candidate, len(previous)+len(candidates))
	for id, candidate := range previous {
		next[id] = candidate
	}
	for _, candidate := range candidates {
		next[candidate.ID] = candidate
	}
	m.state.Candidates = next
	if err := m.saveLocked(); err != nil {
		m.state.Candidates = previous
		m.mu.Unlock()
		return nil, err
	}
	m.mu.Unlock()
	return candidates, nil
}

func buildCandidate(input CandidateInput, now time.Time) (Candidate, error) {
	poolID, name, arguments, origin := input.PoolID, input.Name, input.Arguments, input.Origin
	if !validPool(poolID) {
		return Candidate{}, fmt.Errorf("unknown strategy pool %q", poolID)
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return Candidate{}, errors.New("название кандидата должно содержать от 1 до 100 символов")
	}
	parsed, err := parseArguments(arguments)
	if err != nil {
		return Candidate{}, err
	}
	if origin == "" {
		origin = "expert"
	}
	digest := sha256.Sum256([]byte(poolID + "\x00" + name + "\x00" + strings.Join(parsed, "\x00")))
	id := "st-" + hex.EncodeToString(digest[:8])
	candidate := Candidate{ID: id, PoolID: poolID, Name: name, Arguments: strings.TrimSpace(arguments), Origin: origin, CreatedAt: now.Format(time.RFC3339), Validation: Validation{Code: "NATIVE_REQUIRED", Output: "Синтаксис разобран; требуется NFQWS2 --dry-run", Arguments: parsed}}
	return candidate, nil
}

func (m *Manager) Validate(ctx context.Context, id string) (Candidate, error) {
	m.mu.RLock()
	candidate, ok := m.state.Candidates[id]
	m.mu.RUnlock()
	if !ok {
		return Candidate{}, fmt.Errorf("unknown candidate %q", id)
	}
	arguments, err := parseArguments(candidate.Arguments)
	if err != nil {
		return Candidate{}, err
	}
	validator := m.Validator
	if validator == nil {
		validator = ExecValidator{}
	}
	validation := validator.Validate(ctx, arguments)
	validation.Arguments = arguments
	if validation.CheckedAt == "" {
		validation.CheckedAt = m.now().UTC().Format(time.RFC3339)
	}
	candidate.Validation = validation
	m.mu.Lock()
	m.state.Candidates[id] = candidate
	err = m.saveLocked()
	m.mu.Unlock()
	return candidate, err
}

// DeleteCandidate removes a draft experiment together with only its own
// evidence and selections. It never edits the active NFQWS2 configuration.
func (m *Manager) DeleteCandidate(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.state.Candidates[id]; !ok {
		return fmt.Errorf("unknown candidate %q", id)
	}
	delete(m.state.Candidates, id)
	evidence := m.state.Evidence[:0]
	for _, item := range m.state.Evidence {
		if item.CandidateID != id {
			evidence = append(evidence, item)
		}
	}
	m.state.Evidence = evidence
	for key, selection := range m.state.Selections {
		if selection.CandidateID == id {
			delete(m.state.Selections, key)
		} else if selection.PreviousCandidateID == id {
			selection.PreviousCandidateID = ""
			m.state.Selections[key] = selection
		}
	}
	return m.saveLocked()
}

func (m *Manager) Record(evidence Evidence) error {
	if evidence.CandidateID == "" || evidence.ServiceID == "" || !validProtocol(evidence.Protocol) || !validFamily(evidence.IPFamily) {
		return errors.New("candidate, service, protocol and IP family are required")
	}
	if len(evidence.Stages) == 0 {
		return errors.New("typed stage evidence is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	candidate, ok := m.state.Candidates[evidence.CandidateID]
	if !ok {
		return errors.New("candidate is unknown")
	}
	if !candidate.Validation.OK || !candidate.Validation.Native {
		return errors.New("candidate has not passed native NFQWS2 validation")
	}
	if evidence.CheckedAt == "" {
		evidence.CheckedAt = m.now().UTC().Format(time.RFC3339)
	}
	if evidence.Success && !evidence.RouteConfirmed {
		return errors.New("successful evidence must confirm the tested route")
	}
	m.state.Evidence = append(m.state.Evidence, evidence)
	if len(m.state.Evidence) > MaxEvidence {
		m.state.Evidence = append([]Evidence(nil), m.state.Evidence[len(m.state.Evidence)-MaxEvidence:]...)
	}
	m.reconcileSelectionLocked(evidence)
	return m.saveLocked()
}

func (m *Manager) Select(serviceID, protocol, family, candidateID string, frozen bool) (Selection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.state.Candidates[candidateID]; !ok {
		return Selection{}, errors.New("candidate is unknown")
	}
	key := selectionKey(serviceID, protocol, family)
	for _, summary := range summarize(m.state, m.now()) {
		if selectionKey(summary.ServiceID, summary.Protocol, summary.IPFamily) == key && summary.CandidateID == candidateID {
			if !summary.Eligible {
				return Selection{}, errors.New(summary.Reason)
			}
			now := m.now().UTC().Format(time.RFC3339)
			selection := Selection{ServiceID: serviceID, Protocol: protocol, IPFamily: family, CandidateID: candidateID, Frozen: frozen, SelectedAt: now, LastHealthyAt: summary.LastCheckedAt, Healthy: true, Confidence: summary.Confidence, Status: "healthy", Reason: summary.Reason}
			if previous, ok := m.state.Selections[key]; ok && previous.CandidateID != candidateID {
				selection.PreviousCandidateID = previous.CandidateID
			}
			m.state.Selections[key] = selection
			return selection, m.saveLocked()
		}
	}
	return Selection{}, errors.New("candidate has no evidence for the requested service/protocol/family")
}

func (m *Manager) ResetSelection(serviceID, protocol, family string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.state.Selections, selectionKey(serviceID, protocol, family))
	return m.saveLocked()
}

func summarize(state State, now time.Time) []Summary {
	type aggregate struct {
		s               Summary
		latency         int64
		ttfb            int64
		latest          time.Time
		weightedSuccess float64
		weightedTotal   float64
		freshConfirmed  int
	}
	groups := map[string]*aggregate{}
	for _, evidence := range state.Evidence {
		key := evidence.CandidateID + "|" + selectionKey(evidence.ServiceID, evidence.Protocol, evidence.IPFamily)
		group := groups[key]
		if group == nil {
			group = &aggregate{s: Summary{CandidateID: evidence.CandidateID, ServiceID: evidence.ServiceID, Protocol: evidence.Protocol, IPFamily: evidence.IPFamily}}
			groups[key] = group
		}
		if evidence.Success {
			group.s.Passes++
			group.latency += evidence.LatencyMS
			group.ttfb += evidence.TTFBMS
		} else {
			group.s.Failures++
		}
		if evidence.RouteConfirmed {
			group.s.Confirmed++
		}
		checked, err := time.Parse(time.RFC3339, evidence.CheckedAt)
		if err != nil {
			continue
		}
		age := now.Sub(checked)
		if age < 0 {
			age = 0
		}
		weight := math.Exp2(-float64(age) / float64(ConfidenceHalfLife))
		group.weightedTotal += weight
		if evidence.Success {
			group.weightedSuccess += weight
		}
		if age <= EvidenceFreshness {
			if evidence.Success {
				group.s.FreshPasses++
				if evidence.RouteConfirmed {
					group.freshConfirmed++
				}
			} else {
				group.s.FreshFailures++
			}
		}
		if checked.After(group.latest) {
			group.latest = checked
		}
	}
	out := make([]Summary, 0, len(groups))
	for _, group := range groups {
		total := group.s.Passes + group.s.Failures
		if total > 0 {
			group.s.SuccessRate = float64(group.s.Passes) / float64(total)
		}
		if group.weightedTotal > 0 {
			group.s.Confidence = group.weightedSuccess / group.weightedTotal
		}
		if group.s.Passes > 0 {
			group.s.AverageLatency = float64(group.latency) / float64(group.s.Passes)
			group.s.AverageTTFB = float64(group.ttfb) / float64(group.s.Passes)
		}
		group.s.LastCheckedAt = group.latest.UTC().Format(time.RFC3339)
		switch {
		case group.latest.IsZero() || now.Sub(group.latest) > EvidenceFreshness:
			group.s.Reason = "результат устарел; выполните новый изолированный тест"
		case group.s.FreshPasses < RequiredPasses:
			group.s.Reason = fmt.Sprintf("нужно минимум %d свежих подтверждённых прохода", RequiredPasses)
		case group.freshConfirmed < group.s.FreshPasses:
			group.s.Reason = "не каждый успешный проход подтвердил изолированный маршрут"
		case group.s.Confidence < 0.75:
			group.s.Reason = "доверие с учётом давности ниже 75%"
		default:
			group.s.Eligible = true
			group.s.Reason = "кандидат воспроизводим и готов только к переносу в draft"
		}
		out = append(out, group.s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ServiceID+out[i].Protocol+out[i].IPFamily+out[i].CandidateID < out[j].ServiceID+out[j].Protocol+out[j].IPFamily+out[j].CandidateID
	})
	return out
}

func selectionsWithHealth(state State, summaries []Summary) []Selection {
	byCandidate := make(map[string]Summary, len(summaries))
	for _, summary := range summaries {
		byCandidate[summary.CandidateID+"|"+selectionKey(summary.ServiceID, summary.Protocol, summary.IPFamily)] = summary
	}
	selections := make([]Selection, 0, len(state.Selections))
	for key, selection := range state.Selections {
		summary, ok := byCandidate[selection.CandidateID+"|"+key]
		selection.Healthy = ok && summary.Eligible
		selection.Confidence = summary.Confidence
		selection.ConsecutiveFailures = consecutiveFailures(state.Evidence, selection)
		if ok {
			selection.Reason = summary.Reason
		} else {
			selection.Reason = "для выбранного кандидата нет результатов"
		}
		switch {
		case selection.Frozen && selection.Healthy:
			selection.Status = "frozen-healthy"
		case selection.Frozen:
			selection.Status = "frozen-degraded"
		case selection.Healthy:
			selection.Status = "healthy"
		default:
			selection.Status = "degraded"
		}
		selections = append(selections, selection)
	}
	return selections
}

func consecutiveFailures(evidence []Evidence, selection Selection) int {
	selectedAt, _ := time.Parse(time.RFC3339, selection.SelectedAt)
	count := 0
	for index := len(evidence) - 1; index >= 0; index-- {
		item := evidence[index]
		if item.CandidateID != selection.CandidateID || selectionKey(item.ServiceID, item.Protocol, item.IPFamily) != selectionKey(selection.ServiceID, selection.Protocol, selection.IPFamily) {
			continue
		}
		checked, _ := time.Parse(time.RFC3339, item.CheckedAt)
		if !selectedAt.IsZero() && !checked.IsZero() && checked.Before(selectedAt) {
			break
		}
		if item.Success {
			break
		}
		count++
	}
	return count
}

func (m *Manager) reconcileSelectionLocked(evidence Evidence) {
	key := selectionKey(evidence.ServiceID, evidence.Protocol, evidence.IPFamily)
	selection, ok := m.state.Selections[key]
	if !ok || selection.CandidateID != evidence.CandidateID {
		return
	}
	if evidence.Success && evidence.RouteConfirmed {
		selection.LastHealthyAt = evidence.CheckedAt
		m.state.Selections[key] = selection
		return
	}
	if selection.Frozen || consecutiveFailures(m.state.Evidence, selection) < RollbackFailures {
		return
	}
	summaries := summarize(m.state, m.now())
	var alternatives []Summary
	for _, summary := range summaries {
		if summary.CandidateID != selection.CandidateID && summary.Eligible && selectionKey(summary.ServiceID, summary.Protocol, summary.IPFamily) == key {
			alternatives = append(alternatives, summary)
		}
	}
	if len(alternatives) == 0 {
		return
	}
	sort.SliceStable(alternatives, func(i, j int) bool {
		if alternatives[i].CandidateID == selection.PreviousCandidateID {
			return true
		}
		if alternatives[j].CandidateID == selection.PreviousCandidateID {
			return false
		}
		if alternatives[i].Confidence != alternatives[j].Confidence {
			return alternatives[i].Confidence > alternatives[j].Confidence
		}
		return alternatives[i].AverageLatency < alternatives[j].AverageLatency
	})
	fallback := alternatives[0]
	now := m.now().UTC().Format(time.RFC3339)
	selection.PreviousCandidateID = selection.CandidateID
	selection.CandidateID = fallback.CandidateID
	selection.SelectedAt = now
	selection.LastHealthyAt = fallback.LastCheckedAt
	selection.RolledBackAt = now
	selection.RollbackReason = fmt.Sprintf("%d последовательных изолированных отказа; выбран свежий подтверждённый кандидат", RollbackFailures)
	m.state.Selections[key] = selection
}

func parseArguments(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, "\x00`;&|<>") || strings.Contains(raw, "$(") || strings.Contains(raw, "${") {
		return nil, errors.New("пустая стратегия, shell-оператор или командная подстановка запрещены")
	}
	arguments, err := splitWords(raw)
	if err != nil {
		return nil, err
	}
	for _, argument := range arguments {
		if !strings.HasPrefix(argument, "--") {
			return nil, fmt.Errorf("аргумент %q должен начинаться с --", argument)
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
		switch name {
		case "qnum", "daemon", "pidfile", "user", "uid", "gid", "debug-log", "wf-tcp", "wf-udp":
			return nil, fmt.Errorf("runtime-параметр --%s управляется RAZVILKA и запрещён в стратегии", name)
		}
	}
	return arguments, nil
}

// ParseArguments validates and tokenizes a candidate without invoking NFQWS2.
// It is exported for read-only migration previews; native --dry-run remains
// mandatory before the candidate can receive evidence or become selectable.
func ParseArguments(raw string) ([]string, error) {
	return parseArguments(raw)
}

func splitWords(raw string) ([]string, error) {
	words := []string{}
	var current strings.Builder
	quote := rune(0)
	escaped := false
	inComment := false
	flush := func() {
		if current.Len() > 0 {
			words = append(words, current.String())
			current.Reset()
		}
	}
	for _, r := range raw {
		if inComment {
			if r == '\n' {
				inComment = false
				flush()
			}
			continue
		}
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' && current.Len() == 0 {
			inComment = true
			continue
		}
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			flush()
			continue
		}
		current.WriteRune(r)
	}
	if escaped || quote != 0 {
		return nil, errors.New("незавершённая кавычка или escape в стратегии")
	}
	flush()
	if len(words) == 0 {
		return nil, errors.New("стратегия не содержит аргументов")
	}
	return words, nil
}

func validPool(id string) bool {
	for _, pool := range Pools {
		if pool.ID == id {
			return true
		}
	}
	return false
}

func validProtocol(value string) bool { return value == "tcp" || value == "udp" || value == "quic" }
func validFamily(value string) bool   { return value == "ipv4" || value == "ipv6" }

func selectionKey(serviceID, protocol, family string) string {
	return strings.TrimSpace(serviceID) + "|" + strings.ToLower(strings.TrimSpace(protocol)) + "|" + strings.ToLower(strings.TrimSpace(family))
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) saveLocked() error {
	if strings.TrimSpace(m.Path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	temporary := m.Path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, m.Path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func findNFQWS2() string {
	for _, candidate := range []string{"/opt/usr/bin/nfqws2", "/opt/bin/nfqws2", "/usr/bin/nfqws2", "nfqws2"} {
		if strings.Contains(candidate, "/") {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return candidate
			}
			continue
		}
		if found, err := exec.LookPath(candidate); err == nil {
			return found
		}
	}
	return ""
}
