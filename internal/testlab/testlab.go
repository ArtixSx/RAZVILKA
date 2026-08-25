package testlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/evidence"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type Result struct {
	ServiceID      string         `json:"service_id"`
	ServiceName    string         `json:"service_name"`
	ProbeURL       string         `json:"probe_url"`
	ScenarioID     string         `json:"scenario_id,omitempty"`
	ScenarioLabel  string         `json:"scenario_label,omitempty"`
	ScenarioNeeded bool           `json:"scenario_required,omitempty"`
	Route          string         `json:"route"`
	Status         string         `json:"status"` // pass, partial, fail, not-ready, pending
	HTTPStatus     int            `json:"http_status,omitempty"`
	LatencyMS      int64          `json:"latency_ms,omitempty"`
	TTFBMS         int64          `json:"ttfb_ms,omitempty"`
	ReadMS         int64          `json:"read_ms,omitempty"`
	BytesRead      int64          `json:"bytes_read,omitempty"`
	StreamStatus   string         `json:"stream_status,omitempty"`
	CheckedAt      string         `json:"checked_at"`
	Detail         string         `json:"detail,omitempty"`
	RouteConfirmed bool           `json:"route_confirmed"`
	EvidenceSource string         `json:"evidence_source,omitempty"`
	EvidenceLevel  evidence.Level `json:"evidence_level"`
	EgressIP       string         `json:"egress_ip,omitempty"`
}

// NormalizeEvidence derives the public assurance level from observed facts.
// It is safe to call for old adapters that only populate RouteConfirmed.
func (result *Result) NormalizeEvidence() {
	if result == nil || !result.EvidenceLevel.Valid() || result.EvidenceLevel == evidence.None {
		result.EvidenceLevel = evidence.FromProbe(result.Status, result.RouteConfirmed)
	}
}

// AssuranceLevel returns a normalized value without mutating the result.
func (result Result) AssuranceLevel() evidence.Level {
	if result.EvidenceLevel.Valid() && result.EvidenceLevel != evidence.None {
		return result.EvidenceLevel
	}
	return evidence.FromProbe(result.Status, result.RouteConfirmed)
}

type MatrixCell struct {
	ServiceID string  `json:"service_id"`
	Route     string  `json:"route"`
	Status    string  `json:"status"`
	Reason    string  `json:"reason,omitempty"`
	Last      *Result `json:"last,omitempty"`
}

type Snapshot struct {
	Current []Result     `json:"current"`
	Matrix  []MatrixCell `json:"matrix"`
}

// ComparisonAssessment explains what an isolated route comparison proved.
// A working bypass alone proves that route works, but only a failed, isolated
// DIRECT control proves that the bypass is actually required on this network.
type ComparisonAssessment struct {
	ServiceID        string `json:"service_id"`
	ServiceName      string `json:"service_name"`
	ControlStatus    string `json:"control_status"`
	Conclusion       string `json:"conclusion"`
	RecommendedRoute string `json:"recommended_route,omitempty"`
	BypassRequired   *bool  `json:"bypass_required,omitempty"`
	Message          string `json:"message"`
}

type Runner struct {
	Client *http.Client
	mu     sync.RWMutex
	latest map[string]Result
}

type RouteProber interface {
	Probe(context.Context, catalog.Service, string) Result
}

func NewRunner() *Runner {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true
	return &Runner{
		Client: &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 4 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		latest: map[string]Result{},
	}
}

func (r *Runner) ProbeCurrent(ctx context.Context, cat catalog.Catalog, ids []string) []Result {
	selected := selectServices(cat, ids)
	if len(selected) == 0 {
		return []Result{}
	}
	sem := make(chan struct{}, 4)
	type target struct {
		service catalog.Service
		probe   catalog.Probe
	}
	targets := []target{}
	for _, service := range selected {
		for _, probe := range serviceProbes(service) {
			targets = append(targets, target{service: service, probe: probe})
		}
	}
	results := make([]Result, len(targets))
	var wg sync.WaitGroup
	for i, item := range targets {
		i, item := i, item
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = r.probe(ctx, withProbe(item.service, item.probe), item.probe)
			results[i].NormalizeEvidence()
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].ServiceName < results[j].ServiceName })
	r.mu.Lock()
	for _, v := range results {
		r.latest[resultKey(v)] = v
	}
	r.mu.Unlock()
	return results
}

func (r *Runner) ProbeRoutes(ctx context.Context, cat catalog.Catalog, ids, routes []string, prober RouteProber) []Result {
	selected := selectServices(cat, ids)
	if len(selected) == 0 || len(routes) == 0 || prober == nil {
		return []Result{}
	}
	sem := make(chan struct{}, 3)
	targetCount := 0
	for _, service := range selected {
		targetCount += len(serviceProbes(service)) * len(routes)
	}
	results := make([]Result, targetCount)
	var wg sync.WaitGroup
	index := 0
	for _, service := range selected {
		for _, probe := range serviceProbes(service) {
			for _, route := range routes {
				i, currentService, currentProbe, currentRoute := index, service, probe, route
				index++
				wg.Add(1)
				go func() {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					results[i] = prober.Probe(ctx, withProbe(currentService, currentProbe), currentRoute)
					results[i].ScenarioID = currentProbe.ID
					results[i].ScenarioLabel = currentProbe.Label
					results[i].ScenarioNeeded = currentProbe.Required
					results[i].NormalizeEvidence()
				}()
			}
		}
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		if results[i].ServiceName == results[j].ServiceName {
			if results[i].Route == results[j].Route {
				return results[i].ScenarioID < results[j].ScenarioID
			}
			return results[i].Route < results[j].Route
		}
		return results[i].ServiceName < results[j].ServiceName
	})
	r.mu.Lock()
	for _, result := range results {
		r.latest[resultKey(result)] = result
	}
	r.mu.Unlock()
	return results
}

// AssessComparisons converts raw probe rows into a user-facing control
// conclusion without promoting uncertain results. DIRECT must itself be
// route-confirmed before it can prove that a bypass is or is not necessary.
func AssessComparisons(results []Result) []ComparisonAssessment {
	results = AggregateScenarios(results)
	grouped := map[string][]Result{}
	order := []string{}
	for _, result := range results {
		if _, exists := grouped[result.ServiceID]; !exists {
			order = append(order, result.ServiceID)
		}
		grouped[result.ServiceID] = append(grouped[result.ServiceID], result)
	}
	sort.Strings(order)
	out := make([]ComparisonAssessment, 0, len(order))
	for _, serviceID := range order {
		rows := grouped[serviceID]
		assessment := ComparisonAssessment{ServiceID: serviceID, ServiceName: rows[0].ServiceName, ControlStatus: "not-run", Conclusion: "control-not-run", Message: "Прямой контроль не запускался; необходимость обхода не доказана."}
		var direct *Result
		candidates := make([]Result, 0, len(rows))
		for i := range rows {
			row := rows[i]
			if row.Route == "direct" {
				direct = &row
				continue
			}
			if viableResult(row) {
				candidates = append(candidates, row)
			}
		}
		sort.SliceStable(candidates, func(i, j int) bool { return betterCandidate(candidates[i], candidates[j]) })
		bestRoute := ""
		if len(candidates) > 0 {
			bestRoute = candidates[0].Route
		}
		if direct == nil {
			assessment.RecommendedRoute = bestRoute
			out = append(out, assessment)
			continue
		}
		assessment.ControlStatus = direct.Status
		directConfirmed := direct.AssuranceLevel().AtLeast(evidence.Service)
		directFailedConfirmed := direct.Status == "fail" && direct.AssuranceLevel().AtLeast(evidence.Route)
		switch {
		case directConfirmed && direct.Status == "pass":
			required := false
			assessment.BypassRequired = &required
			assessment.Conclusion = "direct-sufficient"
			assessment.RecommendedRoute = "direct"
			assessment.Message = "Сервис доступен напрямую. Обход для этой сети сейчас не требуется."
		case directConfirmed && direct.Status == "partial" && len(candidates) > 0 && candidates[0].Status == "pass":
			required := false
			assessment.BypassRequired = &required
			assessment.Conclusion = "bypass-improves-access"
			assessment.RecommendedRoute = bestRoute
			assessment.Message = "DIRECT достигает сервиса лишь частично; выбранный обход даёт полноценный ответ."
		case directConfirmed && direct.Status == "partial":
			required := false
			assessment.BypassRequired = &required
			assessment.Conclusion = "direct-partial"
			assessment.RecommendedRoute = "direct"
			assessment.Message = "Прямой путь достигает сервиса, но получил ограниченный ответ; обязательность обхода не подтверждена."
		case directFailedConfirmed && len(candidates) > 0:
			required := true
			assessment.BypassRequired = &required
			assessment.Conclusion = "bypass-required"
			assessment.RecommendedRoute = bestRoute
			assessment.Message = "DIRECT подтверждённо не работает, а обход отвечает: для этой сети обход необходим."
		case directFailedConfirmed:
			required := true
			assessment.BypassRequired = &required
			assessment.Conclusion = "no-working-route"
			assessment.Message = "DIRECT подтверждённо не работает, и среди проверенных обходов рабочего варианта нет."
		default:
			assessment.ControlStatus = "unavailable"
			assessment.Conclusion = "control-unavailable"
			assessment.RecommendedRoute = bestRoute
			assessment.Message = "Работа обхода проверена, но честный DIRECT-контроль недоступен; необходимость обхода не доказана."
		}
		out = append(out, assessment)
	}
	return out
}

func viableResult(result Result) bool {
	return (result.Status == "pass" || result.Status == "partial") && result.AssuranceLevel().AtLeast(evidence.Service)
}

func betterCandidate(left, right Result) bool {
	quality := func(status string) int {
		if status == "pass" {
			return 2
		}
		if status == "partial" {
			return 1
		}
		return 0
	}
	if quality(left.Status) != quality(right.Status) {
		return quality(left.Status) > quality(right.Status)
	}
	if left.LatencyMS != right.LatencyMS {
		if left.LatencyMS == 0 {
			return false
		}
		if right.LatencyMS == 0 {
			return true
		}
		return left.LatencyMS < right.LatencyMS
	}
	return left.Route < right.Route
}

func (r *Runner) Snapshot(cat catalog.Catalog) Snapshot {
	r.mu.RLock()
	current := make([]Result, 0, len(r.latest))
	for _, v := range r.latest {
		v.NormalizeEvidence()
		current = append(current, v)
	}
	r.mu.RUnlock()
	sort.Slice(current, func(i, j int) bool {
		if current[i].ServiceName == current[j].ServiceName {
			if current[i].Route == current[j].Route {
				return current[i].ScenarioID < current[j].ScenarioID
			}
			return current[i].Route < current[j].Route
		}
		return current[i].ServiceName < current[j].ServiceName
	})
	return Snapshot{Current: current, Matrix: r.matrix(cat, current)}
}

func (r *Runner) matrix(cat catalog.Catalog, current []Result) []MatrixCell {
	current = AggregateScenarios(current)
	last := map[string]Result{}
	for _, v := range current {
		last[v.ServiceID+"|"+v.Route] = v
	}
	opts := routecatalog.Options()
	statuses := map[string]engine.Status{}
	for _, e := range (engine.Detector{}).All() {
		statuses[e.ID] = e
	}
	cells := make([]MatrixCell, 0, len(cat.Services)*len(opts))
	for _, s := range cat.Services {
		for _, o := range opts {
			if o.ID == "auto" {
				continue
			}
			cell := MatrixCell{ServiceID: s.ID, Route: o.ID, Status: "pending", Reason: "route-specific isolated probe has not run yet"}
			if o.ID != "direct" {
				st, ok := statuses[o.ID]
				if !ok || !st.Installed {
					cell.Status = "not-ready"
					cell.Reason = "engine is not installed"
				} else if !st.Running {
					cell.Status = "not-ready"
					cell.Reason = "engine is installed but not running"
				} else {
					cell.Status = "adapter-pending"
					cell.Reason = "engine is running; isolated test adapter is not connected yet"
				}
			} else {
				cell.Status = "adapter-pending"
				cell.Reason = "DIRECT needs an isolated bypass-free socket before it can be compared fairly"
			}
			if v, ok := last[s.ID+"|"+o.ID]; ok {
				copy := v
				cell.Last = &copy
				cell.Status = v.Status
				cell.Reason = v.Detail
			} else if v, ok := last[s.ID+"|current"]; ok {
				copy := v
				cell.Last = &copy
			}
			cells = append(cells, cell)
		}
	}
	return cells
}

func (r *Runner) probe(ctx context.Context, s catalog.Service, probe catalog.Probe) Result {
	res := Result{ServiceID: s.ID, ServiceName: s.Name, ProbeURL: s.ProbeURL, ScenarioID: probe.ID, ScenarioLabel: probe.Label, ScenarioNeeded: probe.Required, Route: "current", Status: "fail", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if strings.TrimSpace(s.ProbeURL) == "" {
		res.Status = "not-ready"
		res.Detail = "service has no probe URL"
		return res
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.ProbeURL, nil)
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "RAZVILKA-Probe/0.15.1")
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
	req.Header.Set("Range", "bytes=0-32767")
	start := time.Now()
	resp, err := r.Client.Do(req)
	res.TTFBMS = time.Since(start).Milliseconds()
	if err != nil {
		res.LatencyMS = time.Since(start).Milliseconds()
		res.Detail = short(err.Error())
		return res
	}
	defer resp.Body.Close()
	res.HTTPStatus = resp.StatusCode
	readStarted := time.Now()
	res.BytesRead, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 32768))
	res.ReadMS = time.Since(readStarted).Milliseconds()
	res.LatencyMS = time.Since(start).Milliseconds()
	res.StreamStatus = classifyStream(resp, res.BytesRead, err)
	if err != nil {
		res.Status = "fail"
		res.Detail = fmt.Sprintf("response stream interrupted after %d bytes: %s", res.BytesRead, short(err.Error()))
		return res
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		res.Status = "pass"
		res.Detail = "HTTP endpoint reachable through the currently applied routing"
	case resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 407 || resp.StatusCode == 429 || resp.StatusCode == 451:
		res.Status = "partial"
		res.Detail = fmt.Sprintf("network path works, but service/policy returned HTTP %d", resp.StatusCode)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		res.Status = "partial"
		res.Detail = fmt.Sprintf("HTTP endpoint reached with client error %d", resp.StatusCode)
	default:
		res.Status = "fail"
		res.Detail = fmt.Sprintf("HTTP endpoint returned %d", resp.StatusCode)
	}
	return res
}

func classifyStream(resp *http.Response, bytesRead int64, readErr error) string {
	if readErr != nil {
		return "interrupted"
	}
	if bytesRead == 0 {
		return "empty"
	}
	if bytesRead >= 32768 || resp.ContentLength > bytesRead {
		return "sampled"
	}
	return "complete"
}

func resultKey(result Result) string {
	return result.ServiceID + "|" + result.Route + "|" + result.ScenarioID
}

func serviceProbes(service catalog.Service) []catalog.Probe {
	if len(service.Probes) > 0 {
		return append([]catalog.Probe(nil), service.Probes...)
	}
	return []catalog.Probe{{ID: "primary", Label: "Основной доступ", URL: service.ProbeURL, Required: true}}
}

func withProbe(service catalog.Service, probe catalog.Probe) catalog.Service {
	service.ProbeURL = probe.URL
	return service
}

// AggregateScenarios produces one conservative result per service and route.
// A required failure must not be hidden by a successful web landing page.
func AggregateScenarios(results []Result) []Result {
	groups := map[string][]Result{}
	keys := []string{}
	for _, result := range results {
		key := result.ServiceID + "|" + result.Route
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], result)
	}
	sort.Strings(keys)
	out := make([]Result, 0, len(keys))
	for _, key := range keys {
		rows := groups[key]
		if len(rows) == 1 {
			out = append(out, rows[0])
			continue
		}
		aggregate := rows[0]
		aggregate.ScenarioID = "all"
		requiredCount := 0
		for _, row := range rows {
			if row.ScenarioNeeded {
				requiredCount++
			}
		}
		aggregate.ScenarioLabel = fmt.Sprintf("Все обязательные сценарии (%d)", requiredCount)
		aggregate.ScenarioNeeded = true
		aggregate.ProbeURL = ""
		aggregate.Status = "pass"
		aggregate.Detail = fmt.Sprintf("%d обязательных сценариев подтверждены", requiredCount)
		aggregate.RouteConfirmed = true
		aggregate.EvidenceLevel = evidence.Service
		aggregate.LatencyMS = 0
		failed := []string{}
		partial := []string{}
		for _, row := range rows {
			if !row.ScenarioNeeded {
				continue
			}
			if !row.RouteConfirmed {
				aggregate.RouteConfirmed = false
			}
			if !row.AssuranceLevel().AtLeast(aggregate.EvidenceLevel) {
				aggregate.EvidenceLevel = row.AssuranceLevel()
			}
			if row.LatencyMS > aggregate.LatencyMS {
				aggregate.LatencyMS = row.LatencyMS
			}
			switch row.Status {
			case "pass":
			case "partial":
				partial = append(partial, row.ScenarioLabel)
			default:
				failed = append(failed, row.ScenarioLabel)
			}
		}
		switch {
		case len(failed) > 0:
			aggregate.Status = "fail"
			aggregate.Detail = "Не пройдены обязательные сценарии: " + strings.Join(failed, ", ")
		case len(partial) > 0:
			aggregate.Status = "partial"
			aggregate.Detail = "Частичный ответ в сценариях: " + strings.Join(partial, ", ")
		}
		aggregate.NormalizeEvidence()
		out = append(out, aggregate)
	}
	return out
}

func selectServices(cat catalog.Catalog, ids []string) []catalog.Service {
	if len(ids) == 0 {
		return append([]catalog.Service(nil), cat.Services...)
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	out := []catalog.Service{}
	for _, s := range cat.Services {
		if wanted[s.ID] {
			out = append(out, s)
		}
	}
	return out
}
func short(s string) string {
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}

// DecodeRunRequest deliberately accepts only service IDs from the catalog. URLs are never accepted from the browser,
// which prevents the test endpoint from becoming an arbitrary SSRF primitive on the router.
func DecodeRunRequest(body io.Reader) ([]string, error) {
	var in struct {
		Services []string `json:"services"`
	}
	d := json.NewDecoder(io.LimitReader(body, 64<<10))
	if err := d.Decode(&in); err != nil && err != io.EOF {
		return nil, err
	}
	return in.Services, nil
}
