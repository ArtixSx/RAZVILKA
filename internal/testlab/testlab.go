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
	"github.com/ArtixSx/razvilka/internal/probecheck"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type Result struct {
	ServiceID              string                  `json:"service_id"`
	ServiceName            string                  `json:"service_name"`
	ProbeURL               string                  `json:"probe_url"`
	ScenarioID             string                  `json:"scenario_id,omitempty"`
	ScenarioLabel          string                  `json:"scenario_label,omitempty"`
	ScenarioNeeded         bool                    `json:"scenario_required,omitempty"`
	Route                  string                  `json:"route"`
	Status                 string                  `json:"status"` // pass, partial, fail, not-ready, pending
	HTTPStatus             int                     `json:"http_status,omitempty"`
	LatencyMS              int64                   `json:"latency_ms,omitempty"`
	TTFBMS                 int64                   `json:"ttfb_ms,omitempty"`
	ReadMS                 int64                   `json:"read_ms,omitempty"`
	BytesRead              int64                   `json:"bytes_read,omitempty"`
	StreamStatus           string                  `json:"stream_status,omitempty"`
	CheckedAt              string                  `json:"checked_at"`
	Detail                 string                  `json:"detail,omitempty"`
	RouteConfirmed         bool                    `json:"route_confirmed"`
	EvidenceSource         string                  `json:"evidence_source,omitempty"`
	EvidenceLevel          evidence.Level          `json:"evidence_level"`
	Outcome                evidence.Outcome        `json:"outcome"`
	EvidenceV2             *evidence.ProbeEvidence `json:"evidence_v2,omitempty"`
	EvidenceFreshUntil     string                  `json:"evidence_fresh_until,omitempty"`
	EgressIP               string                  `json:"egress_ip,omitempty"`
	Verdict                evidence.Verdict        `json:"verdict,omitempty"`
	ErrorCode              string                  `json:"error_code,omitempty"`
	FinalURL               string                  `json:"final_url,omitempty"`
	RedirectChain          []string                `json:"redirect_chain,omitempty"`
	ContentType            string                  `json:"content_type,omitempty"`
	ContentFingerprint     string                  `json:"content_fingerprint,omitempty"`
	ExpectedRoutePathID    string                  `json:"expected_route_path_id,omitempty"`
	ObservedRoutePathID    string                  `json:"observed_route_path_id,omitempty"`
	NegativeControlMatched bool                    `json:"negative_control_matched,omitempty"`
	RouteProofError        string                  `json:"route_proof_error,omitempty"`
}

// EvaluateHTTP retains only redacted metadata and a bounded content digest;
// response bodies (which may contain service data) never enter diagnostics.
func (result *Result) EvaluateHTTP(service catalog.Service, observation probecheck.Observation) {
	assessment := probecheck.Evaluate(service, probecheck.ServiceProbe(service), observation)
	result.Status, result.Verdict, result.Outcome = assessment.Status, assessment.Verdict, assessment.Outcome
	result.Detail, result.ErrorCode = assessment.Detail, assessment.ErrorCode
	result.ContentFingerprint = assessment.ContentFingerprint
	result.ContentType = observation.ContentType
	result.FinalURL = probecheck.RedactedURL(observation.FinalURL)
	result.RedirectChain = make([]string, 0, len(observation.RedirectChain))
	for _, target := range observation.RedirectChain {
		result.RedirectChain = append(result.RedirectChain, probecheck.RedactedURL(target))
	}
	result.ExpectedRoutePathID = observation.ExpectedRoutePathID
	result.ObservedRoutePathID = observation.ObservedRoutePathID
	result.NegativeControlMatched = observation.NegativeControlMatched
}

// NormalizeEvidence derives the public assurance level from observed facts.
// It is safe to call for old adapters that only populate RouteConfirmed.
func (result *Result) NormalizeEvidence() {
	if result == nil {
		return
	}
	if result.RouteProofError != "" {
		result.RouteConfirmed = false
		result.ObservedRoutePathID = ""
		if result.Status == "pass" {
			result.Status, result.Verdict = "partial", evidence.VerdictInconclusive
			result.Outcome = evidence.OutcomeTransportReachable
		}
	}
	if result.Verdict == evidence.VerdictPass && result.Status != "pass" {
		result.Verdict = evidence.VerdictFromProbe(result.Status, result.HTTPStatus, result.ErrorCode)
		result.Outcome = evidence.OutcomeFromProbe(result.Status, result.HTTPStatus, result.ErrorCode)
	}
	if result.NegativeControlMatched || (result.ExpectedRoutePathID != "" && result.ObservedRoutePathID != "" && result.ExpectedRoutePathID != result.ObservedRoutePathID) || result.Verdict == evidence.VerdictMisrouted {
		result.RouteConfirmed = false
		result.Status = "partial"
		result.Verdict = evidence.VerdictMisrouted
		result.Outcome = evidence.OutcomeTransportReachable
	}
	if result.EvidenceV2 == nil {
		finished, err := time.Parse(time.RFC3339, result.CheckedAt)
		if err != nil {
			finished = time.Now().UTC()
		}
		started := finished.Add(-time.Duration(result.LatencyMS) * time.Millisecond)
		routePath := ""
		if result.RouteConfirmed {
			routePath = "isolated:" + result.Route
			if result.ObservedRoutePathID != "" {
				routePath = result.ObservedRoutePathID
			}
		}
		errorCode := result.ErrorCode
		if errorCode == "" {
			errorCode = probeErrorCode(result.Detail)
		}
		if result.Verdict == "" {
			result.Verdict = evidence.VerdictFromProbe(result.Status, result.HTTPStatus, errorCode)
		}
		outcome := result.Outcome
		if outcome == "" {
			outcome = evidence.OutcomeFromProbe(result.Status, result.HTTPStatus, errorCode)
		}
		confidence := 0.25
		if outcome == evidence.OutcomeServiceAccepted {
			confidence = 1
		} else if outcome != evidence.OutcomeUnknown {
			confidence = 0.65
		}
		result.EvidenceV2 = &evidence.ProbeEvidence{
			SchemaVersion: evidence.ProbeSchemaVersion,
			ProbeID:       fmt.Sprintf("%s:%s:%s:%d", result.ServiceID, result.ScenarioID, result.Route, finished.UnixNano()),
			StartedAt:     started, FinishedAt: finished,
			Service: result.ServiceID, Subservice: result.ScenarioID,
			RoutePathID: routePath, Engine: result.Route, EgressIP: result.EgressIP,
			Stage: "service", Outcome: outcome, HTTPStatus: result.HTTPStatus,
			LatencyMS: result.LatencyMS, Confidence: confidence,
			Source: result.EvidenceSource, ErrorCode: errorCode,
			Verdict: result.Verdict, RequestedURL: probecheck.RedactedURL(result.ProbeURL), FinalURL: result.FinalURL,
			RedirectChain: append([]string(nil), result.RedirectChain...), ContentType: result.ContentType,
			ContentFingerprint:  result.ContentFingerprint,
			ExpectedRoutePathID: result.ExpectedRoutePathID, ObservedRoutePathID: result.ObservedRoutePathID,
			NegativeControlMatched: result.NegativeControlMatched,
			RouteProofError:        result.RouteProofError,
		}
	}
	if result.RouteProofError != "" || result.EvidenceV2.RouteProofError != "" {
		copy := *result.EvidenceV2
		if result.RouteProofError != "" {
			copy.RouteProofError = result.RouteProofError
		}
		copy.RoutePathID = ""
		copy.ObservedRoutePathID = ""
		if copy.Verdict == evidence.VerdictPass {
			copy.Verdict, copy.Outcome = evidence.VerdictInconclusive, evidence.OutcomeTransportReachable
		}
		result.EvidenceV2 = &copy
		result.RouteProofError = copy.RouteProofError
		result.RouteConfirmed = false
		result.ObservedRoutePathID = ""
		result.EgressIP = ""
		if result.Status == "pass" {
			result.Status = "partial"
		}
	}
	probe := result.EvidenceV2
	if result.Verdict == evidence.VerdictMisrouted || probe.Verdict == evidence.VerdictMisrouted || probe.NegativeControlMatched || (probe.ExpectedRoutePathID != "" && probe.ObservedRoutePathID != "" && probe.ExpectedRoutePathID != probe.ObservedRoutePathID) {
		copy := *result.EvidenceV2
		copy.Verdict = evidence.VerdictMisrouted
		copy.Outcome = evidence.OutcomeTransportReachable
		copy.RoutePathID = ""
		result.EvidenceV2 = &copy
		result.Status = "partial"
		result.RouteConfirmed = false
	}
	result.Outcome = result.EvidenceV2.Outcome
	result.Verdict = result.EvidenceV2.Verdict
	result.EvidenceFreshUntil = result.EvidenceV2.FinishedAt.Add(24 * time.Hour).Format(time.RFC3339)
	derived := result.EvidenceV2.AssuranceLevel()
	if result.EvidenceLevel.Valid() && result.EvidenceLevel != evidence.None {
		result.EvidenceLevel = evidence.Weaker(result.EvidenceLevel, derived)
	} else {
		result.EvidenceLevel = derived
	}
}

// AssuranceLevel returns a normalized value without mutating the result.
func (result Result) AssuranceLevel() evidence.Level {
	result.NormalizeEvidence()
	return result.EvidenceLevel
}

func probeErrorCode(detail string) string {
	detail = strings.ToLower(strings.TrimSpace(detail))
	switch {
	case strings.Contains(detail, "certificate") || strings.Contains(detail, "tls"):
		return "tls-certificate-mismatch"
	case strings.Contains(detail, "timeout") || strings.Contains(detail, "deadline exceeded"):
		return "timeout"
	case strings.Contains(detail, "context canceled"):
		return "cancelled"
	default:
		return ""
	}
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
	res := Result{ServiceID: s.ID, ServiceName: s.Name, ProbeURL: probecheck.RedactedURL(s.ProbeURL), ScenarioID: probe.ID, ScenarioLabel: probe.Label, ScenarioNeeded: probe.Required, Route: "current", Status: "fail", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
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
	req.Header.Set("User-Agent", "RAZVILKA-Probe/0.16.0")
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
	req.Header.Set("Range", "bytes=0-32767")
	start := time.Now()
	redirects := []string{}
	resp, err := probecheck.RecordingClient(r.Client, s, &redirects).Do(req)
	res.TTFBMS = time.Since(start).Milliseconds()
	if err != nil {
		res.LatencyMS = time.Since(start).Milliseconds()
		res.Detail = short(probecheck.RedactedError(err))
		return res
	}
	defer resp.Body.Close()
	res.HTTPStatus = resp.StatusCode
	readStarted := time.Now()
	body, err := io.ReadAll(io.LimitReader(resp.Body, probecheck.MaxBodyBytes))
	res.BytesRead = int64(len(body))
	res.ReadMS = time.Since(readStarted).Milliseconds()
	res.LatencyMS = time.Since(start).Milliseconds()
	res.StreamStatus = classifyStream(resp, res.BytesRead, err)
	if err != nil {
		res.Status = "fail"
		res.Detail = fmt.Sprintf("response stream interrupted after %d bytes: %s", res.BytesRead, short(err.Error()))
		return res
	}
	res.EvaluateHTTP(s, probecheck.Observation{RequestedURL: s.ProbeURL, FinalURL: probecheck.FinalURL(resp, s.ProbeURL), RedirectChain: redirects, HTTPStatus: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: body, BodyTruncated: res.StreamStatus == "sampled"})
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
	service.Probes = []catalog.Probe{probe}
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
		aggregate := Result{ServiceID: rows[0].ServiceID, ServiceName: rows[0].ServiceName, Route: rows[0].Route, CheckedAt: rows[0].CheckedAt, EvidenceSource: "required-scenarios"}
		aggregate.ScenarioID = "all"
		requiredCount := 0
		for _, row := range rows {
			if row.ScenarioNeeded {
				requiredCount++
			}
		}
		allRequired := requiredCount == 0
		if allRequired {
			requiredCount = len(rows)
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
		var representative *Result
		for _, row := range rows {
			if !row.ScenarioNeeded && !allRequired {
				continue
			}
			row.NormalizeEvidence()
			if representative == nil || verdictSeverity(row.Verdict) > verdictSeverity(representative.Verdict) {
				copy := row
				representative = &copy
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
				aggregate.HTTPStatus = row.HTTPStatus
				partial = append(partial, row.ScenarioLabel)
			default:
				aggregate.HTTPStatus = row.HTTPStatus
				failed = append(failed, row.ScenarioLabel)
			}
		}
		if representative != nil {
			aggregate.HTTPStatus = representative.HTTPStatus
			aggregate.Outcome = representative.Outcome
			aggregate.Verdict = representative.Verdict
			aggregate.ErrorCode = representative.ErrorCode
			aggregate.ExpectedRoutePathID = representative.ExpectedRoutePathID
			aggregate.ObservedRoutePathID = representative.ObservedRoutePathID
			aggregate.NegativeControlMatched = representative.NegativeControlMatched
		}
		switch {
		case len(failed) > 0:
			aggregate.Status = "fail"
			aggregate.Detail = "Не пройдены обязательные сценарии: " + strings.Join(failed, ", ")
		case len(partial) > 0:
			aggregate.Status = "partial"
			aggregate.Detail = "Частичный ответ в сценариях: " + strings.Join(partial, ", ")
		}
		aggregate.EvidenceV2 = nil
		aggregate.EvidenceFreshUntil = ""
		aggregate.NormalizeEvidence()
		out = append(out, aggregate)
	}
	return out
}

func verdictSeverity(verdict evidence.Verdict) int {
	switch verdict {
	case evidence.VerdictMisrouted:
		return 5
	case evidence.VerdictBlocked:
		return 4
	case evidence.VerdictError:
		return 3
	case evidence.VerdictInconclusive:
		return 2
	case evidence.VerdictPartial:
		return 1
	default:
		return 0
	}
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
