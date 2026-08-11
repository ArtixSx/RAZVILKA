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
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type Result struct {
	ServiceID   string `json:"service_id"`
	ServiceName string `json:"service_name"`
	ProbeURL    string `json:"probe_url"`
	Route       string `json:"route"`
	Status      string `json:"status"` // pass, partial, fail, not-ready, pending
	HTTPStatus  int    `json:"http_status,omitempty"`
	LatencyMS   int64  `json:"latency_ms,omitempty"`
	CheckedAt   string `json:"checked_at"`
	Detail      string `json:"detail,omitempty"`
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

type Runner struct {
	Client *http.Client
	mu     sync.RWMutex
	latest map[string]Result
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
	results := make([]Result, len(selected))
	var wg sync.WaitGroup
	for i, s := range selected {
		i, s := i, s
		wg.Add(1)
		go func() { defer wg.Done(); sem <- struct{}{}; defer func() { <-sem }(); results[i] = r.probe(ctx, s) }()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].ServiceName < results[j].ServiceName })
	r.mu.Lock()
	for _, v := range results {
		r.latest[v.ServiceID] = v
	}
	r.mu.Unlock()
	return results
}

func (r *Runner) Snapshot(cat catalog.Catalog) Snapshot {
	r.mu.RLock()
	current := make([]Result, 0, len(r.latest))
	for _, v := range r.latest {
		current = append(current, v)
	}
	r.mu.RUnlock()
	sort.Slice(current, func(i, j int) bool { return current[i].ServiceName < current[j].ServiceName })
	return Snapshot{Current: current, Matrix: r.matrix(cat, current)}
}

func (r *Runner) matrix(cat catalog.Catalog, current []Result) []MatrixCell {
	last := map[string]Result{}
	for _, v := range current {
		last[v.ServiceID] = v
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
			if v, ok := last[s.ID]; ok && v.Route == "current" {
				copy := v
				cell.Last = &copy
			}
			cells = append(cells, cell)
		}
	}
	return cells
}

func (r *Runner) probe(ctx context.Context, s catalog.Service) Result {
	res := Result{ServiceID: s.ID, ServiceName: s.Name, ProbeURL: s.ProbeURL, Route: "current", Status: "fail", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
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
	req.Header.Set("User-Agent", "RAZVILKA-Probe/0.0.7")
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
	req.Header.Set("Range", "bytes=0-4095")
	start := time.Now()
	resp, err := r.Client.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Detail = short(err.Error())
		return res
	}
	defer resp.Body.Close()
	res.HTTPStatus = resp.StatusCode
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
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
