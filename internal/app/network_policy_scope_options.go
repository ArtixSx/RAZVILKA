package app

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

const networkPolicyScopeOptionsPath = "/api/v1/networkpolicy/scope-options"

type networkPolicyScopeOptionsResponse struct {
	Schema           int    `json:"schema"`
	OK               bool   `json:"ok"`
	Revision         uint64 `json:"revision"`
	PolicyRevision   uint64 `json:"policy_revision"`
	EffectAuthorized bool   `json:"effect_authorized"`
	LiveApplied      bool   `json:"live_applied"`
	physicalscope.ScopeOptionsObservation
	RetainedSegmentIDs []string `json:"retained_segment_ids"`
	RetainedDeviceIDs  []string `json:"retained_device_ids"`
}

func (a *App) networkPolicyScopeOptions(w http.ResponseWriter, r *http.Request) {
	a.networkPolicyScopeOptionsRead(w, r, physicalscope.ObserveReviewedStockNC1812ScopeOptions)
}

// The private seam supplies modeled observations in tests, never an authority.
// Production has exactly one concrete protected read source above.
func (a *App) networkPolicyScopeOptionsRead(w http.ResponseWriter, r *http.Request, observe func(context.Context) physicalscope.ScopeOptionsObservation) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Security == nil || !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"code": "AUTH_REQUIRED"})
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || r.ContentLength != 0 {
		writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_SCOPE_OPTIONS_INPUT"})
		return
	}
	if a.Store == nil {
		writeJSON(w, 503, map[string]any{"code": "NETWORK_POLICY_SCOPE_OPTIONS_UNAVAILABLE"})
		return
	}
	// Existing shared admission can wait up to two seconds before this handler.
	// The three-second budget covers the entire admitted observation below.
	c, cancel := context.WithTimeout(r.Context(), physicalscope.ScopeOptionsTimeout)
	defer cancel()
	before := a.Store.Get()
	observation := observe(c)
	if c.Err() != nil {
		observation = scopeOptionsUnavailable("SOURCE_CANCELED")
		if c.Err() == context.DeadlineExceeded {
			observation.Code = "SOURCE_TIMEOUT"
		}
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		writeJSON(w, 409, map[string]any{"code": "NETWORK_POLICY_SCOPE_OPTIONS_CHANGED"})
		return
	}
	response := networkPolicyScopeOptionsView(before, observation)
	data, err := json.Marshal(response)
	if err != nil || len(data) > 1<<20 {
		// Source bound failure must not intersect or truncate saved policy refs.
		response = networkPolicyScopeOptionsView(before, scopeOptionsUnavailable("BOUNDS_EXCEEDED"))
	}
	writeJSON(w, 200, response)
}

func scopeOptionsUnavailable(code string) physicalscope.ScopeOptionsObservation {
	return physicalscope.ScopeOptionsObservation{State: "unavailable", Code: code, Segments: []physicalscope.ScopeSegmentOption{}, Devices: []physicalscope.ScopeDeviceOption{}}
}

func networkPolicyScopeOptionsView(cfg config.Config, observation physicalscope.ScopeOptionsObservation) networkPolicyScopeOptionsResponse {
	r := networkPolicyScopeOptionsResponse{Schema: 1, OK: true, Revision: cfg.Revision, RetainedSegmentIDs: []string{}, RetainedDeviceIDs: []string{}}
	if cfg.NetworkPolicy != nil {
		r.PolicyRevision = cfg.NetworkPolicy.Revision
	}
	for _, p := range []*config.NetworkPolicy{cfg.NetworkPolicy, cfg.AppliedNetworkPolicy} {
		if p != nil {
			r.RetainedSegmentIDs = append(r.RetainedSegmentIDs, p.Clients.SegmentIDs...)
			r.RetainedDeviceIDs = append(r.RetainedDeviceIDs, p.Clients.DeviceIDs...)
			r.RetainedDeviceIDs = append(r.RetainedDeviceIDs, p.Clients.ExcludedDeviceIDs...)
		}
	}
	slices.Sort(r.RetainedSegmentIDs)
	r.RetainedSegmentIDs = slices.Compact(r.RetainedSegmentIDs)
	slices.Sort(r.RetainedDeviceIDs)
	r.RetainedDeviceIDs = slices.Compact(r.RetainedDeviceIDs)
	if len(observation.Segments) > 16 || len(observation.Devices) > 512 {
		observation = scopeOptionsUnavailable("BOUNDS_EXCEEDED")
	}
	observation.Segments, observation.Devices = slices.Clone(observation.Segments), slices.Clone(observation.Devices)
	if observation.Segments == nil {
		observation.Segments = []physicalscope.ScopeSegmentOption{}
	}
	if observation.Devices == nil {
		observation.Devices = []physicalscope.ScopeDeviceOption{}
	}
	r.ScopeOptionsObservation = observation
	for _, id := range r.RetainedSegmentIDs {
		matches := 0
		for _, s := range observation.Segments {
			if s.ID == id || s.NativeName != nil && *s.NativeName == id {
				matches++
			}
		}
		if matches != 1 {
			code := "SAVED_REFERENCE_UNKNOWN"
			if matches > 1 {
				code = "ALIAS_CONFLICT"
			}
			r.Segments = append(r.Segments, physicalscope.ScopeSegmentOption{ID: id, Label: id, State: "unknown", Code: code})
		}
	}
	for _, id := range r.RetainedDeviceIDs {
		if slices.ContainsFunc(observation.Devices, func(d physicalscope.ScopeDeviceOption) bool { return d.ID == id }) {
			continue
		}
		state, code := "unknown", "SAVED_REFERENCE_UNKNOWN"
		if observation.State == "available" {
			state, code = "not_observed", "NOT_OBSERVED"
		}
		r.Devices = append(r.Devices, physicalscope.ScopeDeviceOption{ID: id, Label: id, State: state, Code: code})
	}
	// Labels stay ID-only here: Known/ListWithStatus hold the discovery mutex
	// without a cancellable wait. The UI may apply its existing cached labels;
	// this GET never discovers, persists metadata or uses cached associations.
	slices.SortFunc(r.Segments, func(a, b physicalscope.ScopeSegmentOption) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(r.Devices, func(a, b physicalscope.ScopeDeviceOption) int { return strings.Compare(a.ID, b.ID) })
	return r
}
