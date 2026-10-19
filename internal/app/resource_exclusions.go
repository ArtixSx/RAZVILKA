package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

const resourceExclusionsPath = "/api/v1/networkpolicy/exclusions"

func (a *App) resourceExclusions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Security == nil || !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"error": "Требуется авторизация."})
		return
	}
	if a.Store == nil {
		writeJSON(w, 503, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_UNAVAILABLE"})
		return
	}
	if r.Method == http.MethodGet {
		a.writeResourceExclusions(w, a.Store.Get())
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request struct {
		ExpectedRevision          uint64                          `json:"expected_revision"`
		ExpectedPolicyRevision    uint64                          `json:"expected_policy_revision"`
		ExpectedExclusionRevision uint64                          `json:"expected_exclusion_revision"`
		Manual                    *[]config.ResourceMatch         `json:"manual"`
		Accepted                  *config.AcceptedRussianSnapshot `json:"accepted_russian_snapshot"`
		RussianEnabled            *bool                           `json:"russian_enabled"`
		RussianAutoUpdateAllowed  *bool                           `json:"russian_auto_update_allowed"`
	}
	// JSON null must not turn an explicit deletion into an omitted patch. Empty
	// [] clears manual entries; omission preserves them. Feed deletion is absent.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 512<<10))
	if err != nil {
		writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_INVALID"})
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_INVALID"})
		return
	}
	for _, key := range []string{"manual", "accepted_russian_snapshot", "russian_enabled", "russian_auto_update_allowed"} {
		if raw, present := fields[key]; present && string(raw) == "null" {
			writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_INVALID"})
			return
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.Manual == nil && request.Accepted == nil && request.RussianEnabled == nil && request.RussianAutoUpdateAllowed == nil {
		writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_INVALID"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ctx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	store := a.Store
	before := store.Get()
	policyRevision, exclusionRevision := uint64(0), uint64(0)
	if before.NetworkPolicy != nil {
		policyRevision = before.NetworkPolicy.Revision
		if before.NetworkPolicy.Exclusions != nil {
			exclusionRevision = before.NetworkPolicy.Exclusions.Revision
		}
	} else if before.InactiveResourceExclusions != nil {
		exclusionRevision = before.InactiveResourceExclusions.Revision
	}
	if before.Revision != request.ExpectedRevision || policyRevision != request.ExpectedPolicyRevision || exclusionRevision != request.ExpectedExclusionRevision {
		writeJSON(w, 409, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_CHANGED", "live_applied": false})
		return
	}
	if before.NetworkPolicy == nil && (request.Accepted != nil || request.RussianEnabled != nil || request.RussianAutoUpdateAllowed != nil) {
		writeJSON(w, 503, map[string]any{"code": "NETWORK_POLICY_SCOPE_REQUIRED", "live_applied": false})
		return
	}
	if config.ValidateListNetworkPolicy(before.NetworkPolicy) != nil {
		writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_LIST_REQUIRED", "live_applied": false})
		return
	}
	var after config.Config
	err = a.Operations.WithExclusiveContext(ctx, func() error {
		if a.Store != store {
			return config.ErrRevisionChanged
		}
		var err error
		after, err = store.UpdateResourceExclusionsPatch(ctx, before, config.ResourceExclusionsPatch{Manual: request.Manual, Accepted: request.Accepted, RussianEnabled: request.RussianEnabled, RussianAutoUpdateAllowed: request.RussianAutoUpdateAllowed})
		return err
	})
	if err != nil {
		status, code := 503, "NETWORK_POLICY_EXCLUSIONS_UNAVAILABLE"
		if errors.Is(err, config.ErrRevisionChanged) {
			status, code = 409, "NETWORK_POLICY_EXCLUSIONS_CHANGED"
		} else if errors.Is(err, config.ErrResourceExclusions) {
			status, code = 400, "NETWORK_POLICY_EXCLUSIONS_INVALID"
		}
		writeJSON(w, status, map[string]any{"code": code, "live_applied": false})
		return
	}
	a.writeResourceExclusions(w, after)
}

func (a *App) writeResourceExclusions(w http.ResponseWriter, cfg config.Config) {
	effective, err := config.EffectiveConfigResourceExclusions(cfg)
	if err != nil {
		writeJSON(w, 503, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_UNAVAILABLE"})
		return
	}
	applied, err := config.EffectiveResourceExclusions(cfg.AppliedNetworkPolicy)
	if err != nil {
		writeJSON(w, 503, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_UNAVAILABLE"})
		return
	}
	var exclusions *config.ResourceExclusions
	russianEnabled := false
	russianAutoUpdateAllowed := false
	if cfg.NetworkPolicy != nil {
		exclusions, russianEnabled = cfg.NetworkPolicy.Exclusions, cfg.NetworkPolicy.Russian.Enabled
		russianAutoUpdateAllowed = cfg.NetworkPolicy.Russian.AutoUpdateAllowed
	} else {
		exclusions = cfg.InactiveResourceExclusions
	}
	storageState := "inactive"
	if cfg.NetworkPolicy != nil {
		storageState = "configured"
	}
	desiredMatchesApplied := reflect.DeepEqual(cfg.NetworkPolicy, cfg.AppliedNetworkPolicy)
	if cfg.NetworkPolicy == nil && cfg.AppliedNetworkPolicy == nil {
		desiredMatchesApplied = a.committedHonoursSiteExclusions(cfg)
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "revision": cfg.Revision, "policy_revision": effective.PolicyRevision,
		"exclusion_revision": effective.Revision, "resource_exclusions": exclusions,
		"russian_enabled": russianEnabled, "russian_auto_update_allowed": russianAutoUpdateAllowed, "effective": effective,
		"scope_configured": cfg.NetworkPolicy != nil, "storage_state": storageState,
		"applied_revision": cfg.AppliedRevision, "applied_effective": applied,
		"desired_matches_applied": desiredMatchesApplied,
		"live_applied":            false,
	})
}

// In the whole-network mode the saved list is applied through the committed
// plan. Nothing committed matches only an empty list.
func (a *App) committedHonoursSiteExclusions(cfg config.Config) bool {
	plan := dataplane.Plan{}
	if a.Dataplane != nil {
		committed, exists, err := a.Dataplane.Committed()
		if err != nil {
			return false
		}
		if exists && committed.State == "committed" {
			plan = committed
		}
	}
	return dataplane.PlanHonoursLegacyExclusions(cfg, plan)
}
