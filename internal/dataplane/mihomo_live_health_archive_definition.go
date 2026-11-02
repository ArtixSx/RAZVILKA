package dataplane

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
)

// Immutable reader8 comparison history only. Native join/cleanup, original
// writer ownership and callback revocation require the SAME live issuer.
// Only the archive transaction carries this marker; origin After has none.
type MihomoTransitHistoryArchive struct {
	Schema             int    `json:"schema"`
	OriginExecutionID  string `json:"origin_execution_id"`
	OriginPlanID       string `json:"origin_plan_id"`
	OriginDigest       string `json:"origin_digest"`
	OriginBefore       []byte `json:"origin_before"`
	OriginBeforeSHA256 string `json:"origin_before_sha256"`
	OriginAfterSHA256  string `json:"origin_after_sha256"`
}

const mihomoTransitArchiveRows = 128
const mihomoTransitArchiveImageLimit = 4 << 20

func (h MihomoTransitHistoryArchive) Clone() MihomoTransitHistoryArchive {
	h.OriginBefore = bytes.Clone(h.OriginBefore)
	return h
}

func (h MihomoTransitHistoryArchive) validate(archive Execution) error {
	_, err := h.deriveAfter(archive)
	return err
}

func (h MihomoTransitHistoryArchive) deriveAfter(archive Execution) (Execution, error) {
	refuse := func() (Execution, error) { return Execution{}, ErrExecutionJournal }
	if h.Schema != 1 || !validPlanID(h.OriginExecutionID) || h.OriginPlanID != h.OriginExecutionID || !validPlanDigest(h.OriginDigest) || !validPlanDigest(h.OriginBeforeSHA256) || !validPlanDigest(h.OriginAfterSHA256) || len(h.OriginBefore) == 0 || len(h.OriginBefore) > mihomoTransitArchiveImageLimit || nodeDefaultSourceMaterialHash(h.OriginBefore) != h.OriginBeforeSHA256 || !mihomoTransitArchiveExecutionID(archive.PlanID) || archive.PlanID == h.OriginExecutionID || archive.ResourcePlanID != h.OriginPlanID || archive.Digest != h.OriginDigest || archive.State != "temporary-complete" || archive.RollbackVerified || archive.Error != "" || len(archive.Resources) < mihomoTransitArchiveRows || len(archive.Resources) > maxExecutionResources {
		return refuse()
	}
	if archive.DomainDNSCoexistence != nil || archive.MihomoTransitHistoryArchive != nil && !reflect.DeepEqual(h, *archive.MihomoTransitHistoryArchive) {
		return refuse()
	}
	started, e1 := time.Parse(time.RFC3339Nano, archive.StartedAt)
	finished, e2 := time.Parse(time.RFC3339Nano, archive.FinishedAt)
	if e1 != nil || e2 != nil || started.IsZero() || finished.Before(started) || started.UTC().Format(time.RFC3339Nano) != archive.StartedAt || finished.UTC().Format(time.RFC3339Nano) != archive.FinishedAt || len(archive.Steps) != 1 {
		return refuse()
	}
	step := archive.Steps[0]
	if step.Adapter != "mihomo" || step.Phase != "archive-joined-transit" || step.State != "passed" || step.StartedAt != archive.StartedAt || step.FinishedAt != archive.FinishedAt || step.Detail != "" {
		return refuse()
	}
	// Reject recursion BEFORE ordinary resource validation can dispatch back to
	// this marker. Strict canonical bytes preserve the original writer image.
	var keys map[string]json.RawMessage
	if nfqws2ManagedUniqueJSON(h.OriginBefore) != nil || json.Unmarshal(h.OriginBefore, &keys) != nil || keys["mihomo_transit_history_archive"] != nil {
		return refuse()
	}
	var before Execution
	decoder := json.NewDecoder(bytes.NewReader(h.OriginBefore))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&before) != nil || decoder.Decode(new(any)) != io.EOF || before.PlanID != h.OriginExecutionID || before.Digest != h.OriginDigest || before.State != "committed" || before.ResourcePlanID != "" || before.RollbackVerified || before.DomainDNSCoexistence != nil || validateExecutionResources(before, true) != nil {
		return refuse()
	}
	canonical, err := json.Marshal(before)
	if err != nil || !bytes.Equal(canonical, h.OriginBefore) {
		return refuse()
	}
	if !reflect.DeepEqual(archive.MihomoLiveHealthOperation, before.MihomoLiveHealthOperation) {
		return refuse()
	}
	var live *ExecutionMihomoLiveDefinition
	for _, row := range before.Resources {
		if row.Kind == "mihomo-live" {
			if live != nil || row.State != "active" || row.MihomoLive == nil {
				return refuse()
			}
			live = row.MihomoLive
		} else if row.Kind != "node-transit" {
			return refuse()
		}
	}
	if live == nil {
		return refuse()
	}
	rows := make(map[string]ExecutionResource, len(before.Resources))
	for _, row := range before.Resources {
		rows[row.ID] = row
	}
	selected := map[string]bool{}
	var cohort *NodeTransitSpec
	for _, row := range archive.Resources {
		original, found := rows[row.ID]
		if !found || selected[row.ID] || row.Kind != "node-transit" || row.NodeTransit == nil || row.State != "removed" && row.State != "unused" || !reflect.DeepEqual(original, row) {
			return refuse()
		}
		spec := row.NodeTransit
		if spec.Engine != "mihomo" || spec.BootID != live.NetworkIdentity.BootID || spec.NetworkProfile != live.NetworkProfile || spec.RuntimeID != live.Profile.ConfigSHA256 || spec.Interface != live.Policy.Interface || spec.Table != live.Policy.Table || spec.Priority != 80 {
			return refuse()
		}
		if cohort != nil && (spec.PolicyGeneration != cohort.PolicyGeneration || spec.IfIndex != cohort.IfIndex || spec.Source != cohort.Source) {
			return refuse()
		}
		cohort = spec
		selected[row.ID] = true
	}
	after := before
	after.Resources = nil
	for _, row := range before.Resources {
		if !selected[row.ID] {
			after.Resources = append(after.Resources, row)
		}
	}
	after.Resources = cloneExecutionResources(after.Resources)
	afterImage, err := json.Marshal(after)
	if err != nil || nodeDefaultSourceMaterialHash(afterImage) != h.OriginAfterSHA256 {
		return refuse()
	}
	// Include the marker's embedded base64 image in the actual archive bound,
	// even when a pure caller has not yet attached the shared Execution field.
	archiveImage, err := json.Marshal(archive)
	var archiveKeys map[string]json.RawMessage
	if err != nil || json.Unmarshal(archiveImage, &archiveKeys) != nil {
		return refuse()
	}
	marker, err := json.Marshal(h)
	if err != nil {
		return refuse()
	}
	archiveKeys["mihomo_transit_history_archive"] = marker
	complete, err := json.Marshal(archiveKeys)
	if err != nil || len(complete) > mihomoTransitArchiveImageLimit {
		return refuse()
	}
	return after, nil
}

func mihomoTransitArchiveExecutionID(id string) bool {
	const prefix = "dp-check-"
	suffix := strings.TrimPrefix(id, prefix)
	return strings.HasPrefix(id, prefix) && len(suffix) == 32 && strings.Trim(suffix, "0123456789abcdef") == ""
}
