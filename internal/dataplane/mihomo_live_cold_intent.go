package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

var ErrMihomoLiveRetirement = errors.New("offline Mihomo runtime retirement requires intact intent and fresh complete absence")

const mihomoLiveRetirementDetail = "Original Mihomo runtime retired offline after fresh process and kernel absence; historical service access and original rollback remain unverified."

// This parses comparison data only. The offline operation independently owns
// its store lifetime, directory/file anchors and real absence observations.
func decodeMihomoLiveRetirementIntent(raw []byte) (Execution, ExecutionMihomoLiveDefinition, error) {
	var e Execution
	var d ExecutionMihomoLiveDefinition
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > 4<<20 || nfqws2ManagedUniqueJSON(raw) != nil || decoder.Decode(&e) != nil || decoder.Decode(new(any)) != io.EOF || !validPlanID(e.PlanID) || e.ResourcePlanID != "" || validateExecutionResources(e, false) != nil {
		return e, d, ErrMihomoLiveRetirement
	}
	// An interrupted commit retains its separate publication protocol. Offline
	// retirement may not turn a finalizing transaction into an acknowledged one.
	switch e.State {
	case "applying", "resource-failed", "journal-failed", "cancelled", "rolling-back", "rollback-failed", "rolled-back", "committed":
	default:
		return e, d, ErrMihomoLiveRetirement
	}
	found := false
	for _, row := range e.Resources {
		if row.MihomoLive != nil {
			if found {
				return e, d, ErrMihomoLiveRetirement
			}
			found = true
			d = row.MihomoLive.Clone()
		} else if row.Kind != "node-transit" || row.NodeTransit == nil || row.NodeTransit.Engine != "mihomo" {
			return e, d, ErrMihomoLiveRetirement
		}
	}
	if !found || d.Plan.PlanID != e.PlanID || d.Plan.Digest != e.Digest {
		return e, d, ErrMihomoLiveRetirement
	}
	return e, d, nil
}

func mihomoLiveRetirementTerminal(before Execution, finished string) (Execution, error) {
	if _, err := time.Parse(time.RFC3339Nano, finished); err != nil {
		return Execution{}, ErrMihomoLiveRetirement
	}
	raw, err := json.Marshal(before)
	if err != nil {
		return Execution{}, err
	}
	if _, _, err := decodeMihomoLiveRetirementIntent(raw); err != nil {
		return Execution{}, err
	}
	after := before
	after.Resources = cloneExecutionResources(before.Resources)
	after.Steps = append([]ExecutionStep(nil), before.Steps...)
	for i := range after.Resources {
		after.Resources[i].State = "removed"
		if after.Resources[i].MihomoLive != nil {
			after.Resources[i].Phase = "removed"
		}
	}
	for i := range after.Steps {
		_, finishedErr := time.Parse(time.RFC3339Nano, after.Steps[i].FinishedAt)
		if after.Steps[i].State != "passed" || finishedErr != nil {
			after.Steps[i].State = "failed"
			after.Steps[i].FinishedAt = finished
			after.Steps[i].Detail = mihomoLiveRetirementDetail
		}
	}
	after.State, after.FinishedAt, after.Error = "rolled-back", finished, mihomoLiveRetirementDetail
	after.RollbackVerified = false
	after.Steps = append(after.Steps, ExecutionStep{Adapter: "mihomo", Phase: "close-retire-mihomo", State: "passed", StartedAt: finished, FinishedAt: finished, Detail: mihomoLiveRetirementDetail})
	return after, validateExecutionResources(after, true)
}
