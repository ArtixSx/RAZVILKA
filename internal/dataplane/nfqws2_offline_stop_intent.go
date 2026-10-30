package dataplane

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const NFQWS2OfflineStopJournalName = "offline-nfqws2-stop.json"
const NFQWS2OfflineStopJournalLimit = 16 << 20

// NFQWS2OfflineStopIntent is the private offline command's comparison WAL.
// Persisted data never substitutes for fresh native observation or Store CAS.
// Sharing its closed codec lets the original native source independently read
// the actual pending intent for interrupted metadata cleanup; no public flag
// or caller-provided 'inactive' assertion can grant that narrow admission.
type NFQWS2OfflineStopIntent struct {
	Version      int                             `json:"version"`
	State        string                          `json:"state"`
	StateRoot    string                          `json:"state_root"`
	StateOwner   string                          `json:"state_owner"`
	ConfigPath   string                          `json:"config_path"`
	ConfigOwner  string                          `json:"config_owner"`
	DNSPath      string                          `json:"dns_path"`
	AppliedAt    time.Time                       `json:"applied_at"`
	Plan         Plan                            `json:"plan"`
	Target       Plan                            `json:"target"`
	ConfigBefore config.Config                   `json:"config_before"`
	ConfigAfter  config.Config                   `json:"config_after"`
	BeforeImage  restorejournal.Image            `json:"before_image"`
	AfterImage   restorejournal.Image            `json:"after_image"`
	Resolved     map[string]string               `json:"resolved"`
	Original     map[string]restorejournal.Image `json:"original"`
	HooksAfter   map[string]restorejournal.Image `json:"hooks_after"`
	Source       NFQWS2OfflineStopEvidence       `json:"source"`
	Publication  *OfflineNFQWS2StopPublication   `json:"publication,omitempty"`
}

func DecodeNFQWS2OfflineStopIntent(raw []byte) (NFQWS2OfflineStopIntent, error) {
	var intent NFQWS2OfflineStopIntent
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > NFQWS2OfflineStopJournalLimit || d.Decode(&intent) != nil || d.Decode(new(any)) != io.EOF {
		return intent, ErrReviewChanged
	}
	canonical, err := json.Marshal(intent)
	if err != nil || !bytes.Equal(canonical, raw) || ValidateNFQWS2OfflineStopIntent(intent) != nil {
		return NFQWS2OfflineStopIntent{}, ErrReviewChanged
	}
	return intent, nil
}

func ValidateNFQWS2OfflineStopIntent(in NFQWS2OfflineStopIntent) error {
	if in.Version != 1 || in.State != "pending" && in.State != "inactive" && in.State != "applying" && in.State != "complete" || in.AppliedAt.IsZero() ||
		in.StateOwner == "" || in.ConfigOwner == "" || !NFQWS2OfflineStopPlanScope(in.Plan) || ValidateNFQWS2EmptyStopPlan(in.Target) != nil ||
		in.ConfigBefore.ServiceControl.Stopped || in.Plan.Revision != in.ConfigBefore.AppliedRevision || in.Target.Revision != in.ConfigBefore.Revision+1 ||
		len(in.Original) != 7 || len(in.HooksAfter) != 2 || !in.Source.Matches(in.Source, false) {
		return ErrReviewChanged
	}
	for _, path := range []string{in.StateRoot, in.ConfigPath, in.DNSPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == filepath.VolumeName(path)+string(filepath.Separator) {
			return ErrReviewChanged
		}
	}
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json", "latest-execution.json", "latest-recovery.json", "nfqws2-hooks-recovery.json", nfqws2BootHookJournal, filepath.Join("transactions", in.Plan.PlanID, "execution.json")} {
		image, ok := in.Original[name]
		if !ok || !image.Exists && len(image.Data) != 0 || len(image.Data) > 1<<20 {
			return ErrReviewChanged
		}
	}
	for _, name := range []string{"nfqws2-hooks-recovery.json", nfqws2BootHookJournal} {
		image, ok := in.HooksAfter[name]
		if !ok || !image.Exists && len(image.Data) != 0 || len(image.Data) > 1<<20 {
			return ErrReviewChanged
		}
	}
	planRaw, _ := json.MarshalIndent(in.Plan, "", "  ")
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json"} {
		if !in.Original[name].Exists || !bytes.Equal(in.Original[name].Data, planRaw) {
			return ErrReviewChanged
		}
	}
	executionImage := in.Original["latest-execution.json"]
	var execution Execution
	d := json.NewDecoder(bytes.NewReader(executionImage.Data))
	d.DisallowUnknownFields()
	if !executionImage.Exists || d.Decode(&execution) != nil || d.Decode(new(any)) != io.EOF || execution.State != "committed" || execution.PlanID != in.Plan.PlanID || execution.Digest != in.Plan.Digest || execution.ResourcePlanID != "" || len(execution.Resources) != 0 || execution.RollbackVerified || execution.Error != "" {
		return ErrExecutionJournal
	}
	executionRaw, _ := json.MarshalIndent(execution, "", "  ")
	if !bytes.Equal(executionRaw, executionImage.Data) || !emptyStopImageEqual(executionImage, in.Original[filepath.Join("transactions", in.Plan.PlanID, "execution.json")]) {
		return ErrExecutionJournal
	}
	for _, at := range []string{execution.StartedAt, execution.FinishedAt} {
		if _, err := time.Parse(time.RFC3339Nano, at); err != nil {
			return ErrExecutionJournal
		}
	}
	for _, step := range execution.Steps {
		if step.State != "passed" || step.FinishedAt == "" {
			return ErrExecutionJournal
		}
	}
	before, _, err := config.InspectBytes(in.BeforeImage.Data)
	if err != nil || !in.BeforeImage.Exists || !offlineStopWireEqual(before, in.ConfigBefore) {
		return ErrReviewChanged
	}
	after, err := config.ReviewedNFQWS2StopImage(in.ConfigBefore, in.Resolved, in.AppliedAt)
	if err != nil || !offlineStopWireEqual(after, in.ConfigAfter) {
		return ErrReviewChanged
	}
	encoded, _ := json.MarshalIndent(after, "", "  ")
	if !in.AfterImage.Exists || !bytes.Equal(encoded, in.AfterImage.Data) || !PlanHonoursLegacyExclusions(in.ConfigBefore, in.Plan) {
		return ErrReviewChanged
	}
	exclusions, err := LegacySiteExclusions(in.ConfigBefore)
	if err != nil || !reflect.DeepEqual(exclusions, in.Target.SiteExclusions) {
		return ErrReviewChanged
	}
	if in.State == "complete" && in.Publication == nil {
		return ErrReviewChanged
	}
	if in.Publication != nil && (in.State != "applying" && in.State != "complete" || ValidateNFQWS2EmptyStopPublication(in.Plan, in.Target, in.Original, *in.Publication) != nil) {
		return ErrReviewChanged
	}
	if in.ConfigBefore.NetworkPolicy != nil || in.ConfigBefore.AppliedNetworkPolicy != nil || in.ConfigBefore.DefaultRouteConsent != nil || len(in.Resolved) != len(in.Plan.Routes) {
		return ErrReviewChanged
	}
	seen := map[string]bool{}
	for _, route := range in.Plan.Routes {
		state, exists := in.ConfigBefore.AppliedServices[route.ServiceID]
		if route.ServiceID == "" || seen[route.ServiceID] || !exists || !state.Enabled || state.Route != route.Selected || route.Resolved != "nfqws2" || in.Resolved[route.ServiceID] != "nfqws2" || len(state.Sources) != 0 || len(route.Sources) != 0 {
			return ErrReviewChanged
		}
		seen[route.ServiceID] = true
	}
	return nil
}

func offlineStopWireEqual(a, b any) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}
