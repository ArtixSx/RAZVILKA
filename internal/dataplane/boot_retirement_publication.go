package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// Write-ahead images are restricted to three fixed journal names. This is an
// offline metadata publication protocol, never a receipt for a kernel effect.
type bootRetirementPublication struct {
	Schema                                         int
	PlanID, Digest, SettingsSHA256, ManifestSHA256 string
	Before, After                                  map[string][]byte
	Checksum                                       string
}

func bootPublicationChecksum(p bootRetirementPublication) string {
	p.Checksum = ""
	raw, _ := json.Marshal(p)
	return routeidentity.Hash(raw)
}
func bootPublicationPaths(id string) []string {
	return []string{filepath.Join("transactions", id, "execution.json"), "latest-execution.json", "latest-plan.json"}
}

func readBootPublication(root *os.Root, archive string) (*bootRetirementPublication, error) {
	raw, err := bootRetirementRead(root, filepath.Join(archive, "publication.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p bootRetirementPublication
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF || p.Schema != 1 || p.Checksum != bootPublicationChecksum(p) {
		return nil, ErrBootRetirement
	}
	canonical, _ := json.Marshal(p)
	if !bytes.Equal(canonical, raw) {
		return nil, ErrBootRetirement
	}
	return &p, nil
}

func verifyBootPublicationCurrent(root *os.Root, p *bootRetirementPublication) error {
	if p == nil || len(p.Before) != 3 || len(p.After) != 3 {
		return ErrBootRetirement
	}
	for _, path := range bootPublicationPaths(p.PlanID) {
		before, beforeOK := p.Before[path]
		after, afterOK := p.After[path]
		current, err := bootRetirementRead(root, path)
		if !beforeOK || !afterOK || err != nil || !bytes.Equal(current, before) && !bytes.Equal(current, after) {
			return ErrBootRetirement
		}
	}
	return nil
}

func (m *Manager) reviewBootPublication(root *os.Root, manifest bootRetirementManifest, p *bootRetirementPublication) (failedRollback, bool) {
	if p == nil || p.Schema != 1 || p.PlanID != manifest.PlanID || p.Digest != manifest.Digest || p.SettingsSHA256 != manifest.SettingsSHA256 || p.ManifestSHA256 != bootRetirementChecksum(manifest) || verifyBootPublicationCurrent(root, p) != nil {
		return failedRollback{}, false
	}
	var original, originalTransaction Execution
	var originalPlan, previous Plan
	transaction := filepath.Join("transactions", manifest.PlanID, "execution.json")
	if json.Unmarshal(manifest.Evidence["latest-execution.json"], &original) != nil || json.Unmarshal(manifest.Evidence[transaction], &originalTransaction) != nil || json.Unmarshal(manifest.Evidence["latest-plan.json"], &originalPlan) != nil || json.Unmarshal(manifest.Evidence["latest-committed-plan.json"], &previous) != nil {
		return failedRollback{}, false
	}
	if _, ok := m.reviewFailedRollbackImagesMode(manifest.PlanID, manifest.Digest, &original, &originalTransaction, originalPlan, previous, manifest.Schema == 2); !ok {
		return failedRollback{}, false
	}
	forward := func(e Execution) []ExecutionStep {
		var result []ExecutionStep
		for _, step := range e.Steps {
			if recovery, _ := rollbackRecoveryPhase(step.Phase); !recovery {
				result = append(result, step)
			}
		}
		return result
	}
	for _, images := range []map[string][]byte{p.Before, p.After} {
		var plan Plan
		if json.Unmarshal(images["latest-plan.json"], &plan) != nil || plan.State != "rollback-failed" && plan.State != "rolled-back" {
			return failedRollback{}, false
		}
		comparison := plan
		comparison.State, comparison.Note = originalPlan.State, originalPlan.Note
		if !reflect.DeepEqual(comparison, originalPlan) {
			return failedRollback{}, false
		}
		plan.State = "rollback-failed"
		for _, path := range []string{transaction, "latest-execution.json"} {
			var execution Execution
			if json.Unmarshal(images[path], &execution) != nil || execution.RollbackVerified || execution.State != "rollback-failed" && execution.State != "rolled-back" || !reflect.DeepEqual(forward(execution), forward(original)) {
				return failedRollback{}, false
			}
			execution.State = "rollback-failed"
			if _, ok := m.reviewFailedRollbackImagesMode(manifest.PlanID, manifest.Digest, &execution, &execution, plan, previous, manifest.Schema == 2); !ok {
				return failedRollback{}, false
			}
		}
	}
	var desired Execution
	var plan Plan
	if !bytes.Equal(p.After[transaction], p.After["latest-execution.json"]) || json.Unmarshal(p.After["latest-execution.json"], &desired) != nil || json.Unmarshal(p.After["latest-plan.json"], &plan) != nil || desired.RollbackVerified || desired.State != "rollback-failed" && desired.State != "rolled-back" || plan.State != "rollback-failed" && plan.State != "rolled-back" {
		return failedRollback{}, false
	}
	comparison := plan
	comparison.State, comparison.Note = originalPlan.State, originalPlan.Note
	if !reflect.DeepEqual(comparison, originalPlan) {
		return failedRollback{}, false
	}
	desired.State, plan.State = "rollback-failed", "rollback-failed"
	return m.reviewFailedRollbackImagesMode(manifest.PlanID, manifest.Digest, &desired, &desired, plan, previous, manifest.Schema == 2)
}

func (w *bootRetirementWriter) publish(updates map[string][]byte) error {
	if w.current() != nil || w.archive == "" {
		return ErrBootRetirement
	}
	if w.pending != nil {
		if err := verifyBootPublicationCurrent(w.state, w.pending); err != nil {
			return err
		}
	}
	before := map[string][]byte{}
	after := map[string][]byte{}
	for _, path := range bootPublicationPaths(w.manifest.PlanID) {
		raw, err := bootRetirementRead(w.state, path)
		if err != nil {
			return err
		}
		if w.pending == nil && !bytes.Equal(raw, w.manifest.Evidence[path]) {
			return ErrBootRetirement
		}
		before[path] = raw
		after[path] = raw
	}
	for path, raw := range updates {
		if _, ok := after[path]; !ok {
			return ErrBootRetirement
		}
		after[path] = raw
	}
	p := &bootRetirementPublication{Schema: 1, PlanID: w.manifest.PlanID, Digest: w.manifest.Digest, SettingsSHA256: w.manifest.SettingsSHA256, ManifestSHA256: bootRetirementChecksum(w.manifest), Before: before, After: after}
	p.Checksum = bootPublicationChecksum(*p)
	raw, _ := json.Marshal(p)
	if len(raw) > bootRetirementLimit {
		return ErrBootRetirement
	}
	if err := writeBootRetirementAtomic(w.state, filepath.Join(w.archive, "publication.json"), raw); err != nil {
		return err
	}
	w.pending = p
	if w.fault != nil {
		if err := w.fault("publication-intent"); err != nil {
			return err
		}
	}
	return w.finishPublication(p)
}

func (w *bootRetirementWriter) finishPublication(p *bootRetirementPublication) error {
	for _, path := range bootPublicationPaths(p.PlanID) {
		if err := errors.Join(w.current(), verifyBootPublicationCurrent(w.state, p)); err != nil {
			return err
		}
		current, err := bootRetirementRead(w.state, path)
		if err != nil {
			return err
		}
		if bytes.Equal(current, p.After[path]) {
			continue
		}
		if w.observe == nil || w.observe() != nil {
			return ErrBootRetirement
		}
		root, name := w.state, path
		if path == filepath.Join("transactions", p.PlanID, "execution.json") {
			root, name = w.transaction, "execution.json"
		}
		if err := writeBootRetirementAtomic(root, name, p.After[path]); err != nil {
			return err
		}
		if w.fault != nil {
			if err := w.fault("publication-write:" + path); err != nil {
				return err
			}
		}
	}
	return w.current()
}
