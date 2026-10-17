package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// completedBootRetirement recognizes only the original durable offline
// publication. It never interprets prose as authority, observes current runtime
// absence, or grants activation. A completed retirement makes the old committed
// DTO historical; only a newly reviewed Apply may replace that history.
func (m *Manager) completedBootRetirement() (bool, string, error) {
	var latest *Execution
	exists, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &latest)
	if err != nil {
		return false, "", err
	}
	candidate := false
	if exists && latest != nil {
		for _, step := range latest.Steps {
			if step.Phase == "close-retire-after-boot" {
				candidate = true
			}
		}
	}
	plan, planExists, planErr := m.latestLocked()
	previous, previousExists, previousErr := m.committedLocked()
	if latest != nil && planErr == nil && previousErr == nil && planExists && previousExists && latest.State == "rolled-back" && !latest.RollbackVerified && mixedStopRetirementPlans(plan, previous) {
		candidate = true
	}
	refuse := func() (bool, string, error) { return true, "", ErrBootRetirement }
	if _, err := os.Lstat(filepath.Join(m.StateRoot, "boot-retirements")); errors.Is(err, os.ErrNotExist) {
		if candidate {
			return refuse()
		}
		return false, "", nil
	} else if err != nil {
		return refuse()
	}
	if previousErr != nil || !previousExists {
		return refuse()
	}
	state, err := openBootRetirementRoot(m.StateRoot)
	if err != nil {
		return refuse()
	}
	defer state.Close()
	committedBytes, err := bootRetirementRead(state, "latest-committed-plan.json")
	if err != nil {
		return refuse()
	}
	dir, err := state.Open("boot-retirements")
	if err != nil {
		return refuse()
	}
	entries, err := dir.ReadDir(129)
	_ = dir.Close()
	if err != nil || len(entries) == 0 || len(entries) > 128 {
		return refuse()
	}
	matched := false
	retiredPlanID := ""
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || len(name) != 84 || name[19] != '-' || !validPlanID(name[:19]) || !validPlanDigest(name[20:]) {
			return refuse()
		}
		archive := filepath.Join("boot-retirements", name)
		manifest, found, err := readBootRetirementManifest(state, archive)
		if err != nil || !found || manifest.PlanID != name[:19] || manifest.Digest != name[20:] || !validPlanDigest(manifest.SettingsSHA256) {
			return refuse()
		}
		if !bytes.Equal(manifest.Evidence["latest-committed-plan.json"], committedBytes) {
			continue
		} // A genuine fresh commit superseded this archive.
		if !m.completedBootRetirementArchive(state, archive, manifest, committedBytes) {
			return refuse()
		}
		matched = true
		retiredPlanID = manifest.PlanID
	}
	if candidate && !matched {
		return refuse()
	}
	return matched, retiredPlanID, nil
}

// A later read-only preview or settled failed fresh Apply may replace the
// latest records. The retired transaction and its exact publication remain the
// anchor until a genuine new committed plan supersedes the historical DTO.
func (m *Manager) completedBootRetirementArchive(state *os.Root, archive string, manifest bootRetirementManifest, committedBytes []byte) bool {
	publication, err := readBootPublication(state, archive)
	if err != nil || publication == nil || publication.PlanID != manifest.PlanID || publication.Digest != manifest.Digest || publication.SettingsSHA256 != manifest.SettingsSHA256 || publication.ManifestSHA256 != bootRetirementChecksum(manifest) || len(publication.Before) != 3 || len(publication.After) != 3 {
		return false
	}
	var original, transaction Execution
	var originalPlan, previous Plan
	root := filepath.Join("transactions", manifest.PlanID, "execution.json")
	if json.Unmarshal(manifest.Evidence["latest-execution.json"], &original) != nil || json.Unmarshal(manifest.Evidence[root], &transaction) != nil || json.Unmarshal(manifest.Evidence["latest-plan.json"], &originalPlan) != nil || json.Unmarshal(committedBytes, &previous) != nil {
		return false
	}
	reviewed, ok := m.reviewFailedRollbackImagesMode(manifest.PlanID, manifest.Digest, &original, &transaction, originalPlan, previous, manifest.Schema == 2)
	if !ok {
		return false
	}
	forward := func(e Execution) []ExecutionStep {
		var out []ExecutionStep
		for _, step := range e.Steps {
			if recovery, _ := rollbackRecoveryPhase(step.Phase); !recovery {
				out = append(out, step)
			}
		}
		return out
	}
	for _, images := range []map[string][]byte{publication.Before, publication.After} {
		for _, path := range bootPublicationPaths(manifest.PlanID) {
			if _, ok := images[path]; !ok {
				return false
			}
		}
		if !bytes.Equal(images[root], images["latest-execution.json"]) {
			return false
		}
		var plan Plan
		if json.Unmarshal(images["latest-plan.json"], &plan) != nil || plan.State != "rollback-failed" && plan.State != "rolled-back" {
			return false
		}
		comparison := plan
		comparison.State, comparison.Note = originalPlan.State, originalPlan.Note
		if !reflect.DeepEqual(comparison, originalPlan) {
			return false
		}
		var e Execution
		if json.Unmarshal(images[root], &e) != nil || e.RollbackVerified || len(e.Resources) != 0 || e.ResourcePlanID != "" || e.State != "rollback-failed" && e.State != "rolled-back" || !reflect.DeepEqual(forward(e), forward(original)) {
			return false
		}
		e.State, plan.State = "rollback-failed", "rollback-failed"
		if _, ok := m.reviewFailedRollbackImagesMode(manifest.PlanID, manifest.Digest, &e, &e, plan, previous, manifest.Schema == 2); !ok {
			return false
		}
	}
	var terminal Execution
	var terminalPlan Plan
	if json.Unmarshal(publication.After[root], &terminal) != nil || terminal.State != "rolled-back" || terminal.RollbackVerified || len(terminal.Steps) == 0 || json.Unmarshal(publication.After["latest-plan.json"], &terminalPlan) != nil || terminalPlan.State != "rolled-back" {
		return false
	}
	last := terminal.Steps[len(terminal.Steps)-1]
	if last.Phase != "close-retire-after-boot" || last.Adapter != "sing-box" || last.State != "passed" || last.FinishedAt == "" {
		return false
	}
	currentTerminal, err := bootRetirementRead(state, root)
	if err != nil || !bytes.Equal(currentTerminal, publication.After[root]) {
		return false
	}
	a, ok := m.adapter("sing-box")
	proxy, concrete := a.(*ProxyTunnelAdapter)
	if !ok || !concrete || proxy == nil || proxy.StateRoot != filepath.Join(m.StateRoot, "sing-box") || validateBootRetirement(proxy, reviewed, manifest) != nil || verifyBootRetirementEvidence(state, manifest) != nil {
		return false
	}
	for name, expected := range manifest.Files {
		if _, err := state.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return false
		}
		raw, err := bootRetirementRead(state, filepath.Join(archive, "files", name))
		if err != nil || !bytes.Equal(raw, expected) {
			return false
		}
	}
	if !completedBootRetirementWitness(state, archive, manifest) {
		return false
	}
	checkManifest, found, err := readBootRetirementManifest(state, archive)
	if err != nil || !found || checkManifest.Checksum != manifest.Checksum {
		return false
	}
	checkPublication, err := readBootPublication(state, archive)
	if err != nil || checkPublication == nil || checkPublication.Checksum != publication.Checksum {
		return false
	}
	currentTerminal, err = bootRetirementRead(state, root)
	return err == nil && bytes.Equal(currentTerminal, publication.After[root]) && verifyBootRetirementEvidence(state, manifest) == nil
}

func completedBootRetirementWitness(state *os.Root, archive string, manifest bootRetirementManifest) bool {
	dir, err := state.Open(filepath.Join(archive, "observations"))
	if err != nil {
		return false
	}
	entries, err := dir.ReadDir(129)
	_ = dir.Close()
	if err != nil || len(entries) == 0 || len(entries) > 128 {
		return false
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			return false
		}
		boot := strings.TrimSuffix(entry.Name(), ".json")
		if !kernelBootIDPattern.MatchString(boot) || boot == manifest.OldBoot {
			return false
		}
		witness := struct {
			Schema                                            int
			ManifestSHA256, SettingsSHA256, Boot, Observation string
		}{1, bootRetirementChecksum(manifest), manifest.SettingsSHA256, boot, "bracketed-proc-interface-kernel-absence-v1"}
		if manifest.Schema == 2 {
			witness.Observation = "bracketed-proxy-and-nfq-absence-v1"
		}
		expected, _ := json.Marshal(witness)
		raw, err := bootRetirementRead(state, filepath.Join(archive, "observations", entry.Name()))
		if err != nil || !bytes.Equal(raw, expected) {
			return false
		}
	}
	return true
}
