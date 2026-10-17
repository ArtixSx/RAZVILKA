package dataplane

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// This lane never retries a command. It closes only the legacy two-adapter
// Stop whose original Deactivate failed, after independently observing both
// runtimes absent. Ordinary rollback/close eligibility remains unchanged.
func mixedStopRetirementHistory(r failedRollback) bool {
	validPlan := func(p Plan) bool {
		return slices.Equal(p.Adapters, []string{"nfqws2", "sing-box"}) && p.LAN == nil && p.DNS == nil && p.DomainPolicy == nil && p.SyntheticDNS == nil && !p.SuspendDNS && !p.DiscardDNS && len(p.RetiringAdapters) == 0
	}
	if r.latest == nil || !validPlan(r.plan) || !validPlan(r.previous) || len(r.latest.Resources) != 0 || r.latest.ResourcePlanID != "" {
		return false
	}
	var forward []ExecutionStep
	for _, s := range r.latest.Steps {
		if recovery, _ := rollbackRecoveryPhase(s.Phase); !recovery {
			forward = append(forward, s)
		}
	}
	if len(forward) != 4 {
		return false
	}
	for i, want := range []struct{ adapter, phase, state string }{{"nfqws2", "snapshot", "passed"}, {"sing-box", "snapshot", "passed"}, {"nfqws2", "deactivate", "passed"}, {"sing-box", "deactivate", "failed"}} {
		s := forward[i]
		if s.Adapter != want.adapter || s.Phase != want.phase || s.State != want.state || s.StartedAt == "" || s.FinishedAt == "" {
			return false
		}
	}
	return true
}

func mixedStopRetirementEvidence(r failedRollback) []string {
	transaction := filepath.Join("transactions", r.plan.PlanID)
	committed := filepath.Join("transactions", r.previous.PlanID)
	return []string{"latest-execution.json", "latest-plan.json", "latest-committed-plan.json", filepath.Join(transaction, "execution.json"), filepath.Join(transaction, "sing-box", "snapshot.json"), filepath.Join(transaction, "nfqws2", "snapshot.json"), filepath.Join(committed, "execution.json"), filepath.Join(committed, "sing-box", "policy-additions.json")}
}

func validateMixedStopRetirement(a *ProxyTunnelAdapter, r failedRollback, manifest bootRetirementManifest) error {
	refuse := func() error { return ErrBootRetirement }
	if manifest.Schema != 2 || !mixedStopRetirementHistory(r) || !kernelBootIDPattern.MatchString(manifest.OldBoot) || manifest.OldBoot == manifest.CurrentBoot || !kernelBootIDPattern.MatchString(manifest.CurrentBoot) || len(manifest.Files) == 0 || len(manifest.Files) > 512 || len(manifest.Evidence) != 8 || !boundedBootRetirement(manifest) {
		return refuse()
	}
	for _, name := range mixedStopRetirementEvidence(r) {
		if _, exists := manifest.Evidence[name]; !exists {
			return refuse()
		}
	}
	var original, transaction, committedExecution Execution
	var failed, committed Plan
	var snapshot proxySnapshot
	var nfqSnapshot nfqws2Snapshot
	var receipt proxyPolicyReceipt
	decode := func(name string, target any) bool { return json.Unmarshal(manifest.Evidence[name], target) == nil }
	root := filepath.Join("transactions", r.plan.PlanID)
	prior := filepath.Join("transactions", r.previous.PlanID)
	if !decode("latest-execution.json", &original) || !decode(filepath.Join(root, "execution.json"), &transaction) || !reflect.DeepEqual(original, transaction) ||
		!decode("latest-plan.json", &failed) || !decode("latest-committed-plan.json", &committed) || !reflect.DeepEqual(committed, r.previous) ||
		!decode(filepath.Join(root, "sing-box", "snapshot.json"), &snapshot) || !decode(filepath.Join(root, "nfqws2", "snapshot.json"), &nfqSnapshot) ||
		!decode(filepath.Join(prior, "execution.json"), &committedExecution) || committedExecution.State != "committed" || committedExecution.PlanID != committed.PlanID || committedExecution.Digest != committed.Digest || len(committedExecution.Resources) != 0 || committedExecution.ResourcePlanID != "" ||
		!decode(filepath.Join(prior, "sing-box", "policy-additions.json"), &receipt) {
		return refuse()
	}
	// Recheck the original images with the same narrow history reviewer. Later
	// recovery steps may have been appended, but the forward prefix is immutable.
	originalHistory := r
	originalHistory.latest, originalHistory.plan, originalHistory.previous = &original, failed, committed
	if !mixedStopRetirementHistory(originalHistory) || original.State != "rollback-failed" || original.PlanID != r.plan.PlanID || original.Digest != r.plan.Digest || failed.PlanID != r.plan.PlanID || failed.Digest != r.plan.Digest || failed.State != "rollback-failed" {
		return refuse()
	}
	forward := func(e Execution) []ExecutionStep {
		var out []ExecutionStep
		for _, s := range e.Steps {
			if recovery, _ := rollbackRecoveryPhase(s.Phase); !recovery {
				out = append(out, s)
			}
		}
		return out
	}
	if !reflect.DeepEqual(forward(original), forward(*r.latest)) || snapshot.EngineID != "sing-box" || !kernelBootIDPattern.MatchString(snapshot.BootID) || !snapshot.PolicyExists || !snapshot.PolicyTracked || snapshot.PolicyBinding == nil || snapshot.ConfigDraft || a.checkSnapshotSidecar(snapshot) != nil || nfqSnapshot.ConfigDraft {
		return refuse()
	}
	var policy proxyPolicyJournal
	var binding proxyPolicyBinding
	if json.Unmarshal(manifest.Files[filepath.Join("sing-box", "policy.json")], &policy) != nil || policy.AdditionReceiptVersion != 1 || json.Unmarshal(manifest.Files[filepath.Join("sing-box", "policy-generation.json")], &binding) != nil ||
		binding.Schema != 1 || binding.Engine != "sing-box" || binding.Phase != "active" || binding.Digest != proxyPolicyDigest(policy.PolicyState) || !reflect.DeepEqual(binding, *snapshot.PolicyBinding) || !reflect.DeepEqual(policy.PolicyState, snapshot.Policy) {
		return refuse()
	}
	state := policy.PolicyState
	if state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority || state.NetworkPolicyGeneration != "" || state.NetworkDefault || state.WireGuardEndpoint != nil {
		return refuse()
	}
	if _, err := policyAdditionExpected(state); err != nil {
		return refuse()
	}
	unsigned := receipt
	unsigned.Checksum = ""
	raw, _ := json.Marshal(unsigned)
	canonical, _ := json.Marshal(receipt)
	if receipt.Schema != 1 || receipt.Engine != "sing-box" || receipt.Boot != manifest.OldBoot || receipt.Phase != "complete" || receipt.Generation != binding.Generation || receipt.Generation != binding.ReceiptID || receipt.Digest != binding.Digest || receipt.NoAdditions || receipt.RestorationGeneration != "" || receipt.RetirementSnapshot != "" || receipt.RetirementReceiptID != "" || receipt.Checksum != routeidentity.Hash(raw) || !bytes.Equal(canonical, manifest.Evidence[filepath.Join(prior, "sing-box", "policy-additions.json")]) {
		return refuse()
	}
	allowed := map[string]bool{}
	for _, path := range bootRetirementRuntimePaths(a) {
		name, _ := filepath.Rel(filepath.Dir(a.StateRoot), path)
		allowed[name] = true
	}
	boundSeen := false
	for name, raw := range manifest.Files {
		if allowed[name] {
			continue
		}
		parts := strings.Split(name, string(filepath.Separator))
		if len(parts) != 4 || parts[0] != "sing-box" || parts[1] != "policy-generations" || !slices.Contains([]string{policyAdditionFile, policyAdditionLock, "policy-state.json"}, parts[3]) {
			return refuse()
		}
		path, err := a.policyGenerationRoot(parts[2])
		if err != nil {
			return refuse()
		}
		if parts[3] == policyAdditionFile {
			var expected *PolicyState
			if parts[2] == binding.Generation {
				expected = &state
				boundSeen = true
			}
			// Orphan generations are archived as unknown old-boot evidence. They
			// do not mint a cleanup grant or claim that their commands completed.
			valid := validateBootRetirementReceipt(raw, path, manifest.OldBoot, expected, false) == nil
			if expected == nil {
				valid = validUnknownBootRetirementReceipt(raw, manifest.OldBoot, a)
			}
			if !valid || !bytes.Equal(manifest.Files[filepath.Join(filepath.Dir(name), policyAdditionLock)], []byte(policyAdditionMarker)) {
				return refuse()
			}
			if expected != nil {
				var doc policyAdditionDocument
				_ = json.Unmarshal(raw, &doc)
				if doc.ID != binding.ReceiptID {
					return refuse()
				}
			}
		}
	}
	if !boundSeen {
		return refuse()
	}
	return nil
}

// Historical copied orphan roots are not deletion authority. Preserve their
// original root hash and bytes instead of rebinding them to their current path.
// Only this metadata-only, fully absent-runtime operation accepts that shape.
func validUnknownBootRetirementReceipt(raw []byte, boot string, a *ProxyTunnelAdapter) bool {
	var doc policyAdditionDocument
	if json.Unmarshal(raw, &doc) != nil || doc.Schema != 1 || doc.Boot != boot || !validPlanDigest(doc.RootHash) || !validPlanDigest(doc.PolicyHash) || !nfqws2ManagedHex(doc.ID, 32) || doc.Checksum != policyAdditionChecksum(doc) || doc.Phase != "active" || doc.PromotionTarget != "" || doc.Generation != "" || doc.EffectsHash != "" || len(doc.Steps) == 0 || len(doc.Steps) > MaxPolicyEffects {
		return false
	}
	canonical, _ := json.Marshal(doc)
	if !bytes.Equal(raw, canonical) {
		return false
	}
	for _, step := range doc.Steps {
		if step.Tool != "" || len(step.Needs) != 0 || !validPolicyAdditionStepState(step.State) || !retiredProxyStepCoveredByAbsence(step, a) {
			return false
		}
	}
	return true
}

// Check coverage only, never execute these historical argv. Every possible
// effect in an orphan image must fall within the interface/table and complete
// priority ranges read by observeBootRetirementKernel, including shared slots.
func retiredProxyStepCoveredByAbsence(step policyAdditionStep, a *ProxyTunnelAdapter) bool {
	owner, _, err := a.inactiveCoordinates()
	if err != nil {
		return false
	}
	args := step.Add
	family := 4
	if len(args) > 0 && args[0] == "-6" {
		family = 6
		args = args[1:]
	}
	if len(args) < 4 || !reflect.DeepEqual(step.Delete, slicesPolicyCommand(step.Add, "del")) {
		return false
	}
	if args[0] == "route" {
		metric := "0"
		if family == 6 {
			metric = "1024"
		}
		return reflect.DeepEqual(args, []string{"route", "add", "default", "dev", a.Interface, "table", strconv.Itoa(a.Table), "proto", "boot", "metric", metric})
	}
	if args[0] != "rule" || args[1] != "add" || args[2] != "priority" || len(args) < 6 {
		return false
	}
	tail := args[4:]
	if tail[0] != "from" {
		tail = append([]string{"from", "all"}, tail...)
	}
	rule, ok := parseKernelPolicyRule(family, args[3]+": "+strings.Join(tail, " "))
	if !ok || rule.table != a.Table && rule.table != 254 || !(rule.priority >= owner.PriorityBase && rule.priority <= owner.PriorityEnd || rule.priority >= owner.SharedPriorityBase && rule.priority <= owner.SharedPriorityEnd) {
		return false
	}
	return reflect.DeepEqual(kernelRuleArgs("add", rule), step.Add)
}
