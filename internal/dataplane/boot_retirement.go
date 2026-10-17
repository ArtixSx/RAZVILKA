package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var ErrBootRetirement = errors.New("offline post-reboot retirement requires intact reviewed history and absent runtime")

const bootRetirementLimit = 16 << 20

// Original bytes remain immutable. An archive is evidence of file retirement,
// never an acknowledgement of an old kernel command or a new cleanup grant.
type bootRetirementManifest struct {
	Schema                                               int `json:"schema"`
	PlanID, Digest, SettingsSHA256, OldBoot, CurrentBoot string
	Evidence                                             map[string][]byte
	Files                                                map[string][]byte
	Checksum                                             string
}

type bootRetirementOptions struct {
	proof     *proxyInactiveProof // Package-private fixture seam; production uses Linux.
	fault     func(string) error
	nfqAbsent func(context.Context) error // Private complete-source fixture seam only.
}

// RetireFailedRollbackAfterBoot is an explicit offline operation. The caller
// must hold all application lifetime leases continuously, before starting any
// HTTP server, worker or runtime. guard must bind the reviewed applied settings
// to settingsSHA256 and refuse any change. There is deliberately no automatic
// startup or HTTP caller. It never invokes a proxy process or kernel mutation.
func (m *Manager) RetireFailedRollbackAfterBoot(ctx context.Context, planID, digest, settingsSHA256 string, guard func(Plan) error) (Execution, error) {
	return m.retireFailedRollbackAfterBoot(ctx, planID, digest, settingsSHA256, guard, bootRetirementOptions{})
}

func (m *Manager) retireFailedRollbackAfterBoot(ctx context.Context, planID, digest, settingsSHA256 string, guard func(Plan) error, options bootRetirementOptions) (Execution, error) {
	refuse := func() (Execution, error) { return Execution{}, ErrBootRetirement }
	if m == nil || guard == nil || !validPlanID(planID) || !validPlanDigest(digest) || !validPlanDigest(settingsSHA256) {
		return refuse()
	}
	proof, err := proxyInactivePlatformProof()
	if options.proof != nil {
		proof, err = *options.proof, nil
	}
	if err != nil || proof.interfaces == nil || proof.readlink == nil {
		return refuse()
	}
	if err := m.beginOperation(ctx); err != nil {
		return Execution{}, err
	}
	defer m.endOperation()
	if m.retainedNFQOwner() != nil || m.retainedXrayOwner() != nil || m.retainedWGOwner() != nil || m.HasPendingManagedNFQWS() {
		return refuse()
	}
	state, err := openBootRetirementRoot(m.StateRoot)
	if err != nil {
		return refuse()
	}
	defer state.Close()
	archive := filepath.Join("boot-retirements", planID+"-"+digest)
	manifest, exists, err := readBootRetirementManifest(state, archive)
	if err != nil {
		return refuse()
	}
	pending, err := readBootPublication(state, archive)
	if err != nil || pending != nil && !exists {
		return refuse()
	}
	reviewed, ok := m.reviewFailedRollbackMode(planID, digest, true)
	if pending != nil {
		reviewed, ok = m.reviewBootPublication(state, manifest, pending)
	}
	mixedStop := ok && mixedStopRetirementHistory(reviewed)
	if ok && !mixedStop {
		for _, step := range reviewed.latest.Steps {
			if step.Phase == "deactivate" && step.State == "failed" {
				return refuse()
			}
		}
	}
	if !ok || (!mixedStop && (!bootRetirementPlan(reviewed.plan) || !bootRetirementPlan(reviewed.previous))) || len(reviewed.latest.Resources) != 0 || reviewed.latest.ResourcePlanID != "" {
		return refuse()
	}
	a, ok := m.adapter("sing-box")
	proxy, actual := a.(*ProxyTunnelAdapter)
	if !ok || !actual || proxy.ID() != "sing-box" || proxy.scopedXray || proxy.xrayPlanDispatch || proxy.xrayOperation ||
		proxy.StateRoot != filepath.Join(m.StateRoot, "sing-box") || guard(reviewed.previous) != nil {
		return refuse()
	}
	observe := func(c context.Context) error {
		if err := observeBootRetirement(c, proxy, proof); err != nil {
			return err
		}
		if mixedStop {
			if options.nfqAbsent != nil {
				return options.nfqAbsent(c)
			}
			nfq, valid := m.Adapters["nfqws2"].(*NFQWS2Adapter)
			if !valid || nfq == nil {
				return ErrBootRetirement
			}
			return nfq.VerifyRuntimeInactive(c)
		}
		return c.Err()
	}
	writer, err := newBootRetirementWriter(m, state, planID)
	if err != nil {
		return refuse()
	}
	defer writer.close()
	boot, err := proxy.currentBootIdentity()
	if err != nil || !kernelBootIDPattern.MatchString(boot) {
		return refuse()
	}
	if !exists {
		manifest, err = collectBootRetirement(state, proxy, reviewed, settingsSHA256, boot)
		if err != nil {
			return refuse()
		}
	}
	if manifest.PlanID != planID || manifest.Digest != digest || manifest.SettingsSHA256 != settingsSHA256 ||
		manifest.OldBoot == boot || !kernelBootIDPattern.MatchString(manifest.CurrentBoot) || validateBootRetirement(proxy, reviewed, manifest) != nil ||
		verifyBootRetirementFiles(state, archive, manifest, exists) != nil ||
		verifyBootRetirementEvidence(state, manifest) != nil ||
		observe(ctx) != nil || guard(reviewed.previous) != nil {
		return refuse()
	}
	unlock, err := lockBootRetirementReceipts(state, archive, manifest)
	if err != nil {
		return refuse()
	}
	defer unlock()
	// Only after complete preflight do we publish a durable retirement intent.
	// Refusals above leave all original journals and runtime metadata untouched.
	if !exists {
		if err := writeBootRetirementManifest(state, m.StateRoot, archive, manifest); err != nil {
			return Execution{}, errors.Join(ErrBootRetirement, err)
		}
	}
	manifest.Checksum = bootRetirementChecksum(manifest)
	manifestBytes, _ := json.Marshal(manifest)
	checkManifest, closeManifest, err := pinBootRetirementFile(state, filepath.Join(archive, "manifest.json"), manifestBytes)
	if err != nil {
		return refuse()
	}
	defer closeManifest()
	checkWitness, closeWitness, err := publishBootRetirementWitness(state, archive, manifest, boot)
	if err != nil {
		return refuse()
	}
	defer closeWitness()
	writer.provenance = func() error {
		current, err := proxy.currentBootIdentity()
		if err != nil || current != boot || guard(reviewed.previous) != nil {
			return ErrBootRetirement
		}
		return errors.Join(checkManifest(), checkWitness(), verifyBootRetirementEvidence(state, manifest))
	}
	writer.observe = func() error { return observe(ctx) }
	writer.archive, writer.manifest, writer.pending, writer.fault = archive, manifest, pending, options.fault
	if options.fault != nil && !exists {
		if err := options.fault("manifest-published"); err != nil {
			return *reviewed.latest, errors.Join(ErrBootRetirement, err)
		}
	}
	if pending != nil {
		if err := writer.finishPublication(pending); err != nil {
			return Execution{}, errors.Join(ErrBootRetirement, err)
		}
	}
	started := time.Now().UTC()
	return m.runFailedRollbackRecovery(ctx, reviewed, guard, "post-reboot metadata retirement", "post-reboot retirement failed", func(run recoveryStepRunner) {
		run(proxy, "close-retire-after-boot", func(c context.Context, _ Plan, _ string) error {
			check := func() error {
				current, err := proxy.currentBootIdentity()
				if err != nil || current != boot || guard(reviewed.previous) != nil || writer.current() != nil {
					return ErrBootRetirement
				}
				if err := verifyBootRetirementFiles(state, archive, manifest, true); err != nil {
					return fmt.Errorf("inspect retirement files: %w", err)
				}
				if err := verifyBootRetirementEvidence(state, manifest); err != nil {
					return fmt.Errorf("inspect original evidence: %w", err)
				}
				if err := observe(c); err != nil {
					return fmt.Errorf("inspect runtime absence: %w", err)
				}
				return nil
			}
			if err := bootRetirementStepPublished(state, reviewed.root, "close-retire-after-boot", started); err != nil {
				return fmt.Errorf("inspect retirement intent: %w", err)
			}
			if err := check(); err != nil {
				return err
			}
			currentOwner := func() error {
				current, err := proxy.currentBootIdentity()
				if err != nil || current != boot || writer.current() != nil || guard(reviewed.previous) != nil {
					return ErrBootRetirement
				}
				return verifyBootRetirementEvidence(state, manifest)
			}
			if err := moveBootRetirementFiles(state, m.StateRoot, archive, manifest, options.fault, currentOwner); err != nil {
				return fmt.Errorf("archive retirement files: %w", err)
			}
			// A file-only result needs fresh negative inventories too. No old
			// receipt is read as an ACK or rewritten to the new boot.
			if err := errors.Join(check(), proxy.inactiveFiles(c)); err != nil {
				return fmt.Errorf("confirm file retirement: %w", err)
			}
			return nil
		})
	}, func(execution *Execution, plan *Plan) {
		execution.RollbackVerified = false
		if mixedStop {
			execution.Error += "; retired-after-boot: old proxy metadata archived with independent fresh proxy and NFQ absence; original rollback remains unverified"
			plan.Note = "retired-after-boot: explicit offline metadata retirement; original rollback and previous service remain unverified. Apply and verify a fresh plan before claiming service access."
			return
		}
		execution.Error += "; old-boot proxy metadata archived after negative runtime inspection; no rollback acknowledgement or service verification"
		plan.Note = "Closed by explicit post-reboot metadata retirement. Runtime absence is not a rollback receipt; apply and verify a fresh plan before claiming service access."
	}, writer)
}

func bootRetirementPlan(plan Plan) bool {
	if plan.LAN != nil || plan.DNS != nil || plan.DomainPolicy != nil || plan.SyntheticDNS != nil || plan.SuspendDNS || plan.DiscardDNS || len(plan.RetiringAdapters) != 0 || !slices.Contains(plan.Adapters, "sing-box") {
		return false
	}
	// Mixed NFQ plans need their own retained cleanup/absence provenance.
	// A nil NFQ ownership lease is not proof that an unknown runtime is gone.
	if !slices.Equal(plan.Adapters, []string{"sing-box"}) {
		return false
	}
	for _, route := range plan.Routes {
		if id := adapterID(route.Resolved); id != "direct" && !slices.Contains(plan.Adapters, id) {
			return false
		}
	}
	return true
}

func openBootRetirementRoot(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrBootRetirement
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && !proxyInactivePrivateDirectory(info) {
		return nil, ErrBootRetirement
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(info, current) {
		root.Close()
		return nil, ErrBootRetirement
	}
	return root, nil
}

func bootRetirementRead(root *os.Root, name string) ([]byte, error) {
	if !filepath.IsLocal(name) || filepath.Clean(name) == "." {
		return nil, ErrBootRetirement
	}
	part := ""
	for _, component := range strings.Split(filepath.Clean(name), string(filepath.Separator)) {
		part = filepath.Join(part, component)
		info, err := root.Lstat(part)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrBootRetirement
		}
		if info.IsDir() && runtime.GOOS != "windows" && !proxyInactivePrivateDirectory(info) {
			return nil, ErrBootRetirement
		}
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > bootRetirementLimit || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrBootRetirement
	}
	data, err := io.ReadAll(io.LimitReader(file, bootRetirementLimit+1))
	if err != nil || len(data) > bootRetirementLimit {
		return nil, ErrBootRetirement
	}
	return data, nil
}

func bootRetirementChecksum(manifest bootRetirementManifest) string {
	manifest.Checksum = ""
	raw, _ := json.Marshal(manifest)
	return routeidentity.Hash(raw)
}

func readBootRetirementManifest(root *os.Root, archive string) (bootRetirementManifest, bool, error) {
	var manifest bootRetirementManifest
	raw, err := bootRetirementRead(root, filepath.Join(archive, "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return manifest, false, nil
	}
	if err != nil {
		return manifest, true, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || (manifest.Schema != 1 && manifest.Schema != 2) || manifest.Checksum != bootRetirementChecksum(manifest) {
		return manifest, true, ErrBootRetirement
	}
	canonical, _ := json.Marshal(manifest)
	if !bytes.Equal(canonical, raw) {
		return manifest, true, ErrBootRetirement
	}
	return manifest, true, nil
}

func bootRetirementRuntimePaths(a *ProxyTunnelAdapter) []string {
	paths := []string{a.policyPath(), a.policyBindingPath(), a.forwardingPath(), a.engineConfigPath(), a.sidecarConfigPath(), a.transportPath(), a.evidencePath(), a.nodeManifestPath(), a.nodeInterfacePath()}
	for _, process := range []ProcessSpec{a.engineProcess(), a.sidecarProcess()} {
		paths = append(paths, process.PIDPath, process.PIDPath+routeidentity.ReceiptSuffix)
	}
	return paths
}

func collectBootRetirement(root *os.Root, a *ProxyTunnelAdapter, reviewed failedRollback, settingsHash, boot string) (bootRetirementManifest, error) {
	manifest := bootRetirementManifest{Schema: 1, PlanID: reviewed.plan.PlanID, Digest: reviewed.plan.Digest, SettingsSHA256: settingsHash, CurrentBoot: boot, Evidence: map[string][]byte{}, Files: map[string][]byte{}}
	transaction := filepath.Join("transactions", reviewed.plan.PlanID)
	evidence := []string{"latest-execution.json", "latest-plan.json", "latest-committed-plan.json", filepath.Join(transaction, "execution.json"), filepath.Join(transaction, "sing-box", "snapshot.json"), filepath.Join(transaction, "sing-box", "policy.staged.json"), filepath.Join(transaction, "sing-box", filepath.Base(proxyPolicyReceiptPath(""))), filepath.Join(transaction, "sing-box", policyAdditionFile)}
	if mixedStopRetirementHistory(reviewed) {
		manifest.Schema = 2
		evidence = mixedStopRetirementEvidence(reviewed)
	}
	for _, path := range evidence {
		raw, err := bootRetirementRead(root, path)
		if err != nil {
			return manifest, err
		}
		manifest.Evidence[path] = raw
		if !boundedBootRetirement(manifest) {
			return manifest, ErrBootRetirement
		}
	}
	var snapshot proxySnapshot
	if json.Unmarshal(manifest.Evidence[filepath.Join(transaction, "sing-box", "snapshot.json")], &snapshot) != nil {
		return manifest, ErrBootRetirement
	}
	manifest.OldBoot = snapshot.BootID
	for _, path := range bootRetirementRuntimePaths(a) {
		name, err := filepath.Rel(filepath.Dir(a.StateRoot), path)
		if err != nil {
			return manifest, err
		}
		raw, err := bootRetirementRead(root, name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return manifest, err
		}
		manifest.Files[name] = raw
		if !boundedBootRetirement(manifest) {
			return manifest, ErrBootRetirement
		}
	}
	generations, err := root.Open(filepath.Join("sing-box", "policy-generations"))
	if err != nil {
		return manifest, err
	}
	entries, err := generations.ReadDir(129)
	generations.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 128 {
		return manifest, ErrBootRetirement
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return manifest, ErrBootRetirement
		}
		if _, err := a.policyGenerationRoot(entry.Name()); err != nil {
			return manifest, err
		}
		name := filepath.Join("sing-box", "policy-generations", entry.Name())
		dir, err := root.Open(name)
		if err != nil {
			return manifest, err
		}
		files, err := dir.ReadDir(5)
		dir.Close()
		if err != nil && !errors.Is(err, io.EOF) || len(files) > 3 {
			return manifest, ErrBootRetirement
		}
		fileNames := map[string]bool{}
		for _, file := range files {
			fileNames[file.Name()] = true
		}
		if !fileNames[policyAdditionFile] || !fileNames[policyAdditionLock] {
			return manifest, ErrBootRetirement
		}
		for _, file := range files {
			if !slices.Contains([]string{policyAdditionFile, policyAdditionLock, "policy-state.json"}, file.Name()) {
				return manifest, ErrBootRetirement
			}
			raw, err := bootRetirementRead(root, filepath.Join(name, file.Name()))
			if err != nil {
				return manifest, err
			}
			manifest.Files[filepath.Join(name, file.Name())] = raw
			if !boundedBootRetirement(manifest) {
				return manifest, ErrBootRetirement
			}
		}
	}
	if manifest.Schema == 2 {
		var binding proxyPolicyBinding
		var doc policyAdditionDocument
		if json.Unmarshal(manifest.Files[filepath.Join("sing-box", "policy-generation.json")], &binding) != nil || json.Unmarshal(manifest.Files[filepath.Join("sing-box", "policy-generations", binding.Generation, policyAdditionFile)], &doc) != nil {
			return manifest, ErrBootRetirement
		}
		manifest.OldBoot = doc.Boot
	}
	return manifest, nil
}

func validateBootRetirement(a *ProxyTunnelAdapter, reviewed failedRollback, manifest bootRetirementManifest) error {
	if manifest.Schema == 2 {
		return validateMixedStopRetirement(a, reviewed, manifest)
	}
	if manifest.Schema != 1 || !kernelBootIDPattern.MatchString(manifest.OldBoot) || manifest.OldBoot == manifest.CurrentBoot || len(manifest.Files) == 0 || len(manifest.Files) > 512 || len(manifest.Evidence) != 8 || !boundedBootRetirement(manifest) {
		return ErrBootRetirement
	}
	transaction := filepath.Join("transactions", manifest.PlanID)
	var snapshot proxySnapshot
	var candidate PolicyState
	var receipt proxyPolicyReceipt
	var policy proxyPolicyJournal
	var binding proxyPolicyBinding
	var original, originalTransaction Execution
	var failed, committed Plan
	decode := func(name string, value any) bool {
		raw, ok := manifest.Evidence[name]
		return ok && json.Unmarshal(raw, value) == nil
	}
	if !decode("latest-execution.json", &original) || !decode(filepath.Join(transaction, "execution.json"), &originalTransaction) || !reflect.DeepEqual(original, originalTransaction) || original.PlanID != manifest.PlanID || original.Digest != manifest.Digest || original.State != "rollback-failed" ||
		!decode("latest-plan.json", &failed) || !decode("latest-committed-plan.json", &committed) || failed.PlanID != manifest.PlanID || failed.Digest != manifest.Digest || committed.PlanID != reviewed.previous.PlanID || committed.Digest != reviewed.previous.Digest ||
		!decode(filepath.Join(transaction, "sing-box", "snapshot.json"), &snapshot) || snapshot.EngineID != "sing-box" || snapshot.BootID != manifest.OldBoot || !snapshot.PolicyExists || !snapshot.PolicyTracked || snapshot.PolicyBinding == nil || snapshot.ConfigDraft || a.checkSnapshotSidecar(snapshot) != nil ||
		!decode(filepath.Join(transaction, "sing-box", "policy.staged.json"), &candidate) || !decode(filepath.Join(transaction, "sing-box", "policy-additions.json"), &receipt) || receipt.Schema != 1 || receipt.Engine != "sing-box" || receipt.Boot != manifest.OldBoot || receipt.Digest != proxyPolicyDigest(candidate) || receipt.NoAdditions || receipt.RetirementSnapshot != "" {
		return ErrBootRetirement
	}
	// The original, completed forward prefix must still be the same failure.
	forward := func(steps []ExecutionStep) []ExecutionStep {
		var result []ExecutionStep
		for _, step := range steps {
			if recovery, _ := rollbackRecoveryPhase(step.Phase); !recovery {
				result = append(result, step)
			}
		}
		return result
	}
	if !reflect.DeepEqual(forward(original.Steps), forward(reviewed.latest.Steps)) {
		return ErrBootRetirement
	}
	if len(original.Resources) != 0 || original.ResourcePlanID != "" || !reflect.DeepEqual(failed.Adapters, reviewed.plan.Adapters) || !reflect.DeepEqual(committed, reviewed.previous) {
		return ErrBootRetirement
	}
	checksum := receipt.Checksum
	receipt.Checksum = ""
	unsigned, _ := json.Marshal(receipt)
	receipt.Checksum = checksum
	if checksum != routeidentity.Hash(unsigned) || !slices.Contains([]string{"unknown", "complete", "removed", "restoring", "restored"}, receipt.Phase) {
		return ErrBootRetirement
	}
	canonicalReceipt, _ := json.Marshal(receipt)
	if !bytes.Equal(canonicalReceipt, manifest.Evidence[filepath.Join(transaction, "sing-box", "policy-additions.json")]) {
		return ErrBootRetirement
	}
	if json.Unmarshal(manifest.Files[filepath.Join("sing-box", "policy.json")], &policy) != nil || policy.AdditionReceiptVersion != 1 ||
		json.Unmarshal(manifest.Files[filepath.Join("sing-box", "policy-generation.json")], &binding) != nil || binding.Schema != 1 || binding.Engine != "sing-box" || binding.Digest != proxyPolicyDigest(policy.PolicyState) || !slices.Contains([]string{"pending", "active", "removed"}, binding.Phase) {
		return ErrBootRetirement
	}
	if !reflect.DeepEqual(policy.PolicyState, snapshot.Policy) && !reflect.DeepEqual(policy.PolicyState, candidate) {
		return ErrBootRetirement
	}
	states := map[string]PolicyState{}
	addState := func(id string, state PolicyState) bool {
		if old, exists := states[id]; exists && !reflect.DeepEqual(old, state) {
			return false
		}
		states[id] = state
		return true
	}
	if !addState(binding.Generation, policy.PolicyState) || !addState(snapshot.PolicyBinding.Generation, snapshot.Policy) {
		return ErrBootRetirement
	}
	if receipt.Generation != "" {
		if !addState(receipt.Generation, candidate) {
			return ErrBootRetirement
		}
	}
	if receipt.RestorationGeneration != "" {
		if !addState(receipt.RestorationGeneration, snapshot.Policy) {
			return ErrBootRetirement
		}
	}
	for _, reference := range []struct {
		binding proxyPolicyBinding
		state   PolicyState
	}{{binding, policy.PolicyState}, {*snapshot.PolicyBinding, snapshot.Policy}} {
		if reference.binding.Schema != 1 || reference.binding.Engine != "sing-box" || reference.binding.Digest != proxyPolicyDigest(reference.state) {
			return ErrBootRetirement
		}
		var doc policyAdditionDocument
		if json.Unmarshal(manifest.Files[filepath.Join("sing-box", "policy-generations", reference.binding.Generation, policyAdditionFile)], &doc) != nil || reference.binding.ReceiptID != "" && reference.binding.ReceiptID != doc.ID {
			return ErrBootRetirement
		}
	}
	for _, state := range append([]PolicyState{candidate, snapshot.Policy, policy.PolicyState}, mapsPolicyStates(states)...) {
		if state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority || state.NetworkPolicyGeneration != "" || state.NetworkDefault || state.WireGuardEndpoint != nil {
			return ErrBootRetirement
		}
		if _, err := policyAdditionExpected(state); err != nil {
			return ErrBootRetirement
		}
	}
	if validateBootRetirementReceipt(manifest.Evidence[filepath.Join(transaction, "sing-box", policyAdditionFile)], filepath.Join(reviewed.root, "sing-box"), manifest.OldBoot, &candidate, false) != nil {
		return ErrBootRetirement
	}
	seen := map[string]bool{}
	allowed := map[string]bool{}
	for _, path := range bootRetirementRuntimePaths(a) {
		name, _ := filepath.Rel(filepath.Dir(a.StateRoot), path)
		allowed[name] = true
	}
	for name, raw := range manifest.Files {
		if allowed[name] {
			continue
		}
		parts := strings.Split(name, string(filepath.Separator))
		if len(parts) != 4 || parts[0] != "sing-box" || parts[1] != "policy-generations" || !slices.Contains([]string{policyAdditionFile, policyAdditionLock, "policy-state.json"}, parts[3]) {
			return ErrBootRetirement
		}
		path, err := a.policyGenerationRoot(parts[2])
		if err != nil {
			return err
		}
		if parts[3] == policyAdditionFile {
			state, referenced := states[parts[2]]
			var expected *PolicyState
			if referenced {
				expected = &state
			}
			if validateBootRetirementReceipt(raw, path, manifest.OldBoot, expected, !referenced) != nil || !bytes.Equal(manifest.Files[filepath.Join(filepath.Dir(name), policyAdditionLock)], []byte(policyAdditionMarker)) {
				return ErrBootRetirement
			}
			seen[parts[2]] = true
		}
	}
	for id := range states {
		if _, err := a.policyGenerationRoot(id); err != nil || !seen[id] {
			return ErrBootRetirement
		}
	}
	return nil
}

func mapsPolicyStates(states map[string]PolicyState) []PolicyState {
	var result []PolicyState
	for _, state := range states {
		result = append(result, state)
	}
	return result
}

func boundedBootRetirement(manifest bootRetirementManifest) bool {
	bytes := 0
	for _, raw := range manifest.Evidence {
		bytes += len(raw)
		if bytes > 8<<20 {
			return false
		}
	}
	for _, raw := range manifest.Files {
		bytes += len(raw)
		if bytes > 8<<20 {
			return false
		}
	}
	return true
}

func validateBootRetirementReceipt(raw []byte, path, boot string, state *PolicyState, removedOnly bool) error {
	var doc policyAdditionDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || decoder.Decode(new(any)) != io.EOF || doc.Schema != 1 || doc.Boot != boot || doc.RootHash != policyAdditionRootHash(path) || len(doc.ID) != 32 || strings.Trim(doc.ID, "0123456789abcdef") != "" || doc.Checksum != policyAdditionChecksum(doc) || doc.Phase != "active" || doc.PromotionTarget != "" || doc.Generation != "" || doc.EffectsHash != "" || len(doc.Steps) == 0 || len(doc.Steps) > MaxPolicyEffects {
		return ErrBootRetirement
	}
	canonical, _ := json.Marshal(doc)
	if !bytes.Equal(raw, canonical) {
		return ErrBootRetirement
	}
	if state != nil {
		expected, err := policyAdditionExpected(*state)
		if err != nil || doc.PolicyHash != policyAdditionHash(*state) || len(expected) != len(doc.Steps) {
			return ErrBootRetirement
		}
		for index, step := range doc.Steps {
			if !reflect.DeepEqual(step.Add, expected[index].Add) || !reflect.DeepEqual(step.Delete, expected[index].Delete) || step.Tool != "" || len(step.Needs) != 0 || !validPolicyAdditionStepState(step.State) {
				return ErrBootRetirement
			}
		}
	}
	if removedOnly && !proxyInactiveRemovedDocument(doc) {
		return ErrBootRetirement
	}
	return nil
}

func verifyBootRetirementFiles(root *os.Root, archive string, manifest bootRetirementManifest, allowArchived bool) error {
	for name, expected := range manifest.Files {
		source, sourceErr := bootRetirementRead(root, name)
		archived, archiveErr := bootRetirementRead(root, filepath.Join(archive, "files", name))
		if sourceErr == nil && bytes.Equal(source, expected) && errors.Is(archiveErr, os.ErrNotExist) {
			continue
		}
		if allowArchived && errors.Is(sourceErr, os.ErrNotExist) && archiveErr == nil && bytes.Equal(archived, expected) {
			continue
		}
		if allowArchived && sourceErr == nil && archiveErr == nil && bytes.Equal(source, expected) && bytes.Equal(archived, expected) {
			left, leftErr := root.Lstat(name)
			right, rightErr := root.Lstat(filepath.Join(archive, "files", name))
			if leftErr == nil && rightErr == nil && os.SameFile(left, right) {
				continue
			}
		}
		return ErrBootRetirement
	}
	return nil
}

func writeBootRetirementManifest(root *os.Root, statePath, archive string, manifest bootRetirementManifest) error {
	if err := mkdirBootRetirement(root, archive); err != nil {
		return err
	}
	manifest.Checksum = bootRetirementChecksum(manifest)
	raw, _ := json.Marshal(manifest)
	if len(raw) > bootRetirementLimit {
		return ErrBootRetirement
	}
	if err := writeBootRetirementAtomic(root, filepath.Join(archive, "manifest.json"), raw); err != nil {
		return err
	}
	for _, directory := range []string{archive, filepath.Dir(archive), "."} {
		if err := syncBootRetirementDirectory(root, directory); err != nil {
			return err
		}
	}
	return nil
}

func moveBootRetirementFiles(root *os.Root, statePath, archive string, manifest bootRetirementManifest, fault func(string) error, currentOwner func() error) error {
	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	slices.Sort(names)
	directories := map[string]bool{}
	for _, name := range names {
		if err := currentOwner(); err != nil {
			return err
		}
		if strings.HasPrefix(name, filepath.Join("sing-box", "policy-generations")+string(filepath.Separator)) {
			directories[filepath.Dir(name)] = true
		}
		if err := verifyBootRetirementFiles(root, archive, manifest, true); err != nil {
			return err
		}
		destination := filepath.Join(archive, "files", name)
		if _, err := bootRetirementRead(root, destination); err == nil {
			// A destination-first durable rename can leave the same original
			// inode visible at both names after a power cut. Remove only that
			// redundant link; different copies retain the fence above.
			if _, sourceErr := root.Lstat(name); sourceErr == nil {
				if err := currentOwner(); err != nil {
					return err
				}
				if err := root.Remove(name); err != nil {
					return err
				}
				if err := syncBootRetirementDirectory(root, filepath.Dir(name)); err != nil {
					return err
				}
			} else if !errors.Is(sourceErr, os.ErrNotExist) {
				return sourceErr
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := mkdirBootRetirement(root, filepath.Dir(destination)); err != nil {
			return err
		}
		if err := currentOwner(); err != nil {
			return err
		}
		if err := root.Rename(name, destination); err != nil {
			return err
		}
		if fault != nil {
			if err := fault("after-rename:" + name); err != nil {
				return err
			}
		}
		if err := currentOwner(); err != nil {
			return err
		}
		for _, directory := range []string{filepath.Dir(destination), filepath.Dir(name)} {
			if err := syncBootRetirementDirectory(root, directory); err != nil {
				return err
			}
		}
		if fault != nil {
			if err := fault(name); err != nil {
				return err
			}
		}
	}
	// Only empty, enumerated generation directories are removed. Unknown new
	// files retain the fence and are never recursively removed.
	for directory := range directories {
		if err := currentOwner(); err != nil {
			return err
		}
		if err := root.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, directory := range []string{filepath.Join("sing-box", "policy-generations"), "sing-box"} {
		if err := syncBootRetirementDirectory(root, directory); err != nil {
			return err
		}
	}
	return verifyBootRetirementFiles(root, archive, manifest, true)
}

func mkdirBootRetirement(root *os.Root, name string) error {
	if !filepath.IsLocal(name) || filepath.Clean(name) == "." {
		return ErrBootRetirement
	}
	part := ""
	for _, component := range strings.Split(filepath.Clean(name), string(filepath.Separator)) {
		part = filepath.Join(part, component)
		if err := root.Mkdir(part, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := root.Lstat(part)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrBootRetirement
		}
		// Make every new ancestor durable before any original file moves into
		// the subtree, not just its eventual deepest destination directory.
		if err := syncBootRetirementDirectory(root, part); err != nil {
			return err
		}
		if err := syncBootRetirementDirectory(root, filepath.Dir(part)); err != nil {
			return err
		}
	}
	return nil
}

func syncBootRetirementDirectory(root *os.Root, name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func lockBootRetirementReceipts(root *os.Root, archive string, manifest bootRetirementManifest) (func(), error) {
	var files []*os.File
	unlock := func() {
		for _, file := range files {
			unlockCloudflareScanFile(file)
			file.Close()
		}
	}
	var names []string
	if manifest.Schema == 1 {
		names = append(names, filepath.Join("transactions", manifest.PlanID, "sing-box", policyAdditionLock))
	}
	for name := range manifest.Files {
		if filepath.Base(name) == policyAdditionLock {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		path := name
		if _, err := bootRetirementRead(root, path); errors.Is(err, os.ErrNotExist) {
			path = filepath.Join(archive, "files", name)
		} else if err != nil {
			unlock()
			return nil, err
		}
		file, err := root.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			unlock()
			return nil, err
		}
		info, err := file.Stat()
		marker, readErr := io.ReadAll(io.LimitReader(file, int64(len(policyAdditionMarker)+1)))
		// The exported operation is Linux-only. Portable fixture execution does
		// not take Windows byte-range locks, which also block its own readback.
		lockErr := error(nil)
		if runtime.GOOS == "linux" {
			lockErr = lockCloudflareScanFile(file)
		}
		if err != nil || !validCloudflareScanLockFile(info) || readErr != nil || string(marker) != policyAdditionMarker || lockErr != nil {
			file.Close()
			unlock()
			return nil, ErrBootRetirement
		}
		files = append(files, file)
		current, err := root.Lstat(path)
		if err != nil || !os.SameFile(info, current) {
			unlock()
			return nil, ErrBootRetirement
		}
	}
	return unlock, nil
}

func verifyBootRetirementEvidence(root *os.Root, manifest bootRetirementManifest) error {
	for name, expected := range manifest.Evidence {
		if filepath.Base(name) == "execution.json" || name == "latest-execution.json" || name == "latest-plan.json" {
			continue
		}
		actual, err := bootRetirementRead(root, name)
		if err != nil || !bytes.Equal(actual, expected) {
			return ErrBootRetirement
		}
	}
	return nil
}

func bootRetirementStepPublished(root *os.Root, transactionRoot, phase string, after time.Time) error {
	var latest, transaction Execution
	left, err := bootRetirementRead(root, "latest-execution.json")
	if err != nil {
		return err
	}
	right, err := bootRetirementRead(root, filepath.Join("transactions", filepath.Base(transactionRoot), "execution.json"))
	if err != nil {
		return err
	}
	if !bytes.Equal(left, right) || json.Unmarshal(left, &latest) != nil || json.Unmarshal(right, &transaction) != nil || len(latest.Steps) == 0 {
		return ErrBootRetirement
	}
	step := latest.Steps[len(latest.Steps)-1]
	started, err := time.Parse(time.RFC3339Nano, step.StartedAt)
	if err != nil || step.Phase != phase || step.State != "running" || started.Before(after) {
		return ErrBootRetirement
	}
	return nil
}
