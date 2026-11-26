package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func mihomoColdCompletion(raw []byte) []byte {
	data, _ := json.Marshal(struct {
		Schema         int    `json:"schema"`
		ManifestSHA256 string `json:"manifest_sha256"`
	}{1, nodeDefaultSourceMaterialHash(raw)})
	return data
}

// Documentary recognition only. It prevents replay of the retired committed
// plan, never grants native absence or a new Apply. A genuine later commit
// supersedes its exact old committed bytes; previews cannot supersede it.
func (m *Manager) completedMihomoLiveRetirement() (retired bool, retiredID string, resultErr error) {
	refuse := func() (bool, string, error) { return true, "", ErrMihomoLiveRetirement }
	if _, err := os.Lstat(filepath.Join(m.StateRoot, "mihomo-live-retirements")); errors.Is(err, os.ErrNotExist) {
		return false, "", nil
	} else if err != nil {
		return refuse()
	}
	root, err := openBootRetirementRoot(m.StateRoot)
	if err != nil {
		return refuse()
	}
	defer func() {
		if err := root.Close(); err != nil {
			retired, retiredID = true, ""
			resultErr = errors.Join(ErrMihomoLiveRetirement, resultErr, err)
		}
	}()
	dir, err := root.Open("mihomo-live-retirements")
	if err != nil {
		return refuse()
	}
	entries, readErr := dir.ReadDir(129)
	closeErr := dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 128 {
		return refuse()
	}
	committed, committedErr := readMihomoColdFile(root, "latest-committed-plan.json")
	if committedErr != nil && !errors.Is(committedErr, os.ErrNotExist) {
		return refuse()
	}
	matched, id := false, ""
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !validPlanID(entry.Name()) {
			return refuse()
		}
		archiveName := filepath.Join("mihomo-live-retirements", entry.Name())
		raw, err := readMihomoColdFile(root, filepath.Join(archiveName, "retirement.json"))
		if err != nil {
			return refuse()
		}
		var manifest mihomoColdManifest
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if nfqws2ManagedUniqueJSON(raw) != nil || decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Schema != 1 || manifest.Observed.Validate() != nil {
			return refuse()
		}
		before, d, err := decodeMihomoLiveRetirementIntent(manifest.Before)
		if err != nil || before.PlanID != entry.Name() || manifest.Observed.BootID == d.NetworkIdentity.BootID || validateMihomoColdPlans(d.Plan, manifest.Plans) != nil {
			return refuse()
		}
		if (d.NativeHome == nil) != (manifest.Home == nil) || manifest.Home != nil && validateMihomoColdHomeArchive(d, *manifest.Home) != nil {
			return refuse()
		}
		old, hadCommitted := manifest.Plans["latest-committed-plan.json"]
		if hadCommitted != (committedErr == nil) || !bytes.Equal(old, committed) {
			continue
		}
		var after Execution
		if json.Unmarshal(manifest.After, &after) != nil {
			return refuse()
		}
		expected, err := mihomoLiveRetirementTerminal(before, after.FinishedAt)
		if err != nil {
			return refuse()
		}
		afterRaw, _ := json.Marshal(expected)
		if !bytes.Equal(afterRaw, manifest.After) {
			return refuse()
		}
		transaction, err := readMihomoColdFile(root, filepath.Join("transactions", entry.Name(), "execution.json"))
		if err != nil || !bytes.Equal(transaction, manifest.After) {
			return refuse()
		}
		complete, err := readMihomoColdFile(root, filepath.Join(archiveName, "completed.json"))
		if err != nil || !bytes.Equal(complete, mihomoColdCompletion(raw)) {
			return refuse()
		}
		a := &ProxyTunnelAdapter{EngineID: "mihomo", StateRoot: filepath.Join(m.StateRoot, "mihomo"), SidecarKind: d.Sidecar.Kind}
		if validateMihomoColdRuntime(a, d, manifest.Runtime) != nil {
			return refuse()
		}
		archived, err := readMihomoColdRuntime(root, filepath.Join(archiveName, "runtime"), a)
		if err != nil {
			return refuse()
		}
		left, e1 := json.Marshal(archived)
		right, e2 := json.Marshal(manifest.Runtime)
		if e1 != nil || e2 != nil || !bytes.Equal(left, right) {
			return refuse()
		}
		// Re-read the immutable manifest after the archive and transaction scan.
		closing, err := readMihomoColdFile(root, filepath.Join(archiveName, "retirement.json"))
		if err != nil || !bytes.Equal(raw, closing) {
			return refuse()
		}
		matched, id = true, entry.Name()
	}
	return matched, id, nil
}
