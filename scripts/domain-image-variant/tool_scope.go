package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const toolTarget = "internal/dataplane/domain_tcp_tool_observation.go"
const toolBaselineFile = "scripts/domain-image-variant/testdata/tool-scope-before.txt"
const toolBaselineRevision = "cb700a4caaa3f027919cc3653e7aae549e682afa"
const toolBaselineSHA = "3f45ce09354cb720de545cdd51bbdc1daa5af234e358b9c00baf5cdac319e375"

// Updated only after independent review of the exact complete candidate file.
const toolCandidateSHA = "f9a3c60ad5c79ace93ae437d1152461499751e5a5b95cf3e5708d5e25f49b87a"

// Both archives come from the same candidate. Only the reviewed original tool
// comparison file is restored in baseline. No image, harness or budget toggle.
func prepareTool(candidate, baseline, output, revision string) error {
	if len(revision) != 40 || revision != strings.ToLower(revision) {
		return errors.New("exact revision required")
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return err
	}
	candidate, err := confinedRoot(candidate)
	if err != nil {
		return err
	}
	baseline, err = confinedRoot(baseline)
	if err != nil {
		return err
	}
	if overlaps(candidate, baseline) {
		return errors.New("overlapping source roots")
	}
	output, err = evidenceRoot(output, candidate, baseline)
	if err != nil {
		return err
	}
	a, err := tree(candidate)
	if err != nil {
		return err
	}
	b, err := tree(baseline)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a, b) {
		return errors.New("initial complete source manifests differ")
	}
	if a[toolTarget].SHA256 != toolCandidateSHA || a[toolBaselineFile].SHA256 != toolBaselineSHA {
		return errors.New("reviewed tool comparison source drift")
	}
	before, err := os.ReadFile(filepath.Join(candidate, filepath.FromSlash(toolBaselineFile)))
	if err != nil {
		return err
	}
	if hash(before) != toolBaselineSHA {
		return errors.New("baseline changed while reading")
	}
	after, err := os.ReadFile(filepath.Join(candidate, filepath.FromSlash(toolTarget)))
	if err != nil || hash(after) != toolCandidateSHA {
		return errors.New("candidate changed while reading")
	}
	helpers := map[string]string{}
	for _, name := range []string{"scripts/domain-image-variant/main.go", "scripts/domain-image-variant/tool_scope.go"} {
		if a[name].SHA256 == "" {
			return errors.New("helper provenance missing")
		}
		helpers[name] = a[name].SHA256
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(baseline, filepath.FromSlash(toolTarget)), before, 0600); err != nil {
		return err
	}
	afterA, err := tree(candidate)
	if err != nil {
		return err
	}
	afterB, err := tree(baseline)
	if err != nil {
		return err
	}
	want := make(manifest, len(a))
	for p, row := range a {
		want[p] = row
	}
	row := want[toolTarget]
	row.Bytes, row.SHA256 = int64(len(before)), toolBaselineSHA
	want[toolTarget] = row
	if !reflect.DeepEqual(a, afterA) || !reflect.DeepEqual(want, afterB) {
		return errors.New("complete tree parity refused after tool comparison patch")
	}
	report := map[string]any{"schema": 1, "source_commit": revision, "comparison": "baseline-tools", "baseline": "same-current-source-original-tool-comparison", "candidate": "same-current-source-bounded-tool-comparison", "changed_path": toolTarget, "baseline_file_revision": toolBaselineRevision, "baseline_file_sha256": toolBaselineSHA, "candidate_file_sha256": toolCandidateSHA, "whole_tree_parity": true, "limits": []string{"One reviewed complete production file differs; all other files and modes identical", "Executable image feature remains enabled on both sides", "Original deadlines, native harness, actual IP version children and cleanup unchanged", "This synthetic source pair is not a historical whole-commit comparison"}}
	report["helpers_sha256"] = helpers
	report["replay_sources"] = map[string]string{"before.go.txt": toolBaselineSHA, "after.go.txt": toolCandidateSHA}
	report["baseline_build_scope"] = "Original app.test native harness imports production dataplane; candidate-only dataplane _test.go files are not compiled in the synthetic baseline"
	for name, data := range map[string][]byte{"before.go.txt": before, "after.go.txt": after} {
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			return err
		}
	}
	for name, value := range map[string]any{"candidate-source.json": afterA, "baseline-source.json": afterB, "variant.json": report} {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(output, name), append(data, '\n'), 0600); err != nil {
			return err
		}
	}
	return nil
}
