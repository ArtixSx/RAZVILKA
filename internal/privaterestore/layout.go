// Package privaterestore coordinates journaled online draft import and offline
// boot recovery before Store caches/API/workers start. It never activates routes.
package privaterestore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Layout is trusted deployment configuration, never part of an imported archive.
// Journal must be stable across launches, including when there is no pending plan.
type Layout struct {
	Config         string
	CustomServices string
	Devices        string
	StageRoot      string
	ProviderRoot   string
	NodeRoot       string // Optional; omitted deployments retain the v1 journal binding.
	JournalRoot    string
}

func (Layout) String() string   { return "[private restore layout]" }
func (Layout) GoString() string { return "[private restore layout]" }

func canonical(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
}
func inside(path, root string) bool {
	rel, err := filepath.Rel(canonical(root), canonical(path))
	return err == nil && (rel == "." || filepath.IsLocal(rel))
}
func normalizeLayout(in Layout) (Layout, string, error) {
	out := in
	for _, p := range []*string{&out.Config, &out.CustomServices, &out.Devices, &out.StageRoot, &out.ProviderRoot, &out.JournalRoot} {
		if strings.TrimSpace(*p) == "" {
			return Layout{}, "", restorejournal.ErrInvalid
		}
		abs, err := filepath.Abs(*p)
		if err != nil || abs == filepath.VolumeName(abs)+string(filepath.Separator) {
			return Layout{}, "", restorejournal.ErrInvalid
		}
		*p = abs
	}
	if out.NodeRoot != "" {
		abs, err := filepath.Abs(out.NodeRoot)
		if err != nil || strings.TrimSpace(out.NodeRoot) == "" || abs == filepath.VolumeName(abs)+string(filepath.Separator) {
			return Layout{}, "", restorejournal.ErrInvalid
		}
		out.NodeRoot = abs
	}
	files := []string{out.Config, out.CustomServices, out.Devices}
	dirs := []string{out.StageRoot, out.ProviderRoot, out.JournalRoot}
	if out.NodeRoot != "" {
		dirs = append(dirs, out.NodeRoot)
	}
	for i, file := range files {
		for _, other := range files[i+1:] {
			if inside(file, other) || inside(other, file) {
				return Layout{}, "", restorejournal.ErrInvalid
			}
		}
		for _, dir := range dirs {
			if inside(file, dir) || inside(dir, file) {
				return Layout{}, "", restorejournal.ErrInvalid
			}
		}
	}
	for i, dir := range dirs {
		for _, other := range dirs[i+1:] {
			if inside(dir, other) || inside(other, dir) {
				return Layout{}, "", restorejournal.ErrInvalid
			}
		}
	}
	// Include the trusted complete slot set and versioned typed adapter contract.
	// No destinations or binding values are taken from the journal/payload.
	bindings := []string{"private-draft-coordinator-v1", canonical(out.Config), canonical(out.CustomServices), canonical(out.Devices), canonical(out.StageRoot), canonical(out.ProviderRoot), canonical(out.JournalRoot)}
	if out.NodeRoot != "" {
		bindings = append(bindings, "nodestore-schema-1", canonical(out.NodeRoot))
	}
	for _, spec := range engineconfig.Specs() {
		for _, file := range spec.Files {
			bindings = append(bindings, draftID(spec.ID, file.ID))
		}
	}
	data, _ := json.Marshal(bindings)
	hash := sha256.Sum256(data)
	return out, hex.EncodeToString(hash[:]), nil
}

func draftID(engineID, fileID string) string { return "draft_" + engineID + "_" + fileID }
