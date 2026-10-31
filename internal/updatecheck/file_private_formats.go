package updatecheck

import (
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"path/filepath"
)

// Shared bounded private image formats. These definitions perform validation
// only; they neither open a live Store nor restore any retained state.
var filePrivateDirectories = map[string]string{
	"nodes": "etc/razvilka/nodes-private", "feeds": "etc/razvilka/subscriptions-private", "cloudflare": "etc/razvilka/cloudflare-private",
	"engines": "razvilka/state/staging", "runtime": "razvilka/state/dataplane", "warp": "razvilka/state/warp", "dns": "razvilka/state/dns", "lkg": "razvilka/state/backups",
}
var filePrivateFiles = map[string]string{
	"token": "etc/razvilka/admin.token", "credentials": "etc/razvilka/admin.credentials.json", "custom": "etc/razvilka/custom-services.json", "devices": "etc/razvilka/devices.json", "source-state": "etc/razvilka/source-state.json", "autonomy": "etc/razvilka/config.json.automation.json.autonomy.json",
}

// Legacy registries are immutable: retained schema1/2 snapshots keep their
// exact key sets. Only schema3 carries the byte-exact StrategyLab pair image.
const StrategyLabReadVersion = 7
const PrivateSnapshotReadVersion = 3

func privateFilesForSchema(schema int) map[string]string {
	if schema != 3 {
		return filePrivateFiles
	}
	files := make(map[string]string, len(filePrivateFiles)+1)
	for name, path := range filePrivateFiles {
		files[name] = path
	}
	files["strategy"] = "razvilka/state/strategy-lab.json"
	return files
}

// Retained native/provider/runtime ledgers and LKG generations are not mutable
// application images. Keep the legacy registry above for reading old snapshots;
// newly produced snapshots and restore targets contain only this subset.
var fileMutablePrivateDirectories = map[string]string{
	"nodes": filePrivateDirectories["nodes"], "feeds": filePrivateDirectories["feeds"],
	"engines": filePrivateDirectories["engines"], "dns": filePrivateDirectories["dns"],
}

type directoryEntry struct {
	Name      string `json:"name"`
	Mode      uint32 `json:"mode"`
	Directory bool   `json:"directory,omitempty"`
	Data      []byte `json:"data,omitempty"`
}
type directoryImage struct {
	Mode    uint32           `json:"mode"`
	Entries []directoryEntry `json:"entries"`
}
type privateFileSnapshot struct {
	Schema int                             `json:"schema"`
	ID     string                          `json:"id"`
	Images map[string]restorejournal.Image `json:"images"`
}

func validateDirectoryImage(image restorejournal.Image) (directoryImage, error) {
	var tree directoryImage
	if !image.Exists {
		if len(image.Data) != 0 {
			return tree, ErrFileProtocol
		}
		return tree, nil
	}
	if len(image.Data) > restorejournal.MaxImageBytes || decodeFileProtocol(image.Data, &tree) != nil || tree.Mode > 0777 || len(tree.Entries) > 4096 {
		return tree, ErrFileProtocol
	}
	seen := map[string]bool{}
	dirs := map[string]bool{".": true}
	for _, entry := range tree.Entries {
		if !filepath.IsLocal(entry.Name) || filepath.Clean(entry.Name) == "." || filepath.Clean(entry.Name) != entry.Name || seen[entry.Name] || entry.Mode > 0777 || !dirs[filepath.Dir(entry.Name)] || entry.Directory && len(entry.Data) != 0 {
			return tree, ErrFileProtocol
		}
		seen[entry.Name] = true
		if entry.Directory {
			dirs[entry.Name] = true
		}
	}
	return tree, nil
}

func validatePrivateSnapshot(snapshot privateFileSnapshot) error {
	directories := filePrivateDirectories
	if snapshot.Schema == 2 || snapshot.Schema == 3 {
		directories = fileMutablePrivateDirectories
	}
	files := privateFilesForSchema(snapshot.Schema)
	if (snapshot.Schema != 1 && snapshot.Schema != 2 && snapshot.Schema != 3) || !jobIDPattern.MatchString(snapshot.ID) || len(snapshot.Images) != len(directories)+len(files) {
		return ErrFileProtocol
	}
	total := 0
	for name, image := range snapshot.Images {
		if _, ok := directories[name]; ok {
			if _, err := validateDirectoryImage(image); err != nil {
				return err
			}
		} else if _, ok := files[name]; !ok {
			return ErrFileProtocol
		}
		if name == "strategy" {
			if _, err := ordinaryStrategyImage(image); err != nil {
				return err
			}
		}
		if len(image.Data) > restorejournal.MaxImageBytes || !image.Exists && len(image.Data) != 0 {
			return ErrFileProtocol
		}
		total += len(image.Data)
	}
	if total > restorejournal.MaxPlanBytes/2 {
		return ErrFileProtocol
	}
	return nil
}
