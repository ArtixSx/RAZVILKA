package engineconfig

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// NormalizeLegacyStagePermissions repairs only the allowlisted staging
// directories created by older RAZVILKA releases. Draft readers still reject
// links, unexpected file types and permissive files.
func NormalizeLegacyStagePermissions(stageRoot string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if strings.TrimSpace(stageRoot) == "" {
		return restorejournal.ErrInvalid
	}
	root, err := filepath.Abs(stageRoot)
	if err != nil || root == filepath.VolumeName(root)+string(filepath.Separator) {
		return restorejournal.ErrInvalid
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return restorejournal.ErrUnavailable
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return restorejournal.ErrUnavailable
	}
	for _, spec := range Specs() {
		path := filepath.Join(root, spec.ID)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return restorejournal.ErrUnavailable
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return restorejournal.ErrUnavailable
		}
	}
	return nil
}
