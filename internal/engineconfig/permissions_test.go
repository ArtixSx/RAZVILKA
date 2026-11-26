package engineconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNormalizeLegacyStagePermissionsRepairsOnlyKnownDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics are verified on Linux")
	}
	root := filepath.Join(t.TempDir(), "staging")
	known := filepath.Join(root, "usque")
	unknown := filepath.Join(root, "third-party")
	for _, path := range []string{known, unknown} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := NormalizeLegacyStagePermissions(root); err != nil {
		t.Fatal(err)
	}
	assertMode := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s stat: %v", path, err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%v, want %v", path, info.Mode().Perm(), want)
		}
	}
	assertMode(root, 0o700)
	assertMode(known, 0o700)
	assertMode(unknown, 0o755)
}
