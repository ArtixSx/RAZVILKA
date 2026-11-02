package restorejournal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileTargetParentIdentityIsReadOnlyHeldComparison(t *testing.T) {
	dir := t.TempDir()
	expected, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	target, err := OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := target.ParentIdentity()
	if err != nil || !os.SameFile(expected, info) {
		t.Fatal("actual parent descriptor changed", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("identity initialized state", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ParentIdentity(); err == nil {
		t.Fatal("closed target retained identity")
	}
	var zero FileTarget
	if _, err := zero.ParentIdentity(); err == nil {
		t.Fatal("zero metadata reader accepted")
	}
}
