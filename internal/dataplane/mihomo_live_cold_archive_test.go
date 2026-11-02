package dataplane

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMihomoLiveColdArchiveBoundsKnownFilesAndDirectoryInventory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("actual inode/uid/nlink inventory requires Linux")
	}
	base := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	a := &ProxyTunnelAdapter{EngineID: "mihomo", StateRoot: filepath.Join(base, "mihomo"), Interface: "rz-mihomo", Table: 207, Priority: 31200, SOCKSPort: 18083, SidecarKind: "hev"}
	if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	d := mihomoLiveDefinitionFixture(t)
	data := []byte("private compiled profile")
	d.Profile.ConfigSHA256 = nodeDefaultSourceMaterialHash(data)
	if err := os.WriteFile(a.engineConfigPath(), data, 0600); err != nil {
		t.Fatal(err)
	}
	generation := "123456789abcdef0123456789abcdef01"
	if err := os.MkdirAll(filepath.Join(a.StateRoot, "policy-generations", generation), 0700); err != nil {
		t.Fatal(err)
	}
	view, err := readMihomoColdRuntime(root, "mihomo", a)
	if err != nil || !view.Present || len(view.Files) != 1 || len(view.Directories) != 3 {
		t.Fatal(view, err)
	}
	if err := validateMihomoColdRuntime(a, d, view); err != nil {
		t.Fatal(err)
	}
	view.Files["unknown"] = []byte("foreign")
	if validateMihomoColdRuntime(a, d, view) == nil {
		t.Fatal("unknown archive member accepted")
	}
	delete(view.Files, "unknown")
	view.Files[mihomoColdRelative(a, a.engineConfigPath())] = []byte("changed")
	if validateMihomoColdRuntime(a, d, view) == nil {
		t.Fatal("changed compiled image accepted")
	}
	if err := os.WriteFile(filepath.Join(a.StateRoot, "foreign"), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMihomoColdRuntime(root, "mihomo", a); err == nil {
		t.Fatal("unknown native member accepted")
	}
}

func TestMihomoLiveColdArchiveRefusesAggregateOversize(t *testing.T) {
	a := &ProxyTunnelAdapter{EngineID: "mihomo", StateRoot: filepath.Join(t.TempDir(), "mihomo"), SidecarKind: "hev"}
	r := mihomoColdRuntimeArchive{Present: true, Identity: "test", Files: map[string][]byte{mihomoColdRelative(a, a.engineProcess().LogPath): make([]byte, 9<<20), mihomoColdRelative(a, a.sidecarProcess().LogPath): make([]byte, 9<<20)}}
	if validateMihomoColdRuntime(a, mihomoLiveDefinitionFixture(t), r) == nil {
		t.Fatal("aggregate bound bypassed")
	}
}
