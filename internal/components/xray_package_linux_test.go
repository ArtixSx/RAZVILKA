//go:build linux

package components

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestXrayReaderRejectsUnsafeHistoryObjects(t *testing.T) {
	for _, variant := range []string{"world-writable", "hard-link", "fifo", "foreign-owner", "foreign-directory"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "update-journal")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, xrayCoreMarkerFile)
			if err := os.WriteFile(marker, []byte(xrayCoreMarker), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch variant {
			case "world-writable":
				err = os.Chmod(marker, 0666)
			case "hard-link":
				err = os.Link(marker, filepath.Join(root, "elsewhere"))
			case "fifo":
				if err = os.Remove(marker); err == nil {
					err = syscall.Mkfifo(marker, 0600)
				}
			case "foreign-owner", "foreign-directory":
				if os.Geteuid() != 0 {
					t.Skip("changing file owner requires root")
				}
				target := marker
				if variant == "foreign-directory" {
					target = dir
				}
				err = os.Chown(target, 65534, -1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), root); err == nil {
				t.Fatal("unsafe history accepted")
			}
		})
	}
}

func TestXrayUnsafeReceiptDirectoryPrecedesDependencyInstall(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "receipts")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{output: map[string]string{"install": "ok", "list-installed": ""}}
	m := &Manager{Opkg: "opkg", Runner: r, RepoDir: t.TempDir(), InitDir: t.TempDir(), StateDir: root, AdmitXrayCoreWrite: admitTestXray}
	if _, err := m.Apply(context.Background(), "xray"); err == nil {
		t.Fatal("unsafe hierarchy accepted")
	}
	for _, call := range r.calls {
		if len(call) < 2 || call[1] != "list-installed" {
			t.Fatal("changed package before storage preflight", call)
		}
	}
}
