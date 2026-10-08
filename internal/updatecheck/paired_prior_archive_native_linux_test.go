//go:build linux

package updatecheck

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Real file descriptor, Unix permission and NOFOLLOW checks; the enclosing
// process/runtime observer is still a model, not native App acceptance.
func TestPairedPriorArchiveNativeUnsafeSourceAndPrivateOutput(t *testing.T) {
	for _, change := range []string{"symlink", "fifo", "writable", "oversized", "foreign-owner", "public-manifest", "public-payload"} {
		t.Run(change, func(t *testing.T) {
			f := pairedArchiveFixture(t, false)
			path := filepath.Join(f.installation, "etc/razvilka/nodes-private/known.private.json")
			switch change {
			case "symlink":
				outside := filepath.Join(filepath.Dir(f.installation), "outside-private")
				if err := os.WriteFile(outside, []byte("outside bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.Truncate(path, maximumPairedArchiveFileBytes+1); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				if os.Geteuid() != 0 {
					t.Skip("foreign UID fixture requires root")
				}
				if err := os.Chown(path, 65534, -1); err != nil {
					t.Fatal(err)
				}
			case "public-manifest", "public-payload":
				if _, err := f.capture(nil); err != nil {
					t.Fatal(err)
				}
				name := "manifest.json"
				if change == "public-payload" {
					name = "payload-00000000"
				}
				path = filepath.Join(f.installation, filepath.FromSlash(pairedPriorArchiveDirectory), pairedArchiveTestID, name)
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if digest, err := f.capture(nil); err == nil || digest != "" {
				t.Fatal("unsafe actual source/archive admitted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("refusal removed or repaired foreign/unsafe evidence", err)
			}
		})
	}
}
