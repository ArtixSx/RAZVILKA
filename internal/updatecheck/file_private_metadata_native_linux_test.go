//go:build linux

package updatecheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePrivateMetadataDescriptorAndModes(t *testing.T) {
	a := &SelfUpdateFileAdapter{owned: func(string) error { return nil }} // own TempDir only
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "secret")
	if err := a.verifyPrivateFileMetadata(ctx, path, false); err != nil {
		t.Fatal("prior absence", err)
	}
	if err := os.WriteFile(path, []byte("fixed private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0600, 0644, 0640, 0400, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		err := a.verifyPrivateFileMetadata(ctx, path, true)
		if (mode == 0600) != (err == nil) {
			t.Fatal("private mode proof", mode, err)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyPrivateFileMetadata(ctx, path, false); err == nil {
		t.Fatal("presence accepted as prior absence")
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyPrivateFileMetadata(ctx, link, true); err == nil {
		t.Fatal("symlink accepted")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if err := a.verifyPrivateFileMetadata(ctx, path, true); err == nil {
			t.Fatal("foreign descriptor UID accepted")
		}
	}
}
