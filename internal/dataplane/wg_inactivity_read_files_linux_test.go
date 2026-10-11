//go:build linux

package dataplane

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWGInactivityReadLinuxOpenRefusesSymlinkAndDoesNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("comparison only"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if file, err := openWGInactivityObservationFile(alias); err == nil {
		file.Close()
		t.Fatal("followed replaced symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := openWGInactivityObservationFile(fifo)
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	closeErr := file.Close()
	if err != nil || closeErr != nil || info.Mode().IsRegular() {
		t.Fatal("FIFO could adopt regular-file incarnation", err, closeErr)
	}
}
