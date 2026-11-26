//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the real production paths/layout/ownership scanner in a disposable
// chroot child. No production /opt, host controller, route or Stop is modified.
func TestNativeFailedMetadataHeaderProductionLayout(t *testing.T) {
	if root := os.Getenv("RAZVILKA_FAILED_METADATA_TEST_ROOT"); root != "" {
		if err := syscall.Chroot(root); err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir("/"); err != nil {
			t.Fatal(err)
		}
		dir := "/opt/razvilka/state/self-update"
		path := filepath.Join(dir, "current.json")
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var record updateRecord
		if err := json.Unmarshal(before, &record); err != nil {
			t.Fatal(err)
		}
		if err := checkDeploymentLayout(record.Deployment); err != nil {
			t.Fatal("real captured production layout refused", err)
		}
		required, err := RequiredSelfUpdateJournalReadVersion(context.Background(), "/opt", dir, "/opt/razvilka/state/self-update-files")
		if err != nil || required != 1 {
			t.Fatal("real effect-free metadata compatibility scanner refused", required, err)
		}
		if images, err := retainedControllerImages(context.Background(), "/opt", "/opt/razvilka/state"); err != nil || len(images) != 0 {
			t.Fatal("real node/controller inventory still fenced", images, err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("reader rewrote header", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 || entries[0].Name() != "current.json" {
			t.Fatal("reader created job/authority files", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("production ownership chroot fixture requires root")
	}
	root := t.TempDir()
	for _, path := range []string{"opt/bin", "opt/etc/init.d", "opt/sbin", "opt/razvilka/state/self-update", "opt/razvilka/run", "opt/etc/razvilka"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"opt/bin/razvilka", "opt/etc/init.d/S99razvilka", "opt/bin/busybox"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("root-owned executable image fixture"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/opt/bin/busybox", filepath.Join(root, "opt/sbin/start-stop-daemon")); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 29, 19, 47, 57, 0, time.UTC)
	record := updateRecord{Owner: updaterOwner, Job: Job{Channel: "preview", ID: strings.Repeat("a", 32), State: "failed", Stage: "metadata", Code: "release-url-refused", StartedAt: at, UpdatedAt: at.Add(time.Second), ConfigRevision: 11, Verification: "github-release-sha256"}, CurrentVersion: "0.20.0-rc.97", ConfigFingerprint: strings.Repeat("b", 64), ParentPID: 32619, Deployment: Deployment{Executable: "/opt/bin/razvilka", Port: "8787", Paths: ProductionPaths()}}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "opt/razvilka/state/self-update/current.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestNativeFailedMetadataHeaderProductionLayout$", "-test.count=1")
	command.Env = append(os.Environ(), "RAZVILKA_FAILED_METADATA_TEST_ROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal("production metadata child failed", err, string(output))
	}
}
