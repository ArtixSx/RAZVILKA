//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/sys/unix"
)

// Actual public producer and consumer; only the Ubuntu platform classification
// is tagged. The package contains the actual built candidate and source files;
// no helper/receipt/Stop/retention image is fabricated by the test.
func TestNativeConfiguredOld193PairLifecycle(t *testing.T) {
	if os.Getenv("RAZVILKA_PAIRED_NATIVE_SCOPE") != "1" {
		t.Skip("disposable configured-old193 public CLI fixture not requested")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated root owner required")
	}
	for i, namespace := range []string{"net", "mnt", "pid"} {
		var outer, current syscall.Stat_t
		kind, err := unix.IoctlRetInt(3+i, unix.NS_GET_NSTYPE)
		want := []int{unix.CLONE_NEWNET, unix.CLONE_NEWNS, unix.CLONE_NEWPID}[i]
		if err != nil || kind != want || syscall.Fstat(3+i, &outer) != nil || syscall.Stat("/proc/self/ns/"+namespace, &current) != nil || outer.Dev == current.Dev && outer.Ino == current.Ino {
			t.Fatal("original outer namespace is not distinct", namespace)
		}
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	privateOpt := false
	for _, line := range strings.Split(strings.TrimSpace(string(mounts)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			t.Fatal("invalid actual mount inventory")
		}
		for _, field := range fields[6:] {
			if field == "-" {
				break
			}
			if strings.HasPrefix(field, "shared:") || strings.HasPrefix(field, "master:") || strings.HasPrefix(field, "propagate_from:") {
				t.Fatal("mount propagation is not private")
			}
		}
		if fields[4] == "/opt" && strings.Contains(line, " - tmpfs ") {
			privateOpt = true
		}
	}
	if !privateOpt {
		t.Fatal("fixed /opt is not a disposable tmpfs mount")
	}
	id := os.Getenv("RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ID")
	if id == "" || os.Getenv("RAZVILKA_NATIVE_PAIRED_RESTORE_ID") != id {
		t.Fatal("producer/consumer transaction mismatch")
	}
	oldSHA := nativePairedRestoreFileHash(t, "/opt/bin/razvilka")
	if expected := os.Getenv("RAZVILKA_PAIRED_NATIVE_SOURCE_SHA"); expected == "" || expected != oldSHA {
		t.Fatal("actual configured old source does not match built old tag")
	}
	initSHA := nativePairedRestoreFileHash(t, installpath.Config+"/source-init-0193")
	if expected := os.Getenv("RAZVILKA_PAIRED_NATIVE_INIT_SHA"); expected == "" || expected != initSHA {
		t.Fatal("configured source changed the actual old init script")
	}
	t.Logf("configured_old193_layout=true source_commit=817783493f0c2784ccc70aa73868cd64e9437634 source_sha256=%s source_init_sha256=%s tagged_platform_classification=true baseline_offline_pair=true", oldSHA, initSHA)
	if !t.Run("actual-bootstrap", TestNativeExternalBootstrapPublicExecutableProducer) {
		return
	}
	// Bootstrap has returned only after its actual original command joins. A
	// fresh real owner publishes Stop through the production operation gate.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var gate operationgate.Gate
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Inspect(installpath.Config + "/config.json")
	if err != nil || !cfg.SafeMode || !cfg.ServiceControl.Stopped {
		release()
		t.Fatal("bootstrap did not retain offline source intent", err)
	}
	stop, err := operationgate.RequestSelfUpdateStop(held, installpath.State+"/self-update-stop", id, cfg.Revision)
	release()
	if err != nil || !stop.Stopped || stop.TransactionID != id || stop.ConfigRevision != cfg.Revision {
		t.Fatal("actual current owner did not publish matching durable Stop", err)
	}
	if !t.Run("actual-paired-restore", TestNativePairedRestorePublicExecutableCaller) {
		return
	}
	t.Log("actual_configured_old193_public_pair complete=true source_restored_offline=true original_stop_retained=true guards_preserved=true tagged_platform_classification=true")
}
