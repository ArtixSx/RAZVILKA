package updatecheck

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// RunInstallerHelper requires the CORE-owned file protocol callback. Legacy
// shell apply cannot bypass the file/helper journals when wiring is absent.
func RunInstallerHelper(id string) int { return RunInstallerHelperWithFileProtocol(id, nil) }

// Main supplies its reviewed SelfUpdateFiles.RunHelper closure, including
// current config CAS/Stop/SafeMode guards. This function owns handoff identity
// and helper receipt only; it never performs a second installation workflow.
func RunInstallerHelperWithFileProtocol(id string, run func(context.Context, string) error, stop ...SelfUpdateStopCheck) int {
	return runInstallerHelperWithAdapter(id, run, NewSelfUpdateFileAdapter(stop...))
}

func RunInstallerHelperWithAuthority(id string, run func(context.Context, string) error, stop SelfUpdateStopCheck, admission SelfUpdateEffectAdmission, runtime ...SelfUpdateRuntimeObservation) int {
	return runInstallerHelperWithAdapter(id, run, NewSelfUpdateFileAdapterWithAuthority(stop, admission, runtime...))
}

func runInstallerHelperWithAdapter(id string, run func(context.Context, string) error, a *SelfUpdateFileAdapter) int {
	if run == nil || !jobIDPattern.MatchString(id) || checkRootOwnedPath(productionUpdateRoot) != nil {
		return 2
	}
	if a.admission == nil || a.runtimeInactive == nil {
		return 2
	}
	var record updateRecord
	for attempt := 0; attempt < 100; attempt++ {
		var err error
		record, err = readAdapterRecord(productionUpdateRoot, id)
		if err != nil || record.Job.State != "installing" || record.Job.ReviewToken != "" || record.ParentPID <= 1 {
			return 2
		}
		if record.Job.HelperPID == os.Getpid() {
			break
		}
		if attempt == 99 {
			return 2
		}
		time.Sleep(100 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	_, review, err := a.load(ctx, id)
	if err != nil || a.Authority(ctx, id, review.Revision) != nil || checkProductionPID(record.ParentPID, record.Deployment.Executable) != nil {
		return 2
	}
	if err := sealFileHelperIdentity(a, id, review); err != nil {
		return 2
	}
	root, err := ownedfs.Open(productionUpdateRoot)
	if err != nil {
		return 2
	}
	defer root.Close()
	record.Job.State = "restarting"
	record.Job.Stage = "file-protocol"
	record.Job.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(record)
	if err != nil || writeSelfUpdateRecord(root, data) != nil {
		return 3
	}
	err = run(ctx, id)
	fresh, readErr := readAdapterRecord(productionUpdateRoot, id)
	if readErr != nil {
		return 3
	}
	stopErr := a.checkStop(ctx, id, "start/live")
	if fresh.Job.State == "completed" && stopErr == nil {
		if err == nil {
			return 0
		}
		return 3
	}
	if fresh.Job.State == "rolled-back" && stopErr == nil {
		return 3
	}
	// Preserve this distinct data-only outcome; it can never report live
	// success, and its retained file receipt must independently verify.
	if fresh.Job.State == stoppedRollbackState && a.Inspect(ctx, id) == nil {
		return 3
	}
	fresh.Job.State = "requires-review"
	fresh.Job.Stage = "file-protocol"
	fresh.Job.Code = "file-protocol-needs-review"
	fresh.Job.CanApply = false
	fresh.Job.CanCancel = false
	fresh.Job.UpdatedAt = time.Now().UTC()
	data, _ = json.Marshal(fresh)
	_ = writeSelfUpdateRecord(root, data)
	return 3
}

type limitedLog struct {
	mu        sync.Mutex
	writer    io.Writer
	remaining int64
}

func (l *limitedLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := len(data)
	if l.remaining > 0 {
		n := min(int64(size), l.remaining)
		if _, err := l.writer.Write(data[:n]); err != nil {
			return 0, err
		}
		l.remaining -= n
	}
	return size, nil
}

func confirmInstalledHealth(expectedVersion string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	version := exec.CommandContext(ctx, "/opt/bin/razvilka", "-version")
	configureBoundedCommand(version)
	version.Env = commandEnvironment()
	out := &cappedOutput{maximum: 1024}
	version.Stdout = out
	version.Stderr = io.Discard
	if runBoundedCommand(version) != nil || strings.TrimSpace(out.String()) != expectedVersion {
		return false
	}
	pid := exec.CommandContext(ctx, "/bin/sh", "/opt/etc/init.d/S99razvilka", "pid")
	configureBoundedCommand(pid)
	pid.Env = commandEnvironment()
	out = &cappedOutput{maximum: 128}
	pid.Stdout = out
	pid.Stderr = io.Discard
	if runBoundedCommand(pid) != nil {
		return false
	}
	id := strings.TrimSpace(out.String())
	if id == "" || strings.Trim(id, "0123456789") != "" {
		return false
	}
	lan := exec.CommandContext(ctx, "/bin/sh", "/opt/etc/init.d/S99razvilka", "lan-ip")
	configureBoundedCommand(lan)
	lan.Env = commandEnvironment()
	out = &cappedOutput{maximum: 128}
	lan.Stdout = out
	lan.Stderr = io.Discard
	if runBoundedCommand(lan) != nil {
		return false
	}
	address := strings.TrimSpace(out.String())
	if ip, err := netip.ParseAddr(address); err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	health := exec.CommandContext(ctx, "/opt/bin/razvilka", "-healthcheck", "http://"+address+":8787/api/v1/status", "-healthcheck-pid", id, "-healthcheck-require-dataplane")
	configureBoundedCommand(health)
	health.Env = commandEnvironment()
	health.Stdout = io.Discard
	health.Stderr = io.Discard
	return runBoundedCommand(health) == nil
}

func helperConfigMatches(record updateRecord) bool {
	path := record.Deployment.Paths["config"]
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return false
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(path), 4<<20)
	var cfg config.Config
	return err == nil && json.Unmarshal(data, &cfg) == nil && ConfigFingerprint(cfg) == record.ConfigFingerprint && cfg.Revision == record.Job.ConfigRevision
}
