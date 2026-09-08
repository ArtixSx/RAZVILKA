//go:build linux

package updatecheck

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func checkRootOwnedPath(path string) error {
	return checkOwnedAncestors(path, "/")
}

func checkOwnedAncestors(path, boundary string) error {
	path, boundary = filepath.Clean(path), filepath.Clean(boundary)
	rel, err := filepath.Rel(boundary, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return errors.New("unsafe-owner-or-path")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if current == boundary {
				return errors.New("unsafe-owner-or-path")
			}
			continue
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe-owner-or-path")
		}
		if current == boundary {
			return nil
		}
	}
}

func checkProductionPID(expected int, executable string) error {
	data, err := os.ReadFile("/opt/var/run/razvilka.pid")
	if err != nil {
		return errors.New("production-pid-unavailable")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 || pid != expected {
		return errors.New("production-process-mismatch")
	}
	actual, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil || actual != executable {
		return errors.New("production-process-mismatch")
	}
	return nil
}

func helperAlive(pid int) bool {
	if pid <= 1 || syscall.Kill(pid, 0) != nil {
		return false
	}
	// kill(0) also succeeds for zombies and an unrelated reused PID. Only the
	// private helper command of our production executable owns this handoff.
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(data) > 4096 {
		return false
	}
	args := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	if len(args) != 3 || args[0] != "/opt/bin/razvilka" || args[1] != "self-update-helper" || !jobIDPattern.MatchString(args[2]) {
		return false
	}
	return true
}

func configureBoundedCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 2 * time.Second
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}

func cleanupCommand(command *exec.Cmd) {
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}

func checkUpdateSpace(directory string, archiveBytes int64) error {
	var stat unix.Statfs_t
	if unix.Statfs(directory, &stat) != nil {
		return errors.New("update-space-unavailable")
	}
	backupBytes := int64(0)
	entries := 0
	for _, directory := range []string{"/opt/etc/razvilka", "/opt/var/lib/razvilka/dataplane", "/opt/var/lib/razvilka/staging"} {
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			entries++
			if entries > 20000 || entry.Type()&os.ModeSymlink != 0 {
				return errors.New("backup-layout-refused")
			}
			if !entry.IsDir() {
				info, err := entry.Info()
				if err != nil {
					return err
				}
				backupBytes += info.Size()
				if backupBytes > 2<<30 {
					return errors.New("backup-size-refused")
				}
			}
			return nil
		})
		if err != nil {
			return errors.New("update-backup-space-unavailable")
		}
	}
	needed := uint64(archiveBytes + MaximumBinaryBytes*2 + backupBytes*2 + 32<<20)
	if uint64(stat.Bavail)*uint64(stat.Bsize) < needed {
		return errors.New("insufficient-update-space")
	}
	return nil
}

func launchInstallerHelper(id string) (int, error) {
	if !jobIDPattern.MatchString(id) {
		return 0, ErrReviewChanged
	}
	cmd := exec.Command("/opt/bin/razvilka", "self-update-helper", id)
	cmd.Env = commandEnvironment()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	// Reap preflight refusals while the original daemon remains alive. When
	// the daemon exits during an actual install, init inherits the helper.
	go func() { _ = cmd.Wait() }()
	return pid, nil
}

func runTransactionalInstaller(command *exec.Cmd, timeout time.Duration) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			cleanupCommand(command)
		}
		return err
	case <-timer.C:
	}
	// TERM the installer shell first: its trap owns transactional rollback.
	_ = command.Process.Signal(syscall.SIGTERM)
	grace := time.NewTimer(150 * time.Second)
	defer grace.Stop()
	select {
	case <-done:
	case <-grace.C:
		// A stuck rollback cannot hold the application indefinitely. Never
		// claim it restored the old version after this bounded cleanup.
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		<-done
	}
	return errInstallerTimeout
}
