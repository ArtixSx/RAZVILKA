package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type ProcessSpec struct {
	ID         string
	Binary     string
	Args       []string
	Dir        string
	PIDPath    string
	LogPath    string
	MatchArg   string
	RouteProof bool
}

type ProcessController interface {
	Start(context.Context, ProcessSpec) error
	Stop(context.Context, ProcessSpec) error
	Running(ProcessSpec) bool
}

type OSProcessController struct{}

func (OSProcessController) Start(ctx context.Context, spec ProcessSpec) error {
	if err := validateProcessSpec(spec); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	controller := OSProcessController{}
	if controller.Running(spec) {
		return fmt.Errorf("managed process %s is already running", spec.ID)
	}
	if err := os.MkdirAll(spec.Dir, 0o700); err != nil {
		return err
	}
	owned, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return err
	}
	defer owned.Close()
	pidName, _ := filepath.Rel(spec.Dir, spec.PIDPath)
	logName, _ := filepath.Rel(spec.Dir, spec.LogPath)
	configName, _ := filepath.Rel(spec.Dir, spec.MatchArg)
	receiptName := pidName + routeidentity.ReceiptSuffix
	configHash := ""
	if spec.RouteProof {
		data, err := owned.ReadLimited(configName, 8<<20)
		if err != nil {
			return fmt.Errorf("read managed route config: %w", err)
		}
		configHash = routeidentity.Hash(data)
		_ = owned.Remove(receiptName)
	}
	_ = owned.Remove(pidName)
	for _, name := range []string{pidName, logName} {
		if parent := filepath.Dir(name); parent != "." {
			if err := owned.MkdirAll(parent, 0o700); err != nil {
				return err
			}
		}
	}
	logFile, err := owned.OpenFile(logName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	command := exec.Command(spec.Binary, spec.Args...)
	command.Dir = spec.Dir
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	pid := command.Process.Pid
	ready := false
	defer func() {
		if ready {
			return
		}
		// Only the child started by this call is stopped; never a PID discovered
		// later in a mutable PID file. Reap it on every startup failure.
		_ = command.Process.Kill()
		_ = command.Wait()
		if savedPID, err := readManagedPID(spec); err == nil && savedPID == pid {
			_ = owned.Remove(pidName)
			_ = owned.Remove(receiptName)
		}
	}()
	if err := owned.WriteAtomic(pidName, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		_ = command.Process.Kill()
		_ = logFile.Close()
		return err
	}
	_ = logFile.Close()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if controller.Running(spec) {
			if spec.RouteProof {
				receipt, err := routeidentity.RecordStart(pid, spec.Binary, spec.Args, spec.MatchArg, configHash)
				if err != nil {
					return fmt.Errorf("record managed route identity: %w", err)
				}
				if err := owned.WriteAtomic(receiptName, receipt, 0o600); err != nil {
					return err
				}
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			ready = true
			go func() { _ = command.Wait() }()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
	}
	_ = owned.Remove(pidName)
	return fmt.Errorf("managed process %s exited during startup", spec.ID)
}

func (OSProcessController) Stop(ctx context.Context, spec ProcessSpec) error {
	if err := validateProcessSpec(spec); err != nil {
		return err
	}
	owned, err := ownedfs.Open(spec.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer owned.Close()
	pidName, _ := filepath.Rel(spec.Dir, spec.PIDPath)
	// Invalidate proof before any stop attempt, including a cancelled stop.
	if spec.RouteProof {
		_ = owned.Remove(pidName + routeidentity.ReceiptSuffix)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pid, err := readManagedPID(spec)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !processMatches(pid, spec) {
		if !processExists(pid) {
			_ = owned.Remove(pidName)
			return nil
		}
		return fmt.Errorf("PID %d does not match managed process %s; refusing to signal it", pid, spec.ID)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = process.Signal(os.Interrupt)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if !processMatches(pid, spec) {
			_ = owned.Remove(pidName)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !processMatches(pid, spec) {
		_ = owned.Remove(pidName)
		return nil
	}
	if err := process.Kill(); err != nil {
		return err
	}
	_ = owned.Remove(pidName)
	return nil
}

func (OSProcessController) Running(spec ProcessSpec) bool {
	if validateProcessSpec(spec) != nil {
		return false
	}
	pid, err := readManagedPID(spec)
	return err == nil && processMatches(pid, spec)
}

func validateProcessSpec(spec ProcessSpec) error {
	if spec.ID == "" || spec.Binary == "" || spec.PIDPath == "" || spec.LogPath == "" || spec.Dir == "" || spec.MatchArg == "" {
		return errors.New("incomplete managed process specification")
	}
	if strings.ContainsAny(spec.ID, "/\\\x00") {
		return errors.New("invalid managed process id")
	}
	if !filepath.IsAbs(spec.Dir) || filepath.Clean(spec.Dir) == filepath.VolumeName(spec.Dir)+string(filepath.Separator) {
		return errors.New("managed process needs a dedicated absolute directory")
	}
	for _, path := range []string{spec.PIDPath, spec.LogPath, spec.MatchArg} {
		relative, err := filepath.Rel(spec.Dir, path)
		if err != nil || !filepath.IsAbs(path) || !filepath.IsLocal(relative) || relative == "." {
			return errors.New("managed process files must stay below its directory")
		}
	}
	if _, err := os.Lstat(spec.Dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	owned, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return err
	}
	defer owned.Close()
	for _, path := range []string{spec.PIDPath, spec.LogPath, spec.MatchArg, spec.PIDPath + routeidentity.ReceiptSuffix} {
		relative, _ := filepath.Rel(spec.Dir, path)
		if err := owned.Check(relative); err != nil {
			return err
		}
	}
	return nil
}

func readManagedPID(spec ProcessSpec) (int, error) {
	owned, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return 0, err
	}
	defer owned.Close()
	name, err := filepath.Rel(spec.Dir, spec.PIDPath)
	if err != nil {
		return 0, err
	}
	data, err := owned.ReadLimited(name, 64)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, errors.New("invalid managed PID file")
	}
	return pid, nil
}

func processMatches(pid int, spec ProcessSpec) bool {
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if len(args) == 0 || !strings.EqualFold(filepath.Base(args[0]), filepath.Base(spec.Binary)) {
		return false
	}
	for _, arg := range args[1:] {
		if arg == spec.MatchArg {
			return true
		}
	}
	return false
}

func processExists(pid int) bool {
	_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	return err == nil
}
