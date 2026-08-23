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
)

type ProcessSpec struct {
	ID       string
	Binary   string
	Args     []string
	Dir      string
	PIDPath  string
	LogPath  string
	MatchArg string
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
	_ = os.Remove(spec.PIDPath)
	if err := os.MkdirAll(filepath.Dir(spec.PIDPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(spec.LogPath), 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(spec.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
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
	if err := writeAtomic(spec.PIDPath, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		_ = command.Process.Kill()
		_ = logFile.Close()
		return err
	}
	_ = command.Process.Release()
	_ = logFile.Close()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if controller.Running(spec) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
	}
	_ = os.Remove(spec.PIDPath)
	return fmt.Errorf("managed process %s exited during startup", spec.ID)
}

func (OSProcessController) Stop(ctx context.Context, spec ProcessSpec) error {
	if err := validateProcessSpec(spec); err != nil {
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
			_ = os.Remove(spec.PIDPath)
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
			_ = os.Remove(spec.PIDPath)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !processMatches(pid, spec) {
		_ = os.Remove(spec.PIDPath)
		return nil
	}
	if err := process.Kill(); err != nil {
		return err
	}
	_ = os.Remove(spec.PIDPath)
	return nil
}

func (OSProcessController) Running(spec ProcessSpec) bool {
	pid, err := readManagedPID(spec)
	return err == nil && processMatches(pid, spec)
}

func validateProcessSpec(spec ProcessSpec) error {
	if spec.ID == "" || spec.Binary == "" || spec.PIDPath == "" || spec.LogPath == "" || spec.Dir == "" || spec.MatchArg == "" {
		return errors.New("incomplete managed process specification")
	}
	if strings.ContainsAny(spec.ID, `/\\\x00`) {
		return errors.New("invalid managed process id")
	}
	return nil
}

func readManagedPID(spec ProcessSpec) (int, error) {
	data, err := os.ReadFile(spec.PIDPath)
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
