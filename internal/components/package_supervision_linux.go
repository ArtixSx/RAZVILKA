//go:build linux

package components

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func bootIdentity() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if !validBootID(id) {
		return "", ErrUpdateUnknown
	}
	return id, nil
}

func processBirth(pid int) (string, int, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, err
	}
	end := strings.LastIndex(string(data), ")")
	if end < 0 {
		return "", 0, ErrUpdateUnknown
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 20 {
		return "", 0, ErrUpdateUnknown
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return "", 0, err
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", 0, err
	}
	return fields[19], group, nil
}

// Call only from the dedicated CLI process, never from the ordinary server.
func ProbePackageSupervision() error {
	const set, get = 36, 37 // PR_SET_CHILD_SUBREAPER / PR_GET_CHILD_SUBREAPER
	if _, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, set, 1, 0, 0, 0, 0); err != 0 {
		return err
	}
	var enabled int32
	if _, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, get, uintptr(unsafe.Pointer(&enabled)), 0, 0, 0, 0); err != 0 {
		return err
	}
	if enabled != 1 {
		return ErrUpdateUnknown
	}
	return nil
}

func (runner execRunner) runSupervised(ctx context.Context, name string, args []string, r packageSupervision, root *ownedfs.Root, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	boot, err := bootIdentity()
	if err != nil {
		return nil, err
	}
	start, _, err := processBirth(os.Getpid())
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, ErrUpdateUnknown
	}
	command := packageCommand{Schema: 1, TransactionID: r.TransactionID, Component: r.Component, Action: r.Action, Program: name, Args: args, BootID: boot, ParentPID: os.Getpid(), ParentStart: start, Deadline: deadline}
	if runner.supervisorPath != "" {
		for _, e := range runner.supervisorEnv {
			if strings.HasPrefix(e, "RAZVILKA_EXPECTED_OFFLINE_ROOT=") {
				command.Environment = append(command.Environment, e)
			}
		}
	}
	hash, err := writePackageCommand(root, command)
	if err != nil {
		return nil, err
	}
	r.BootID, r.CommandSHA256 = boot, hash
	if err := writeSupervision(root, r); err != nil {
		return nil, err
	}
	helper := runner.supervisorPath
	prefix := runner.supervisorArgs
	if helper == "" {
		if filepath.Dir(path) != productionPackageJournal {
			return nil, ErrUpdateUnknown
		}
		helper = "/opt/bin/razvilka"
		prefix = []string{"component-package-supervisor"}
	}
	cmd := exec.Command(helper, append(append([]string{}, prefix...), r.TransactionID, r.Component, r.Action)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = append(os.Environ(), runner.supervisorEnv...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, errors.Join(ErrUpdateUnknown, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-ctx.Done():
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			return nil, errors.Join(ErrUpdateUnknown, ctx.Err())
		}
	}
	out, _ := root.ReadLimited(r.Action+".output", 8192)
	journal, err := openUpdateRoot(filepath.Dir(path), false)
	if err != nil {
		return out, err
	}
	defer journal.Close()
	final, err := readSupervision(journal, r.TransactionID, r.Component, r.Action)
	if err != nil || final.CommandSHA256 != hash || final.State != "reaped" {
		return out, errors.Join(ErrUpdateUnknown, err)
	}
	if final.ExitCode != 0 {
		return out, fmt.Errorf("package command exited %d after all descendants reaped", final.ExitCode)
	}
	return out, ctx.Err()
}

func privateSupervisorRoot(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return ErrUpdateUnknown
	}
	return nil
}

func supervisionRootSafe(path string) error { return privateSupervisorRoot(path) }

// Main dispatches this before daemon startup and terminates with this code.
// No command, argv, path or PID comes from the CLI/HTTP request.
func RunPackageSupervisor(transactionID, component, action string) int {
	if err := runPackageSupervisorAt(productionPackageJournal, transactionID, component, action, false); err != nil {
		return 1
	}
	return 0
}

func runPackageSupervisorAt(path, id, component, action string, test bool) error {
	// Register before filesystem reads/fsync or child creation. A router's
	// USB storage may make the durable running write take several seconds.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	if action != "upgrade" && action != "rollback" {
		return ErrUpdateUnknown
	}
	if err := privateSupervisorRoot(path); err != nil {
		return err
	}
	journal, err := openUpdateRoot(path, false)
	if err != nil {
		return err
	}
	defer journal.Close()
	doc, present, err := readUpdateJournal(journal)
	if err != nil || !present || doc.TransactionID != id || doc.Component != component || doc.SupervisionVersion != 1 {
		return ErrUpdateUnknown
	}
	if (action == "upgrade" && doc.Phase != UpdateStarted) || (action == "rollback" && doc.Phase != UpdateRollbackStarted) {
		return ErrUpdateUnknown
	}
	snapshotPath := filepath.Join(path, id)
	if err := privateSupervisorRoot(snapshotPath); err != nil {
		return err
	}
	root, err := ownedfs.Open(snapshotPath)
	if err != nil {
		return err
	}
	defer root.Close()
	release, err := lockUpdateWriter(root)
	if err != nil {
		return err
	}
	defer release()
	r, err := readSupervision(journal, id, component, action)
	if err != nil || r.State != "intent" {
		return ErrUpdateUnknown
	}
	data, err := root.ReadLimited(action+".command.json", 16384)
	if err != nil || digest(data) != r.CommandSHA256 {
		return ErrUpdateUnknown
	}
	var command packageCommand
	if strictJSON(data, &command) != nil || command.Schema != 1 || command.TransactionID != id || command.Component != component || command.Action != action || len(command.Nonce) != 32 || command.BootID != r.BootID {
		return ErrUpdateUnknown
	}
	boot, err := bootIdentity()
	if err != nil || boot != command.BootID {
		return ErrUpdateUnknown
	}
	start, _, err := processBirth(command.ParentPID)
	if err != nil || start != command.ParentStart || command.ParentPID <= 1 || !time.Now().Before(command.Deadline) {
		return ErrUpdateUnknown
	}
	if !test {
		if command.Program != "/opt/bin/opkg" && command.Program != "/opt/sbin/opkg" {
			return ErrUpdateUnknown
		}
		if len(command.Environment) != 0 {
			return ErrUpdateUnknown
		}
		if action == "upgrade" {
			if len(command.Args) != 2 || command.Args[0] != "upgrade" || command.Args[1] != doc.Package {
				return ErrUpdateUnknown
			}
		} else {
			if len(command.Args) != 4 || command.Args[0] != "install" || command.Args[1] != "--force-downgrade" || command.Args[2] != "--force-reinstall" || command.Args[3] != filepath.Join(snapshotPath, doc.PackageFile) {
				return ErrUpdateUnknown
			}
			// loadSnapshot enforces the immutable package checksum and size bound.
			tx := updateTransaction{manager: &Manager{StateDir: filepath.Dir(path)}, root: journal, doc: doc}
			if _, _, err := tx.loadSnapshot(); err != nil {
				return err
			}
		}
	}
	if err := ProbePackageSupervision(); err != nil {
		return err
	}
	r.PID = os.Getpid()
	r.Start, r.Group, err = processBirth(r.PID)
	if err != nil || r.Group != r.PID {
		return ErrUpdateUnknown
	}
	r.State = "armed"
	if err := writeSupervision(root, r); err != nil {
		return err
	}
	read, write, err := os.Pipe()
	if err != nil {
		return err
	}
	defer read.Close()
	defer write.Close()
	var output boundedPackageLog
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&output, read); close(copied) }()
	cmd := exec.Command(command.Program, command.Args...)
	cmd.Stdout = write
	cmd.Stderr = write
	cmd.Env = append(os.Environ(), command.Environment...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	select {
	case <-signals:
		return ErrUpdateUnknown
	default:
	}
	if err := cmd.Start(); err != nil {
		_ = write.Close()
		<-copied
		var status syscall.WaitStatus
		if _, e := syscall.Wait4(-1, &status, syscall.WNOHANG, nil); e != syscall.ECHILD {
			return ErrUpdateUnknown
		}
		r.State = "not-started"
		r.WaitECHILD = true
		return errors.Join(err, writeSupervision(root, r))
	}
	_ = write.Close()
	r.ChildPID = cmd.Process.Pid
	r.State = "running"
	writeErr := writeSupervision(root, r)
	// This is the sole wait owner. cmd.Wait must never compete with adoption.
	code, seen := 1, false
	cleanup := writeErr != nil
	for {
		select {
		case <-signals:
			cleanup = true
		default:
		}
		if !time.Now().Before(command.Deadline) {
			cleanup = true
		}
		if cleanup {
			killSupervisorChildren(r.PID)
		}
		var status syscall.WaitStatus
		pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if e == syscall.EINTR {
			continue
		}
		if e == syscall.ECHILD {
			if !seen {
				return ErrUpdateUnknown
			}
			break
		}
		if e != nil {
			return e
		}
		if pid > 0 {
			r.Reaped++
			if pid == r.ChildPID {
				seen = true
				if status.Exited() {
					code = status.ExitStatus()
				} else {
					code = 128 + int(status.Signal())
				}
			}
			continue
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = cmd.Process.Release()
	<-copied
	if err := root.WriteAtomic(action+".output", output.data(), 0600); err != nil {
		return err
	}
	if err := syncUpdateDirectory(root); err != nil {
		return err
	}
	if writeErr != nil {
		return writeErr
	}
	// Reaping after forced cleanup proves inactivity, never hook success.
	// The direct opkg may have exited zero long before its detached child.
	if cleanup {
		code = 125
		r.Cancelled = true
	}
	r.State = "reaped"
	r.WaitECHILD = true
	r.ExitCode = code
	if err := writeSupervision(root, r); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("package command exit %d", code)
	}
	return nil
}

func killSupervisorChildren(pid int) {
	// Netcraze 4.9 has no /proc/<pid>/task/<tid>/children interface. The
	// bounded stat scan is for cleanup only, never for positive quiescence.
	// These are our own unreaped children; this sole wait loop prevents PID
	// reuse between the exact PPID/birth recheck and signal.
	for child, birth := range supervisorChildrenAt("/proc", pid) {
		start, parent, err := childIdentityAt("/proc", child)
		if err == nil && parent == pid && start == birth {
			_ = syscall.Kill(child, syscall.SIGKILL)
		}
	}
}

func childIdentityAt(proc string, pid int) (string, int, error) {
	path := filepath.Join(proc, strconv.Itoa(pid), "stat")
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return "", 0, ErrUpdateUnknown
	}
	end := strings.LastIndex(string(data), ")")
	if end < 0 {
		return "", 0, ErrUpdateUnknown
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 20 {
		return "", 0, ErrUpdateUnknown
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, err
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", 0, err
	}
	return fields[19], parent, nil
}

func supervisorChildrenAt(proc string, parent int) map[int]string {
	children := map[int]string{}
	entries, _ := os.ReadDir(proc)
	read := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		read++
		if read > 4096 {
			break
		}
		birth, ppid, err := childIdentityAt(proc, pid)
		if err == nil && ppid == parent {
			children[pid] = birth
		}
	}
	return children
}

func supervisionInactive(ctx context.Context, r packageSupervision) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := bootIdentity()
	if err != nil {
		return err
	}
	if boot != r.BootID {
		return nil
	} // Proves inactivity only, never command success.
	if (r.State == "reaped" || r.State == "not-started") && r.WaitECHILD {
		return nil
	}
	// Dead/reused PID or an empty /proc cannot prove detached children died.
	return ErrUpdateUnknown
}
