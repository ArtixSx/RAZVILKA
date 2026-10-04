//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const nfqws2ManagedJoinGrace = time.Second

func nfqws2ManagedObservationPath(path string) error { return nfqws2ManagedProtected(path, true) }

func nfqws2ManagedProtected(path string, privateParent bool) error {
	if !nfqws2ManagedPath(path) {
		return ErrNFQWSManagedProcessUnknown
	}
	chain := []string{path}
	for ancestor := filepath.Dir(path); ancestor != chain[len(chain)-1]; ancestor = filepath.Dir(ancestor) {
		chain = append(chain, ancestor)
	}
	slices.Reverse(chain)
	temporary, private := false, false
	for i, current := range chain {
		info, err := os.Lstat(current)
		if i == len(chain)-1 && privateParent && errors.Is(err, os.ErrNotExist) && (!temporary || private) {
			return nil // Existing private parent has been checked; intent may create this leaf.
		}
		stat, ok := func() (*syscall.Stat_t, bool) {
			if err != nil {
				return nil, false
			}
			v, ok := info.Sys().(*syscall.Stat_t)
			return v, ok
		}()
		if err != nil || !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0o022 != 0 && !(current == "/tmp" && info.IsDir() && info.Mode()&os.ModeSticky != 0)) {
			return errors.Join(ErrNFQWSManagedProcessUnknown, err)
		}
		if i == len(chain)-1 {
			if !info.Mode().IsRegular() || (temporary && !private) {
				return ErrNFQWSManagedProcessUnknown
			}
			return nil
		}
		if !info.IsDir() || (temporary && info.Mode().Perm()&0o077 != 0) || (privateParent && i == len(chain)-2 && info.Mode().Perm()&0o077 != 0) {
			return ErrNFQWSManagedProcessUnknown
		}
		if temporary {
			private = true
		}
		if current == "/tmp" && info.Mode()&os.ModeSticky != 0 && info.Mode().Perm()&0o022 != 0 {
			temporary = true
		}
	}
	return ErrNFQWSManagedProcessUnknown
}

func nfqws2ManagedFilesCurrent(command nfqws2ManagedProcessCommand) error {
	files := append([]nfqws2ManagedFile{command.Program}, command.Assets...)
	for i, asset := range files {
		if nfqws2ManagedProtected(asset.Path, false) != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		before, err := os.Lstat(asset.Path)
		limit := int64(4 << 20)
		if i == 0 {
			limit = 64 << 20
		}
		if err != nil || before.Size() <= 0 || before.Size() > limit || (i == 0 && before.Mode().Perm()&0o100 == 0) {
			return ErrNFQWSManagedProcessUnknown
		}
		file, err := os.Open(asset.Path)
		if err != nil {
			return errors.Join(ErrNFQWSManagedProcessUnknown, err)
		}
		opened, statErr := file.Stat()
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(file, limit+1))
		after, afterErr := file.Stat()
		_ = file.Close()
		current, pathErr := os.Lstat(asset.Path)
		if statErr != nil || readErr != nil || afterErr != nil || pathErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, current) || !current.Mode().IsRegular() || n != opened.Size() || n > limit || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) || hex.EncodeToString(hash.Sum(nil)) != asset.SHA256 {
			return ErrNFQWSManagedProcessUnknown
		}
	}
	return nil
}

func nfqws2ManagedControlCurrent(ctx context.Context, command nfqws2ManagedProcessCommand) error {
	control, present, err := operationgate.ReadSelfUpdateStop(ctx, command.ControlRoot)
	if err != nil || !present || control.Stopped || control.InstallationID != command.InstallationID || control.Sequence != command.Sequence {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	return ctx.Err()
}

// Exact daemon observation is process-only evidence. The two-sided samples
// reject a dying, reparented, replaced or exec-changed child and a foreign helper.
// No process/lease discovery is promoted to authority to start or attach rules.
func (a *NFQWS2Adapter) observeManagedNFQWSProcessRunning(ctx context.Context) (nfqws2ManagedProcessLease, error) {
	var zero nfqws2ManagedProcessLease
	if a == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	owner, err := a.owner()
	path := filepath.Join(a.StateRoot, nfqws2LeaseFile)
	if err != nil || nfqws2ManagedProtected(path, true) != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	before, err := restorejournal.ReadFileImage(ctx, path)
	lease, decodeErr := nfqws2DecodeManagedLease(before, a.StateRoot, owner)
	if err != nil || decodeErr != nil || lease.Acknowledged || lease.Receipt.State != "running" || lease.Child.PID <= 1 || !time.Now().Before(lease.Command.Deadline) || nfqws2ManagedFilesCurrent(lease.Command) != nil || nfqws2ManagedControlCurrent(ctx, lease.Command) != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err, decodeErr)
	}
	verify := func() error {
		helper, helperErr := components.ReadNFQWSSupervisionProcessIdentity(lease.Receipt.PID)
		child, childErr := components.ReadNFQWSRuntimeProcessIdentity(lease.Child.PID)
		if helperErr != nil || childErr != nil || helper.BootID != lease.Receipt.BootID || helper.Start != lease.Receipt.Start || helper.Group != lease.Receipt.Group || child != lease.Child {
			return errors.Join(ErrNFQWSManagedProcessUnknown, helperErr, childErr)
		}
		return nil
	}
	if err := verify(); err != nil {
		return zero, err
	}
	after, err := restorejournal.ReadFileImage(ctx, path)
	if err != nil || !reflect.DeepEqual(before, after) || verify() != nil || nfqws2ManagedControlCurrent(ctx, lease.Command) != nil || ctx.Err() != nil || !time.Now().Before(lease.Command.Deadline) {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err, ctx.Err())
	}
	return lease, nil
}

// Private process producer. A finished scoped owner must construct its command
// before production wiring; self-update admission alone is not that authority.
// No package init, PID file, queue plan or stock resource is touched here.
func (a *NFQWS2Adapter) runManagedNFQWSProcess(ctx context.Context, command nfqws2ManagedProcessCommand, helperPrefix []string) (nfqws2ManagedProcessLease, error) {
	var zero nfqws2ManagedProcessLease
	owner, err := a.owner()
	if ctx == nil || err != nil || command.StateRoot != a.StateRoot || command.Owner != owner || nfqws2ValidateManagedCommand(command) != nil || !time.Now().Before(command.Deadline) || command.Deadline.After(time.Now().Add(15*time.Second)) {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	command.Args, command.Assets = slices.Clone(command.Args), slices.Clone(command.Assets)
	if nfqws2ManagedFilesCurrent(command) != nil || nfqws2ManagedControlCurrent(ctx, command) != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	program, err := os.Executable()
	if err != nil || nfqws2ManagedProtected(program, false) != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	installed, e1 := os.Stat(program)
	running, e2 := os.Stat("/proc/self/exe")
	if e1 != nil || e2 != nil || !os.SameFile(installed, running) {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	path := filepath.Join(a.StateRoot, nfqws2LeaseFile)
	if nfqws2ManagedProtected(path, true) != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	parent, err := os.Lstat(a.StateRoot)
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	before, err := target.Read(ctx)
	if err != nil || before.Exists {
		_ = target.Close()
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	store := nfqws2ManagedProcessStore{target: target, image: before, lease: nfqws2ManagedProcessLease{Version: 2, StateRoot: a.StateRoot, Owner: owner, Command: command, CommandSHA256: nfqws2ManagedCommandDigest(command), Receipt: components.NFQWSSupervisionReceipt{State: "intent"}}}
	err = store.publish(ctx)
	store.close() // The helper takes this same filename's writer lease.
	if err != nil {
		return zero, err
	}
	if helperPrefix == nil {
		helperPrefix = []string{"nfqws-managed-process-supervisor"}
	}
	args := append(slices.Clone(helperPrefix), command.ID)
	cmd := exec.Command(program, args...)
	cmd.Env = []string{"PATH=/opt/bin:/opt/sbin:/usr/bin:/bin", "LANG=C", "TZ=UTC", "RAZVILKA_DATAPLANE_STATE=" + filepath.Dir(filepath.Dir(a.StateRoot)), "RAZVILKA_SELF_UPDATE_CONTROL_STATE=" + command.ControlRoot}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = operationgate.WithSelfUpdateEffectAdmission(ctx, command.ControlRoot, command.ID, command.InstallationID, command.Sequence, "nfqws-managed-helper", cmd.Start)
	if err != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err) // Durable intent remains fenced.
	}
	identity, identityErr := components.ReadNFQWSSupervisionProcessIdentity(cmd.Process.Pid)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }() // Parent waits only for this exact helper.
	if identityErr != nil || identity.Group != identity.PID || identity.BootID != command.Parent.BootID {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, identityErr)
	}
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		_ = cmd.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(nfqws2ManagedJoinGrace)
		defer timer.Stop()
		select {
		case waitErr = <-done:
		case <-timer.C:
			return zero, errors.Join(ErrNFQWSManagedProcessUnknown, ctx.Err())
		}
	}
	if waitErr != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, waitErr)
	}
	// ACK acknowledges ONLY kernel process settlement, even after Stop/cancel.
	// It grants neither replay, managed selection nor kernel effect retirement.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), nfqws2ManagedJoinGrace)
	defer cancel()
	target, err = restorejournal.OpenFileTarget(path)
	if err != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	defer target.Close()
	image, err := target.Read(cleanupCtx)
	actual, decodeErr := nfqws2DecodeManagedLease(image, a.StateRoot, owner)
	allowed := actual
	allowed.Receipt, allowed.Child = store.lease.Receipt, store.lease.Child
	if err != nil || decodeErr != nil || actual.Acknowledged || !reflect.DeepEqual(allowed, store.lease) || actual.Receipt.PID != identity.PID || actual.Receipt.Group != identity.Group || actual.Receipt.Start != identity.Start || actual.Receipt.BootID != identity.BootID || (actual.Receipt.State != "reaped" && actual.Receipt.State != "not-started") {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err, decodeErr)
	}
	actual.Acknowledged = true
	ack := nfqws2ManagedProcessStore{target: target, image: image, lease: actual}
	if err := ack.publish(cleanupCtx); err != nil {
		return zero, err
	}
	return actual, ctx.Err()
}

// Fixed early dispatch ABI: only the invocation ID comes from CLI. Both roots
// are trusted startup settings. This does not provide scoped launch permission.
func RunNFQWSManagedProcessSupervisor(id, stateRoot, controlRoot string) int {
	if runNFQWSManagedProcessSupervisor(id, stateRoot, controlRoot) != nil {
		return 1
	}
	return 0
}

func runNFQWSManagedProcessSupervisor(id, stateRoot, controlRoot string) error {
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	path := filepath.Join(stateRoot, nfqws2LeaseFile)
	a := NFQWS2Adapter{StateRoot: stateRoot}
	owner, err := a.owner()
	if err != nil || !nfqws2ManagedHex(id, 32) || !nfqws2ManagedPath(controlRoot) || nfqws2ManagedProtected(path, true) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	// Missing/foreign intent must refuse before even opening a writer lease.
	initial, err := restorejournal.ReadFileImage(signalCtx, path)
	declared, decodeErr := nfqws2DecodeManagedLease(initial, stateRoot, owner)
	if err != nil || decodeErr != nil || declared.Command.ID != id || declared.Command.ControlRoot != controlRoot || declared.Receipt.State != "intent" || declared.Acknowledged {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err, decodeErr)
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	store := nfqws2ManagedProcessStore{target: target}
	defer store.close()
	store.image, err = target.Read(signalCtx)
	if err == nil {
		store.lease, err = nfqws2DecodeManagedLease(store.image, stateRoot, owner)
	}
	if err != nil || !reflect.DeepEqual(initial, store.image) || store.lease.Command.ID != id || store.lease.Command.ControlRoot != controlRoot || store.lease.Receipt.State != "intent" || store.lease.Acknowledged {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	command, hash := store.lease.Command, store.lease.CommandSHA256
	ctx, cancel := context.WithDeadline(signalCtx, command.Deadline)
	defer cancel()
	if nfqws2ManagedFilesCurrent(command) != nil || nfqws2ManagedControlCurrent(ctx, command) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	terminal := false
	hooks := components.NFQWSSupervisionHooks{
		Armed: func(identity components.NFQWSSupervisionIdentity) error {
			store.lease.Receipt = components.NFQWSSupervisionReceipt{State: "armed", BootID: identity.BootID, Start: identity.Start, PID: identity.PID, Group: identity.Group, CommandSHA256: hash}
			return store.publish(ctx)
		},
		Started: func(pid int) error {
			store.lease.Receipt.State, store.lease.Receipt.Started, store.lease.Receipt.ChildPID = "running", true, pid
			identity, err := components.ReadNFQWSRuntimeProcessIdentity(pid)
			if err != nil {
				return err
			}
			store.lease.Child = identity
			return store.publish(ctx)
		},
		StartAdmission: func(begin func() error) error {
			if err := nfqws2ManagedFilesCurrent(command); err != nil {
				return err
			}
			return operationgate.WithSelfUpdateEffectAdmission(ctx, controlRoot, id, command.InstallationID, command.Sequence, "nfqws-managed-child", begin)
		},
		StopCheck: func() error { return nfqws2ManagedControlCurrent(ctx, command) },
		Result: func(receipt components.NFQWSSupervisionReceipt, _ []byte) error {
			armed := store.lease.Receipt
			if receipt.PID != armed.PID || receipt.Group != armed.Group || receipt.Start != armed.Start || receipt.BootID != command.Parent.BootID || receipt.CommandSHA256 != hash {
				return ErrNFQWSManagedProcessUnknown
			}
			store.lease.Receipt = receipt
			cleanupCtx, cancel := context.WithTimeout(context.Background(), nfqws2ManagedJoinGrace)
			defer cancel()
			if err := store.publish(cleanupCtx); err != nil {
				return err
			}
			terminal = true
			return nil
		},
	}
	receipt, runErr := components.RunNFQWSSupervision(ctx, components.NFQWSSupervisionCommand{Program: command.Program.Path, Args: slices.Clone(command.Args), BootID: command.Parent.BootID, ParentPID: command.Parent.PID, ParentStart: command.Parent.Start, CommandSHA256: hash, Deadline: command.Deadline}, hooks)
	if !terminal || !receipt.WaitECHILD || (runErr != nil && receipt.ExitCode == 0 && !receipt.Cancelled) {
		return errors.Join(ErrNFQWSManagedProcessUnknown, runErr)
	}
	return nil
}
