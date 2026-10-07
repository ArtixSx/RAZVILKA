//go:build linux

package nativeowner

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/usquediag"
	"golang.org/x/sys/unix"
)

// RunSupervisor is only for the new dedicated command. It never reads a saved
// grant/account path from CLI, adopts a PID, or changes the network namespace.
// All permission arrives on the private inherited live seqpacket endpoint.
func RunSupervisor() int {
	if supervise() != nil {
		return 125
	}
	return 0
}

func supervise() (err error) {
	parentPID := os.Getppid()
	endpoint := os.NewFile(3, "usque-owner-permission")
	if endpoint == nil {
		return ErrOwned
	}
	defer endpoint.Close()
	ch, err := openChannel(endpoint, parentPID, time.Now().Add(30*time.Second))
	if err != nil {
		return ErrOwned
	}
	defer ch.close()
	initial, err := ch.receive()
	if err != nil || initial.Kind != "offer" || initial.Offer == nil {
		return ErrOwned
	}
	o := *initial.Offer
	o.Launch = cloneLaunch(o.Launch)
	if o.Version != 1 || o.digest() != initial.Binding || !launchMatches(o.Scope, o.Launch) || !controlShape(o.Control) || !assetShape(o.Scope.Helper) ||
		o.Scope.Parent.PID != parentPID || !time.Now().Before(o.Scope.Deadline) || o.Scope.Deadline.After(time.Now().Add(30*time.Second)) {
		return ErrOwned
	}
	identity, err := components.ReadNFQWSSupervisionIdentity()
	sid, sidErr := unix.Getsid(0)
	if err != nil || sidErr != nil || sid != identity.PID || identity.Group != identity.PID || identity.BootID != o.Scope.Parent.BootID {
		return ErrOwned
	}
	files := make([]*os.File, 7)
	for i := range files {
		fd := i + 4
		unix.CloseOnExec(fd)
		files[i] = os.NewFile(uintptr(fd), "usque-owner-asset")
		if files[i] == nil {
			return ErrOwned
		}
		defer files[i].Close()
	}
	helperInfo, e1 := files[0].Stat()
	configInfo, e2 := files[1].Stat()
	binaryInfo, e3 := files[2].Stat()
	rootInfo, e4 := files[3].Stat()
	ns, e5 := netNamespace(files[4])
	selfExe, e6 := os.Stat("/proc/self/exe")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || !os.SameFile(helperInfo, selfExe) || ns != o.Scope.Namespace {
		return ErrOwned
	}
	helper := &heldFile{file: files[0], info: helperInfo, path: o.Scope.Helper.Path, hash: o.Scope.Helper.SHA256, limit: 256 << 20}
	config := &heldFile{file: files[1], info: configInfo, path: o.Launch.Process.MatchArg, hash: o.Launch.ConfigSHA256, limit: 8 << 20}
	binary := &heldFile{file: files[2], info: binaryInfo, path: o.Launch.Process.Binary, hash: o.Launch.BinarySHA256, limit: 256 << 20}
	root, err := os.OpenRoot(o.Launch.Process.Dir)
	if err != nil {
		return ErrOwned
	}
	defer root.Close()
	controlRoot, err := os.OpenRoot(o.Control.Root)
	if err != nil {
		return ErrOwned
	}
	defer controlRoot.Close()
	controlRootInfo, e7 := files[5].Stat()
	controlLockInfo, e8 := files[6].Stat()
	if e7 != nil || e8 != nil {
		return ErrOwned
	}
	anchors := &controlAnchors{root: controlRoot, directory: files[5], lock: files[6], rootInfo: controlRootInfo, lockInfo: controlLockInfo, path: o.Control.Root}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	ctx, expire := context.WithDeadline(ctx, o.Scope.Deadline)
	defer expire()
	current := func() error {
		p, e1 := components.ReadNFQWSRuntimeProcessIdentity(parentPID)
		actual, e2 := root.Stat(".")
		path, e3 := os.Lstat(o.Launch.Process.Dir)
		currentNS, e4 := namespaceAt("self")
		if ctx.Err() != nil || e1 != nil || e2 != nil || e3 != nil || e4 != nil || p != o.Scope.Parent || !os.SameFile(actual, rootInfo) || !os.SameFile(path, rootInfo) || currentNS != ns || helper.current(ctx) != nil || binary.current(ctx) != nil || config.current(ctx) != nil || anchors.current() != nil {
			return ErrOwned
		}
		control, present, err := operationgate.ReadSelfUpdateStop(ctx, o.Control.Root)
		if err != nil || !present || control.Stopped || control.InstallationID != o.Control.InstallationID || control.Sequence != o.Control.Sequence || operationgate.CheckSelfUpdateStop(ctx, o.Control.Root, o.Control.TransactionID) != nil {
			return ErrOwned
		}
		return nil
	}
	data, err := io.ReadAll(io.NewSectionReader(files[1], 0, (8<<20)+1))
	defer clear(data)
	selected, assetErr := usquediag.ValidateOwnedUSQUENativeAssets(data, o.Launch.Transport, o.Launch.BinarySHA256, runtime.GOARCH)
	if err != nil || assetErr != nil || selected != o.Launch.Endpoint || current() != nil || components.ProbePackageSupervision() != nil {
		return ErrOwned
	}
	// Only this dedicated helper is subreaper/Wait4 owner. An opening ECHILD is
	// mandatory; previous children cannot be adopted into this invocation.
	var status syscall.WaitStatus
	if pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil); e != syscall.ECHILD || pid > 0 {
		return ErrOwned
	}
	base := frame{Version: 1, Binding: o.digest(), Helper: identity}
	base.Kind = "ready"
	if ch.send(base) != nil {
		return ErrOwned
	}
	if ch.conn.SetDeadline(o.Scope.Deadline.Add(o.Scope.Acquisition.Request.CleanupTimeout)) != nil {
		return ErrOwned
	}
	permission, permissionErr := ch.receive()
	base.Kind = "permit"
	receipt := components.NFQWSSupervisionReceipt{State: "not-started", BootID: identity.BootID, Start: identity.Start, PID: identity.PID, Group: identity.Group, CommandSHA256: o.digest(), ExitCode: 125}
	var child components.NFQWSRuntimeProcessIdentity
	if permissionErr != nil || !reflect.DeepEqual(permission, base) || current() != nil {
		if pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil); e != syscall.ECHILD || pid > 0 {
			return ErrOwned
		}
		receipt.WaitECHILD = true
		return terminalACK(ch, o, identity, child, receipt)
	}
	log, err := root.OpenFile("engine.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrOwned
	}
	defer log.Close()
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Args = append([]string{o.Launch.Process.Binary}, o.Launch.Process.Args...)
	cmd.Dir = o.Launch.Process.Dir
	cmd.Env = append([]string(nil), o.Launch.ProcessEnvironment...)
	cmd.ExtraFiles = []*os.File{files[2], files[1]}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Permission is already consumed. The protected epoch surrounds only the
	// actual syscall; immutable retained assets/parent facts are checked inside.
	// Slow digest/review reads precede the short protected epoch. Only fast held
	// descriptor/path continuity checks accompany the actual start syscall.
	preStartErr := current()
	startErr := preStartErr
	if preStartErr == nil {
		startErr = operationgate.WithSelfUpdateEffectAdmission(ctx, o.Control.Root, o.Control.TransactionID, o.Control.InstallationID, o.Control.Sequence, "usque-native-child", func() error {
			actual, e1 := root.Stat(".")
			path, e2 := os.Lstat(o.Launch.Process.Dir)
			configPath, e3 := os.Lstat(o.Launch.Process.MatchArg)
			if ctx.Err() != nil || anchors.current() != nil || e1 != nil || e2 != nil || e3 != nil || !os.SameFile(actual, rootInfo) || !os.SameFile(path, rootInfo) || !os.SameFile(configPath, configInfo) {
				return ErrOwned
			}
			return cmd.Start()
		})
	}
	if cmd.Process == nil {
		if pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil); e != syscall.ECHILD || pid > 0 {
			return ErrOwned
		}
		receipt.WaitECHILD = true
		return terminalACK(ch, o, identity, child, receipt)
	}
	defer cmd.Process.Release() // Wait4 below is the only child wait owner
	receipt.Started = true
	receipt.ChildPID = cmd.Process.Pid
	receipt.State = "running"
	child, err = components.ReadNFQWSRuntimeProcessIdentity(cmd.Process.Pid)
	if err != nil || !childMatches(o, identity, child) {
		startErr = ErrOwned
	}
	if startErr == nil {
		base.Kind = "started"
		base.Child = child
		if ch.send(base) != nil {
			startErr = ErrOwned
		}
	}
	// A STOP, lost parent/channel, deadline, control change or abnormal direct
	// exit all trigger bounded cleanup of only this helper's unreaped children.
	stop := make(chan struct{})
	go func() { _, _ = ch.receive(); close(stop) }()
	cleanup := startErr != nil
	var cleanupDeadline time.Time
	for {
		if ctx.Err() != nil {
			cleanup = true
		} else if p, e := components.ReadNFQWSRuntimeProcessIdentity(parentPID); e != nil || p != o.Scope.Parent {
			cleanup = true
		}
		select {
		case <-stop:
			cleanup = true
		default:
		}
		if !cleanup {
			record, present, e := operationgate.ReadSelfUpdateStop(ctx, o.Control.Root)
			if e != nil || !present || record.Stopped || record.InstallationID != o.Control.InstallationID || record.Sequence != o.Control.Sequence {
				cleanup = true
			}
		}
		if cleanup {
			if cleanupDeadline.IsZero() {
				cleanupDeadline = time.Now().Add(min(o.Scope.Acquisition.Request.CleanupTimeout, 2*time.Second))
			}
			if !receipt.DirectReaped {
				_ = syscall.Kill(receipt.ChildPID, syscall.SIGKILL)
			} // still our unreaped exact child
			killUnreapedChildren(identity.PID)
			if !time.Now().Before(cleanupDeadline) {
				return ErrOwned
			}
		}
		pid, e := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil)
		if e == syscall.EINTR {
			continue
		}
		if e == syscall.ECHILD {
			if !receipt.DirectReaped {
				return ErrOwned
			}
			receipt.WaitECHILD = true
			break
		}
		if e != nil {
			return ErrOwned
		}
		if pid > 0 {
			if !status.Exited() && !status.Signaled() {
				cleanup = true
				continue
			}
			receipt.Reaped++
			if pid == receipt.ChildPID {
				receipt.DirectReaped = true
				cleanup = true
			}
			continue
		}
		time.Sleep(10 * time.Millisecond) // bounded private wait poll; no shared-process Wait
	}
	// The watcher is the only live reader until it consumes STOP/loss. Join it
	// before terminal ACK reads, so it can never steal the parent's ACK packet.
	select {
	case <-stop:
	case <-time.After(time.Until(o.Scope.Deadline.Add(o.Scope.Acquisition.Request.CleanupTimeout))):
		return ErrOwned
	}
	receipt.State = "reaped"
	receipt.Cancelled = cleanup
	receipt.ExitCode = 125
	return terminalACK(ch, o, identity, child, receipt)
}

func terminalACK(ch *channel, o offer, h components.NFQWSSupervisionIdentity, c components.NFQWSRuntimeProcessIdentity, r components.NFQWSSupervisionReceipt) error {
	if !terminalMatches(o, h, c, r) {
		return ErrOwned
	}
	f := frame{Version: 1, Kind: "terminal", Binding: o.digest(), Helper: h, Child: c, Receipt: r}
	if ch.send(f) != nil {
		return ErrOwned
	}
	// Parent may queue STOP after deadline cleanup; drain only that exact frame.
	for {
		ack, err := ch.receive()
		if err != nil {
			return ErrOwned
		}
		if ack.Kind == "stop" && ack.Binding == f.Binding && ack.Helper == h {
			continue
		}
		f.Kind = "ack"
		if !reflect.DeepEqual(ack, f) {
			return ErrOwned
		}
		return nil
	}
}

// This bounded scan is cleanup only. Sole Wait4 prevents reuse of our unreaped
// children between the exact PPID/birth samples and signal. Only ECHILD proves
// complete quiescence, including adopted descendants/clone children.
func killUnreapedChildren(parent int) {
	proc, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer proc.Close()
	entries, _ := proc.ReadDir(4096)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		first, e1 := components.ReadNFQWSRuntimeProcessIdentity(pid)
		if e1 != nil || first.ParentPID != parent {
			continue
		}
		second, e2 := components.ReadNFQWSRuntimeProcessIdentity(pid)
		if e2 == nil && second == first {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}
