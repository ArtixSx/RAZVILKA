//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"golang.org/x/sys/unix"
)

func mihomoLiveHashFile(ctx context.Context, file *os.File, max int64) (string, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > max {
		return "", errMihomoLiveMaterial
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	for offset := int64(0); offset < before.Size(); {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		want := min(int64(len(buffer)), before.Size()-offset)
		n, err := file.ReadAt(buffer[:want], offset)
		if n != int(want) || err != nil && !errors.Is(err, io.EOF) {
			return "", errMihomoLiveMaterial
		}
		_, _ = hash.Write(buffer[:n])
		offset += int64(n)
	}
	after, err := file.Stat()
	if err != nil || !sameXrayDomainTCPFile(before, after) {
		return "", errMihomoLiveMaterial
	}
	return hex.EncodeToString(hash.Sum(nil)), ctx.Err()
}

func newMihomoLiveSidecar(ctx context.Context, r *mihomoLiveResource, spec ProcessSpec) (n *mihomoLiveSidecar, result error) {
	if r == nil || r.self != r || r.proxy == nil || !spec.RouteProof || validateProcessSpec(spec) != nil || r.proxy.effectiveSidecar() != r.definition.Sidecar.Kind {
		return nil, errMihomoLiveMaterial
	}
	want := []string{"run", "-c", "/proc/self/fd/4"}
	if r.definition.Sidecar.Kind == "hev" {
		want = []string{"/proc/self/fd/4"}
	}
	if !slices.Equal(spec.Args, want) {
		return nil, errMihomoLiveMaterial
	}
	root, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return nil, err
	}
	n = &mihomoLiveSidecar{owner: r, spec: spec, root: root, done: make(chan struct{})}
	n.self = n
	defer func() {
		if result != nil {
			cleanupErr := n.closeUnused()
			result = errors.Join(result, cleanupErr)
			if cleanupErr == nil {
				n = nil
			}
		}
	}()
	n.rootInfo, err = root.RootInfo()
	if err != nil || !networkPolicyPrivateDirectory(n.rootInfo) {
		return n, errMihomoLiveMaterial
	}
	for _, path := range []string{spec.PIDPath, spec.PIDPath + ".pending", spec.PIDPath + routeidentity.ReceiptSuffix, spec.PIDPath + routeidentity.ReceiptSuffix + ".pending"} {
		name, err := filepath.Rel(spec.Dir, path)
		if err != nil {
			return n, err
		}
		if _, err := root.Stat(name); !errors.Is(err, os.ErrNotExist) {
			return n, errMihomoLiveMaterial
		}
	}
	n.binary, err = os.Open(spec.Binary)
	if err != nil {
		return n, err
	}
	binaryInfo, err := n.binary.Stat()
	if err != nil || binaryInfo.Size() != r.definition.Sidecar.BinarySize {
		return n, errMihomoLiveMaterial
	}
	hash, err := mihomoLiveHashFile(ctx, n.binary, 256<<20)
	if err != nil || hash != r.definition.Sidecar.BinarySHA256 {
		return n, errors.Join(errMihomoLiveMaterial, err)
	}
	n.witnessedSHA, n.witnessedSize = hash, binaryInfo.Size()
	configName, err := filepath.Rel(spec.Dir, spec.MatchArg)
	if err != nil {
		return n, err
	}
	config, err := root.ReadLimited(configName, 128<<10)
	defer clear(config)
	if err != nil || routeidentity.Hash(config) != r.definition.Sidecar.ConfigSHA256 {
		return n, errMihomoLiveMaterial
	}
	fd, err := unix.MemfdCreate("razvilka-live-sidecar", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return n, err
	}
	n.profile = os.NewFile(uintptr(fd), "[original sealed TUN sidecar config]")
	if _, err := n.profile.Write(config); err != nil {
		return n, err
	}
	if _, err := unix.FcntlInt(n.profile.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return n, err
	}
	n.command = exec.Command("/proc/self/fd/3", spec.Args...)
	n.command.Args[0], n.command.Dir = spec.Binary, spec.Dir
	n.command.Env = []string{}
	n.command.ExtraFiles = []*os.File{n.binary, n.profile}
	n.command.Stdout, n.command.Stderr = io.Discard, io.Discard
	return n, nil
}

func (n *mihomoLiveSidecar) start(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.self != n || n.started || n.closed || n.owner == nil || n.command == nil {
		return errMihomoLiveMaterial
	}
	if err := n.owner.currentBeforeStart(ctx); err != nil {
		return mihomoLiveSidecarDiagnostic("sidecar-start-owner", err)
	}
	if err := n.owner.control.WithStart(ctx, func() error {
		if err := n.command.Start(); err != nil {
			return err
		}
		n.started = true
		go func() { n.waitErr = n.command.Wait(); n.state = n.command.ProcessState; close(n.done) }()
		return nil
	}); err != nil {
		return mihomoLiveSidecarDiagnostic("sidecar-start-control", err)
	}
	n.pidRaw = []byte(strconv.Itoa(n.command.Process.Pid) + "\n")
	var err error
	n.receiptRaw, err = routeidentity.RecordStart(n.command.Process.Pid, n.spec.Binary, n.spec.Args, n.spec.MatchArg, n.owner.definition.Sidecar.ConfigSHA256)
	if err != nil {
		return mihomoLiveSidecarDiagnostic("sidecar-start-receipt", err)
	}
	for index, entry := range []struct {
		path string
		data []byte
		info *os.FileInfo
	}{{n.spec.PIDPath, n.pidRaw, &n.pidInfo}, {n.spec.PIDPath + routeidentity.ReceiptSuffix, n.receiptRaw, &n.receiptInfo}} {
		name, err := filepath.Rel(n.spec.Dir, entry.path)
		if err != nil {
			return err
		}
		err = n.publishIdentity(ctx, index, name, entry.data)
		if err != nil {
			if index == 0 {
				return mihomoLiveSidecarDiagnostic("sidecar-start-pid-publish", err)
			}
			return mihomoLiveSidecarDiagnostic("sidecar-start-receipt-publish", err)
		}
		*entry.info, err = n.root.Stat(name)
		if err != nil {
			return err
		}
	}
	return n.currentLocked(ctx)
}

func (n *mihomoLiveSidecar) metadata(ctx context.Context) error {
	if n == nil || n.self != n || n.owner == nil || n.root == nil || n.closed || n.command == nil {
		return errMihomoLiveMaterial
	}
	actual, err := os.Lstat(n.spec.Dir)
	held, heldErr := n.root.RootInfo()
	if err != nil || heldErr != nil || !networkPolicyPrivateDirectory(actual) || !os.SameFile(actual, n.rootInfo) || !os.SameFile(held, n.rootInfo) {
		return errMihomoLiveMaterial
	}
	for _, entry := range []struct {
		path string
		data []byte
		info os.FileInfo
	}{{n.spec.PIDPath, n.pidRaw, n.pidInfo}, {n.spec.PIDPath + routeidentity.ReceiptSuffix, n.receiptRaw, n.receiptInfo}} {
		name, err := filepath.Rel(n.spec.Dir, entry.path)
		if err != nil {
			return err
		}
		info, err := n.root.Stat(name)
		data, readErr := n.root.ReadLimited(name, 4096)
		if err != nil || readErr != nil || entry.info == nil || !sameXrayDomainTCPFile(entry.info, info) || !bytes.Equal(entry.data, data) {
			return errMihomoLiveMaterial
		}
	}
	for _, d := range n.identities {
		if d == nil || !d.published || n.identityFileCurrent(d, d.name) != nil {
			return errMihomoLiveMaterial
		}
	}
	name, err := filepath.Rel(n.spec.Dir, n.spec.MatchArg)
	if err != nil {
		return err
	}
	config, err := n.root.ReadLimited(name, 128<<10)
	defer clear(config)
	if err != nil || routeidentity.Hash(config) != n.owner.definition.Sidecar.ConfigSHA256 {
		return errMihomoLiveMaterial
	}
	return ctx.Err()
}

func (n *mihomoLiveSidecar) currentLocked(ctx context.Context) error {
	if !n.started || n.command.Process == nil || n.closeErr != nil {
		return errMihomoLiveMaterial
	}
	select {
	case <-n.done:
		mihomoLiveSidecarExitDiagnostic(n)
		return mihomoLiveSidecarDiagnostic("sidecar-child-exited", errMihomoLiveMaterial)
	default:
	}
	if err := errors.Join(mihomoLiveSidecarDiagnostic("sidecar-metadata", n.metadata(ctx)), mihomoLiveSidecarDiagnostic("sidecar-control", n.owner.control.ObserveCurrent(ctx))); err != nil {
		return err
	}
	return mihomoLiveSidecarDiagnostic("sidecar-kernel", n.kernelCurrent(ctx))
}

func (n *mihomoLiveSidecar) kernelCurrent(ctx context.Context) error {
	if n.command == nil || n.command.Process == nil || n.command.Path != "/proc/self/fd/3" || n.command.Dir != n.spec.Dir || !slices.Equal(n.command.Args, append([]string{n.spec.Binary}, n.spec.Args...)) || len(n.command.Env) != 0 || n.command.Cancel != nil || len(n.command.ExtraFiles) != 2 || n.command.ExtraFiles[0] != n.binary || n.command.ExtraFiles[1] != n.profile {
		return errMihomoLiveMaterial
	}
	if err := n.owner.control.CurrentForCleanup(ctx); err != nil {
		return err
	}
	proc, err := openXraySelectedTCPProc(ctx, n.command.Process.Pid)
	if err != nil {
		return err
	}
	defer proc.close()
	if err := proc.network(ctx, n.owner.definition.NetworkIdentity); err != nil {
		return err
	}
	hash, err := mihomoLiveHashFile(ctx, n.binary, 256<<20)
	if err != nil || hash != n.owner.definition.Sidecar.BinarySHA256 {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	profileHash, err := mihomoLiveHashFile(ctx, n.profile, 128<<10)
	seals, sealErr := unix.FcntlInt(n.profile.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || sealErr != nil || profileHash != n.owner.definition.Sidecar.ConfigSHA256 || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
		return errMihomoLiveMaterial
	}
	current, err := routeidentity.RecordStart(n.command.Process.Pid, n.spec.Binary, n.spec.Args, n.spec.MatchArg, n.owner.definition.Sidecar.ConfigSHA256)
	if err != nil || len(n.receiptRaw) != 0 && !bytes.Equal(current, n.receiptRaw) {
		return errMihomoLiveMaterial
	}
	for _, binding := range []struct {
		suffix string
		file   *os.File
	}{{"exe", n.binary}, {"fd/3", n.binary}, {"fd/4", n.profile}} {
		actual, err := os.Stat(filepath.Join("/proc", strconv.Itoa(n.command.Process.Pid), binding.suffix))
		held, heldErr := binding.file.Stat()
		if err != nil || heldErr != nil || !os.SameFile(actual, held) {
			return errMihomoLiveMaterial
		}
	}
	return ctx.Err()
}

func (n *mihomoLiveSidecar) current(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.currentLocked(ctx)
}
func (n *mihomoLiveSidecar) observation(ctx context.Context) (MihomoLiveRuntimeObservation, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.currentLocked(ctx); err != nil {
		return MihomoLiveRuntimeObservation{}, err
	}
	return MihomoLiveRuntimeObservation{Schema: 1, SidecarReceiptVersion: 1, SidecarReceiptSHA256: routeidentity.Hash(n.receiptRaw)}, nil
}

func (n *mihomoLiveSidecar) closeUnused() error {
	if n.started {
		return errMihomoLiveMaterial
	}
	var result error
	for _, f := range []*os.File{n.profile, n.binary} {
		if f != nil {
			result = errors.Join(result, f.Close())
		}
	}
	if n.root != nil {
		result = errors.Join(result, n.root.Close())
	}
	n.closed = result == nil
	n.closeErr = result
	return result
}

func (n *mihomoLiveSidecar) cleanup(ctx context.Context, review *operationgate.ExclusiveCleanupReview) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	if n.joined {
		return nil
	}
	if n.closeErr != nil || n.owner == nil {
		return errors.Join(errMihomoLiveMaterial, n.closeErr)
	}
	if err := n.owner.control.CurrentForCleanupOperation(ctx, review); err != nil {
		return err
	}
	if !n.started {
		return n.closeUnused()
	}
	select {
	case <-n.done:
	default:
		// The exact retained Cmd is the only signal target. A receipt never
		// substitutes a later process from its numeric PID.
		if err := n.kernelCurrent(ctx); err != nil {
			return err
		}
		if err := n.owner.control.WithCleanupStart(ctx, review, func() error {
			err := n.command.Process.Kill()
			if errors.Is(err, os.ErrProcessDone) {
				return nil
			}
			return err
		}); err != nil {
			return err
		}
	}
	select {
	case <-n.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if !xraySelectedTCPWaitResult(n.command.Process.Pid, n.state, n.waitErr) || originalProcessPIDAbsent(n.command.Process.Pid) != nil {
		return errMihomoLiveMaterial
	}
	for index := range n.identities {
		if err := n.removeIdentity(ctx, index, func(remove func() error) error { return n.owner.control.WithCleanupRemove(ctx, review, remove) }); err != nil {
			return err
		}
	}
	n.joined = true
	return nil // Root/held images survive until terminal publication ACKs.
}

func (n *mihomoLiveSidecar) closeJoined() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	if n.closeErr != nil {
		return n.closeErr
	}
	if n.started && !n.joined {
		return errMihomoLiveMaterial
	}
	for _, d := range n.identities {
		if d != nil {
			return errMihomoLiveMaterial
		}
	}
	var result error
	for _, f := range []*os.File{n.profile, n.binary} {
		if f != nil {
			result = errors.Join(result, f.Close())
		}
	}
	if n.root != nil {
		result = errors.Join(result, n.root.Close())
	}
	n.closeErr = result
	n.closed = result == nil
	return result
}
