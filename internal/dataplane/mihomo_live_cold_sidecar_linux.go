//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"golang.org/x/sys/unix"
)

// This is a cold stop, never construction of an OriginalProcess or a new warm
// lifecycle owner. The caller supplies its startup-compiled spec and a fresh
// exclusive cleanup operation. Only an actually reobserved, pinned pidfd can
// receive a signal. Files, policy and journals stay intact until the separate
// complete absence/retirement protocol proves the entire footprint settled.
func stopMihomoLiveColdSidecar(ctx context.Context, provider *netidentity.Provider, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, spec ProcessSpec, d ExecutionMihomoLiveDefinition) (result error) {
	return stopMihomoLiveColdSidecarOriginal(ctx, provider, control, cleanup, spec, d, nil)
}

func stopMihomoSameBootSidecar(ctx context.Context, o *mihomoSameBootCleanup) error {
	if o == nil || o.self != o || o.static == nil || o.static.self != o.static || o.static.closed || o.static.dirs["runtime"] == nil {
		return ErrMihomoLiveRetirement
	}
	if err := o.static.current(); err != nil {
		return err
	}
	return stopMihomoLiveColdSidecarOriginal(ctx, o.read.tools.Provider, o.control, o.cleanup, o.read.proxy.sidecarProcess(), o.inputs.definition, o.static)
}

func stopMihomoLiveColdSidecarOriginal(ctx context.Context, provider *netidentity.Provider, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, spec ProcessSpec, d ExecutionMihomoLiveDefinition, original *mihomoSameBootStatic) (result error) {
	var originalRoot *os.Root
	if original != nil {
		if original.self != original || original.closed || original.dirs["runtime"] == nil {
			return errMihomoLiveMaterial
		}
		originalRoot = original.dirs["runtime"]
	}
	if xraySelectedTCPFinite(ctx) != nil || provider == nil || control == nil || cleanup == nil || d.validate() != nil || d.Observation == nil || !spec.RouteProof || spec.ID != "mihomo-tun" || validateProcessSpec(spec) != nil || filepath.Clean(spec.Dir) != spec.Dir || !filepath.IsAbs(spec.Dir) || spec.PIDPath != filepath.Join(spec.Dir, "sidecar.pid") || spec.MatchArg != filepath.Join(spec.Dir, "sidecar.json") || spec.LogPath != filepath.Join(spec.Dir, "sidecar.log") {
		return errMihomoLiveMaterial
	}
	args := []string{"run", "-c", "/proc/self/fd/4"}
	if d.Sidecar.Kind == "hev" {
		args = []string{"/proc/self/fd/4"}
	}
	if !slices.Equal(spec.Args, args) || !filepath.IsAbs(spec.Binary) || filepath.Clean(spec.Binary) != spec.Binary {
		return errMihomoLiveMaterial
	}
	root, err := openBootRetirementRoot(spec.Dir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	anchor, err := root.Stat(".")
	if err != nil {
		return err
	}
	originalRootCurrent := func() error {
		if originalRoot == nil {
			return nil
		}
		originalInfo, e1 := originalRoot.Stat(".")
		held, e2 := root.Stat(".")
		named, e3 := os.Lstat(spec.Dir)
		if e1 != nil || e2 != nil || e3 != nil || !networkPolicyPrivateDirectory(originalInfo) || !networkPolicyPrivateDirectory(held) || !networkPolicyPrivateDirectory(named) || !os.SameFile(originalInfo, anchor) || !os.SameFile(originalInfo, held) || !os.SameFile(originalInfo, named) {
			return errors.Join(errMihomoLiveMaterial, e1, e2, e3)
		}
		return original.signalRecordsCurrent()
	}
	if err := originalRootCurrent(); err != nil {
		return err
	}
	readInput := func(name string) ([]byte, error) {
		if original == nil {
			return bootRetirementRead(root, name)
		}
		r := original.sidecarRecord(name)
		if r == nil {
			return nil, errMihomoLiveMaterial
		}
		if err := errors.Join(r.current(), sameBootPolicyRecordIdentity(r)); err != nil {
			return nil, err
		}
		return bytes.Clone(r.data), nil
	}
	pidRaw, err := readInput("sidecar.pid")
	if err != nil {
		return err
	}
	raw, err := readInput("sidecar.pid" + routeidentity.ReceiptSuffix)
	if err != nil || len(raw) > 16<<10 || routeidentity.Hash(raw) != d.Observation.SidecarReceiptSHA256 {
		return errMihomoLiveMaterial
	}
	var receipt routeidentity.Receipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if nfqws2ManagedUniqueJSON(raw) != nil || decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF || receipt.Version != 1 || receipt.PID <= 1 || string(pidRaw) != strconv.Itoa(receipt.PID)+"\n" || receipt.ConfigHash != d.Sidecar.ConfigSHA256 || receipt.BootID != d.NetworkIdentity.BootID {
		return errMihomoLiveMaterial
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errMihomoLiveMaterial
	}
	pinInput := func(name string, expected []byte) (func() error, func(), error) {
		if original == nil {
			return pinBootRetirementFile(root, name, expected)
		}
		r := original.sidecarRecord(name)
		if r == nil || !bytes.Equal(r.data, expected) {
			return nil, nil, errMihomoLiveMaterial
		}
		return func() error { return errors.Join(r.current(), sameBootPolicyRecordIdentity(r)) }, func() {}, nil
	}
	checkPID, closePID, err := pinInput("sidecar.pid", pidRaw)
	if err != nil {
		return err
	}
	defer closePID()
	checkReceipt, closeReceipt, err := pinInput("sidecar.pid"+routeidentity.ReceiptSuffix, raw)
	if err != nil {
		return err
	}
	defer closeReceipt()
	check := func() error {
		if err := originalRootCurrent(); err != nil {
			return err
		}
		if err := control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
			return err
		}
		identity, err := provider.Observe(ctx)
		if err != nil || identity != d.NetworkIdentity {
			return errors.Join(errMihomoLiveMaterial, err)
		}
		named, err := os.Lstat(spec.Dir)
		held, heldErr := root.Stat(".")
		if err != nil || heldErr != nil || !os.SameFile(anchor, held) || !os.SameFile(anchor, named) || !networkPolicyPrivateDirectory(named) {
			return errMihomoLiveMaterial
		}
		return errors.Join(checkPID(), checkReceipt(), ctx.Err())
	}
	if err := check(); err != nil {
		return err
	}
	fd, err := unix.PidfdOpen(receipt.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return check()
	}
	if err != nil {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	defer func() { result = errors.Join(result, unix.Close(fd)) }()
	processRoot := fmt.Sprintf("/proc/%d", receipt.PID)
	current := func() error {
		if err := check(); err != nil {
			return err
		}
		actual, err := routeidentity.RecordStart(receipt.PID, spec.Binary, args, spec.MatchArg, d.Sidecar.ConfigSHA256)
		if err != nil || !bytes.Equal(actual, raw) {
			return errors.Join(errMihomoLiveMaterial, err)
		}
		ns, err := os.Stat(filepath.Join(processRoot, "ns/net"))
		selfNS, selfErr := os.Stat("/proc/self/ns/net")
		if err != nil || selfErr != nil || !os.SameFile(ns, selfNS) {
			return errMihomoLiveMaterial
		}
		hash, info, err := mihomoColdFileHash(ctx, filepath.Join(processRoot, "exe"))
		if err != nil || hash != d.Sidecar.BinarySHA256 || info.Size() != d.Sidecar.BinarySize {
			return errors.Join(errMihomoLiveMaterial, err)
		}
		configFD, err := os.Open(filepath.Join(processRoot, "fd/4"))
		if err != nil {
			return err
		}
		seals, sealErr := unix.FcntlInt(configFD.Fd(), unix.F_GET_SEALS, 0)
		configHash, configInfo, hashErr := mihomoColdFileHash(ctx, filepath.Join(processRoot, "fd/4"))
		heldConfig, heldErr := configFD.Stat()
		closeErr := configFD.Close()
		const requiredSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
		if sealErr != nil || hashErr != nil || heldErr != nil || closeErr != nil || !os.SameFile(heldConfig, configInfo) || seals&requiredSeals != requiredSeals || configHash != d.Sidecar.ConfigSHA256 || configInfo.Size() > 1<<20 {
			return errors.Join(errMihomoLiveMaterial, sealErr, hashErr, heldErr, closeErr)
		}
		closing, err := routeidentity.RecordStart(receipt.PID, spec.Binary, args, spec.MatchArg, d.Sidecar.ConfigSHA256)
		if err != nil || !bytes.Equal(closing, raw) {
			return errors.Join(errMihomoLiveMaterial, err)
		}
		return check()
	}
	if err := current(); err != nil {
		return err
	}
	// Pinning precedes the second complete birth/argv/config/image comparison.
	// A numeric PID can never be used as a signalling fallback.
	if err := current(); err != nil {
		return err
	}
	if err := control.WithCleanupStart(ctx, cleanup, func() error {
		if err := originalRootCurrent(); err != nil {
			return err
		}
		return unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0)
	}); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	deadline := time.Now().Add(4 * time.Second)
	killed := false
	for {
		if err := check(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 20)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			if poll[0].Revents&unix.POLLIN == 0 {
				return errMihomoLiveMaterial
			}
			return check() // Actual exit only; global absence is still mandatory.
		}
		if !killed && time.Now().After(deadline) {
			if err := current(); err != nil {
				return err
			}
			if err := control.WithCleanupStart(ctx, cleanup, func() error {
				if err := originalRootCurrent(); err != nil {
					return err
				}
				return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}); err != nil && !errors.Is(err, unix.ESRCH) {
				return err
			}
			killed = true
		}
	}
}
