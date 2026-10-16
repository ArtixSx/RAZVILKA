package dataplane

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// Exact bounded identity of the runtime at the original successful Commit.
// Engine launch evidence remains mandatory. Legacy Sing-box sidecars do not
// issue a launch receipt, so only this same-Commit snapshot can bind their
// current PID/birth/executable/argv/config; no later journal opener can mint it.
func retainedSingProcessIdentity(spec ProcessSpec) (retainedSingProcess, error) {
	var unknown retainedSingProcess
	if runtime.GOOS != "linux" || validateProcessSpec(spec) != nil {
		return unknown, ErrRetainedSingReview
	}
	runtimeRoot, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return unknown, ErrRetainedSingReview
	}
	defer runtimeRoot.Close()
	pid, err := retainedSingPID(spec)
	if err != nil {
		return unknown, ErrRetainedSingReview
	}
	root := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := readProxyInactiveProc(filepath.Join(root, "stat"), 16<<10)
	if err != nil {
		return unknown, ErrRetainedSingReview
	}
	state, _, ticks, err := proxyInactiveProcStat(stat, pid)
	if err != nil || state == 'Z' || state == 'X' || state == 'x' {
		return unknown, ErrRetainedSingReview
	}
	boot, err := readProxyInactiveProc("/proc/sys/kernel/random/boot_id", 128)
	if err != nil || !kernelBootIDPattern.MatchString(strings.TrimSpace(string(boot))) {
		return unknown, ErrRetainedSingReview
	}
	command, err := readProxyInactiveProc(filepath.Join(root, "cmdline"), 64<<10)
	if err != nil || string(command) != strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00")+"\x00" {
		return unknown, ErrRetainedSingReview
	}
	executable, err := os.Readlink(filepath.Join(root, "exe"))
	if err != nil || executable == "" {
		return unknown, ErrRetainedSingReview
	}
	installed, err := os.Stat(spec.Binary)
	active, activeErr := os.Stat(filepath.Join(root, "exe"))
	if err != nil || activeErr != nil || !os.SameFile(installed, active) {
		return unknown, ErrRetainedSingReview
	}
	configName, err := filepath.Rel(spec.Dir, spec.MatchArg)
	if err != nil {
		return unknown, ErrRetainedSingReview
	}
	_, config, err := retainedSingReadOwned(runtimeRoot, configName, 8<<20)
	if err != nil {
		return unknown, ErrRetainedSingReview
	}
	identity := routeidentity.Receipt{Version: 1, PID: pid, BootID: strings.TrimSpace(string(boot)), StartTicks: ticks, Executable: executable,
		ArgsHash: routeidentity.Hash(command), ConfigHash: routeidentity.Hash(config)}
	if spec.RouteProof {
		receiptName, err := filepath.Rel(spec.Dir, spec.PIDPath+routeidentity.ReceiptSuffix)
		if err != nil {
			return unknown, ErrRetainedSingReview
		}
		_, data, err := retainedSingReadOwned(runtimeRoot, receiptName, 4096)
		var receipt routeidentity.Receipt
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err != nil || decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF || receipt != identity {
			return unknown, ErrRetainedSingReview
		}
	}
	return retainedSingProcess{identity, active}, nil
}

func retainedSingPID(spec ProcessSpec) (int, error) {
	root, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return 0, ErrRetainedSingReview
	}
	defer root.Close()
	name, err := filepath.Rel(spec.Dir, spec.PIDPath)
	if err != nil {
		return 0, ErrRetainedSingReview
	}
	_, data, err := retainedSingReadOwned(root, name, 64)
	if err != nil {
		return 0, ErrRetainedSingReview
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, ErrRetainedSingReview
	}
	return pid, nil
}
