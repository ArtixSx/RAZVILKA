package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/engine"
)

var errComponentRuntimeUnconfirmed = errors.New("component runtime acceptance is unconfirmed")

// proc inspection is independent of version output, init status and candidate
// probes. No caller-supplied PID/path is used by production recovery.
type componentProcess struct {
	pid, start, executable string
	args                   []string
}

func componentProcesses(ctx context.Context, root string) ([]componentProcess, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []componentProcess
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		end := strings.LastIndex(string(stat), ")")
		if end < 0 {
			return nil, errComponentRuntimeUnconfirmed
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 20 {
			return nil, errComponentRuntimeUnconfirmed
		}
		if fields[0] == "Z" || fields[0] == "X" {
			continue
		}
		cmd, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			return nil, err
		}
		if len(cmd) == 0 {
			// Empty user command lines cannot establish quiescence. Only kernel
			// threads (PF_KTHREAD, field 9) are exempt from executable inspection.
			flags, err := strconv.ParseUint(fields[6], 10, 64)
			if err != nil || flags&0x00200000 == 0 {
				return nil, errComponentRuntimeUnconfirmed
			}
			continue
		}
		executable, err := os.Readlink(filepath.Join(dir, "exe"))
		if err != nil {
			return nil, err
		}
		out = append(out, componentProcess{entry.Name(), fields[19], executable, strings.Split(strings.TrimSuffix(string(cmd), "\x00"), "\x00")})
	}
	return out, nil
}

func packageProcess(p componentProcess) bool {
	for _, arg := range append([]string{p.executable}, p.args...) {
		name := strings.TrimSuffix(filepath.Base(arg), " (deleted)")
		switch name {
		case "opkg", "opkg-cl", "sh", "ash", "bash", "dash", "zsh", "ksh", "lua", "luajit", "perl", "python", "python3", "node":
			return true // Includes orphan interpreters and busybox shell applets.
		}
		if strings.Contains(arg, "/opkg/info/") || strings.HasSuffix(name, ".postinst") || strings.HasSuffix(name, ".preinst") || strings.HasSuffix(name, ".prerm") || strings.HasSuffix(name, ".postrm") {
			return true
		}
	}
	return false
}

func nativeComponentQuiescence(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return errors.New("trusted package quiescence requires Linux procfs")
	}
	for range 2 {
		processes, err := componentProcesses(ctx, "/proc")
		if err != nil {
			return err
		}
		for _, process := range processes {
			if packageProcess(process) {
				return errors.New("package command or script interpreter is still active; recovery remains fenced")
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// A historical unknown transaction has no durable process tree/cgroup
	// receipt. An empty name-based scan cannot prove that a package script's
	// detached native child finished. Do not turn observation into authority.
	return errors.New("trusted package supervision receipt unavailable; process scan alone cannot settle an unknown command")
}

func (a *App) checkComponentInactive(ctx context.Context, id string) error {
	if a.componentRecoveryChecks.inactive != nil {
		return a.componentRecoveryChecks.inactive(ctx, id)
	}
	if runtime.GOOS != "linux" || a.Store == nil {
		return errComponentRuntimeUnconfirmed
	}
	if a.managedUpdateInUse(id) {
		return errComponentRuntimeUnconfirmed
	}
	if a.Dataplane != nil {
		if _, _, err := a.Dataplane.Committed(); err != nil {
			return err
		}
	}
	processes, err := componentProcesses(ctx, "/proc")
	if err != nil {
		return err
	}
	for _, process := range processes {
		if componentProcessUses(process, id) {
			return errComponentRuntimeUnconfirmed
		}
	}
	return ctx.Err()
}

func componentProcessUses(p componentProcess, id string) bool {
	name := strings.TrimSuffix(filepath.Base(p.executable), " (deleted)")
	if id == "warp-wg" || id == "wireguard" {
		return name == "wg" || name == "wg-quick" || name == "wireguard-go"
	}
	return name == id || id == "nfqws2" && name == "nfqws"
}

func (a *App) checkComponentLive(ctx context.Context, id string) error {
	if runtime.GOOS != "linux" || a.Dataplane == nil || a.Store == nil {
		return errComponentRuntimeUnconfirmed
	}
	plan, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || plan.Revision != a.Store.Get().AppliedRevision {
		return errComponentRuntimeUnconfirmed
	}
	if handled, err := a.observeManagedComponentRuntime(ctx, plan, id); handled {
		if err != nil {
			return err
		}
		// The original process/rules are current. No selected-client service
		// proof producer exists here, so presence cannot settle accept-live.
		return errComponentServiceProofUnconfirmed
	}
	// This calls owned live probes only. It never stages or runs a candidate.
	if err := a.Dataplane.CheckComponentLive(ctx, plan, id); err != nil {
		return err
	}
	var binary string
	for _, status := range (engine.Detector{}).Inventory() {
		if status.ID == id {
			binary = status.BinaryPath
		}
	}
	if binary == "" {
		return errComponentRuntimeUnconfirmed
	}
	installed, err := os.Stat(binary)
	if err != nil || !installed.Mode().IsRegular() {
		return errComponentRuntimeUnconfirmed
	}
	processes, err := componentProcesses(ctx, "/proc")
	if err != nil {
		return err
	}
	count := 0
	for _, process := range processes {
		if !componentProcessUses(process, id) {
			continue
		}
		active, err := os.Stat(filepath.Join("/proc", process.pid, "exe"))
		if err != nil || !os.SameFile(installed, active) {
			return errors.New("working process still uses another component executable")
		}
		count++
	}
	// wg is a CLI, not a resident daemon: live kernel interface/peer/path proof
	// above is required instead. Proxy/NFQWS acceptance needs resident processes.
	if count == 0 && id != "wireguard" && id != "warp-wg" {
		return errComponentRuntimeUnconfirmed
	}
	// Catch loss of ownership, executable changes and failed health during the
	// independent process inspection before the Manager settles the journal.
	return a.Dataplane.CheckComponentLive(ctx, plan, id)
}
