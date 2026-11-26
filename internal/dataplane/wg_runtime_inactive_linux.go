//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// /proc exe identifies actual executables, even when argv[0] is changed.
// cmdline also catches an in-flight wg-quick shell wrapper. A permission or
// partial-inventory error refuses proof instead of treating it as no process.
func verifyWGProcessesInactive(ctx context.Context, interfaces []string) error {
	return verifyWGProcessesInactiveAt(ctx, "/proc", interfaces)
}

func verifyWGProcessesInactiveAt(ctx context.Context, root string, interfaces []string) error {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) == 0 || len(entries) > 65536 {
		return errors.Join(err, errWGInactiveUnknown)
	}
	pids := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		pids++
		dir := filepath.Join(root, entry.Name())
		exe, exeErr := os.Readlink(filepath.Join(dir, "exe"))
		f, err := os.Open(filepath.Join(dir, "cmdline"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return errWGInactiveUnknown
		}
		cmd, readErr := io.ReadAll(io.LimitReader(f, 65537))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(cmd) > 65536 {
			return errWGInactiveUnknown
		}
		if exeErr != nil {
			if !errors.Is(exeErr, os.ErrNotExist) || len(cmd) != 0 {
				return errWGInactiveUnknown
			}
			continue // kernel thread, zombie, or a process that has exited
		}
		name := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		if name == "wireguard-go" || name == "amneziawg-go" {
			return errWGInactiveUnknown
		}
		flat := strings.ReplaceAll(string(cmd), "\x00", " ")
		if strings.Contains(flat, "wg-quick") || strings.Contains(flat, "awg-quick") || strings.Contains(flat, "wireguard-go") || strings.Contains(flat, "amneziawg-go") {
			for _, iface := range interfaces {
				if strings.Contains(flat, iface) {
					return errWGInactiveUnknown
				}
			}
		}
		for _, arg := range strings.Split(string(cmd), "\x00") {
			base := filepath.Base(arg)
			if base != "wg-quick" && base != "awg-quick" && base != "wireguard-go" && base != "amneziawg-go" {
				continue
			}
			for _, iface := range interfaces {
				for _, value := range strings.Split(string(cmd), "\x00") {
					if value == iface || filepath.Base(value) == iface+".conf" {
						return errWGInactiveUnknown
					}
				}
			}
		}
	}
	if pids == 0 {
		return errWGInactiveUnknown
	}
	return ctx.Err()
}
