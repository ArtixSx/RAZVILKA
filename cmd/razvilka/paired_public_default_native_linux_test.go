//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is the documented refusal of a stopped default-layout installation,
// not a migration or live-upgrade claim. Only the real old init stops its
// original panel; all comparisons begin after tini has reaped that process.
func TestNativeDefaultOld193InstallRefusal(t *testing.T) {
	nativePairedPrivateScope(t)
	if os.Getenv("RAZVILKA_PAIRED_NATIVE_LAYOUT") != "default-refusal" || os.Getenv("RAZVILKA_PAIRED_NATIVE_HISTORY") != "" {
		t.Fatal("exact default refusal scenario required")
	}
	const init = "/opt/etc/init.d/S99razvilka"
	const pidPath = "/opt/var/run/razvilka.pid"
	if got := nativePairedRestoreFileHash(t, init); got != os.Getenv("RAZVILKA_PAIRED_NATIVE_INIT_SHA") {
		t.Fatal("default source init differs from genuine old tag")
	}
	if got := nativePairedRestoreFileHash(t, "/opt/bin/razvilka"); got != os.Getenv("RAZVILKA_PAIRED_NATIVE_SOURCE_SHA") {
		t.Fatal("default source executable differs from genuine old tag")
	}
	assertNewRootAbsent := func() {
		t.Helper()
		if _, err := os.Lstat("/opt/razvilka"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("default source or refused installer created modern root", err)
		}
	}
	assertNewRootAbsent()
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil || len(pidBytes) > 32 {
		t.Fatal("actual old default PID unavailable", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid <= 1 {
		t.Fatal("invalid actual old default PID")
	}
	process := "/proc/" + strconv.Itoa(pid)
	if executable, err := os.Readlink(process + "/exe"); err != nil || executable != "/opt/bin/razvilka" {
		t.Fatal("default PID is not actual source executable", err)
	}
	args, err := os.ReadFile(process + "/cmdline")
	if err != nil || len(args) > 64<<10 || len(args) == 0 || args[len(args)-1] != 0 {
		t.Fatal("default source arguments unavailable")
	}
	words := bytes.Split(args[:len(args)-1], []byte{0})
	for flag, value := range map[string]string{
		"-stage": "/opt/var/lib/razvilka/staging", "-backups": "/opt/var/lib/razvilka/backups",
		"-cache": "/opt/var/cache/razvilka", "-dataplane-state": "/opt/var/lib/razvilka/dataplane",
		"-strategy-lab-state": "/opt/var/lib/razvilka/strategy-lab.json", "-listen": "127.0.0.1:8787",
	} {
		found := 0
		for i := 1; i+1 < len(words); i++ {
			if string(words[i]) == flag {
				found++
				if string(words[i+1]) != value {
					t.Fatal("old default argument was overridden", flag)
				}
			}
		}
		if found != 1 {
			t.Fatal("old default argument absent or duplicated", flag)
		}
	}
	clear(args)
	run := func(limit time.Duration, args ...string) (error, *nativePairedRestoreOutput, *nativePairedRestoreOutput) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), limit)
		defer cancel()
		command := exec.CommandContext(ctx, "/opt/bin/sh", args...)
		command.Env = []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/opt/root", "LANG=C", "LC_ALL=C"}
		stdout, stderr := &nativePairedRestoreOutput{}, &nativePairedRestoreOutput{}
		command.Stdout, command.Stderr, command.WaitDelay = stdout, stderr, 100*time.Millisecond
		err := command.Run() // The exact shell invocation is joined before readback.
		if ctx.Err() != nil || command.ProcessState == nil {
			t.Fatal("original command did not complete within its bound")
		}
		return err, stdout, stderr
	}
	if err, _, stderr := run(90*time.Second, init, "stop"); err != nil || stderr.Len() != 0 {
		t.Fatal("genuine old init did not stop its original panel", err)
	}
	for _, path := range []string{pidPath, process} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("original old process was not reaped or PID file retained", err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	paths := []string{"/opt/bin/razvilka", init, "/opt/etc/razvilka", "/opt/var/lib/razvilka", "/opt/var/cache/razvilka", "/opt/var/log/razvilka", "/opt/var/run", "/opt/razvilka"}
	// The existing bounded walker compares every regular byte, name, type and
	// permission and refuses unexpected symlinks rather than following them.
	before := nativePairedRestoreEvidence(t, ctx, paths)
	program := os.Getenv("RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_CANDIDATE")
	if !filepath.IsAbs(program) || filepath.Clean(program) != program {
		t.Fatal("actual built candidate coordinate missing")
	}
	packageRoot := filepath.Join(filepath.Dir(program), "package", "RAZVILKA-0.20.0")
	if nativePairedRestoreFileHash(t, program) != nativePairedRestoreFileHash(t, filepath.Join(packageRoot, "dist", "razvilka-linux-amd64")) {
		t.Fatal("actual bundle does not contain the built candidate")
	}
	for _, mode := range []string{"--dry-run", "--apply"} {
		err, _, stderr := run(15*time.Second, filepath.Join(packageRoot, "scripts", "upgrade-entware.sh"), mode)
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(stderr.String(), "Pre-0.20 RAZVILKA installation found; 0.20 installs only on a clean base; installation unchanged\n  found: /opt/var/lib/razvilka\n") {
			t.Fatal("installer did not give the exact default-layout refusal", mode, err)
		}
		assertNewRootAbsent()
		if !reflect.DeepEqual(before, nativePairedRestoreEvidence(t, ctx, paths)) {
			t.Fatal("refused installer changed original stopped source", mode)
		}
		if _, err := os.Lstat(process); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused installer restarted original source")
		}
	}
	t.Log("actual_default_old193_install_refused dry_run=true apply=true old_stopped_joined=true source_unchanged=true new_root_absent=true migration_supported=false")
}
